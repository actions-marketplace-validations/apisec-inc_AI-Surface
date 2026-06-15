"""Agent framework detector.

Detects agent frameworks (LangChain, LangGraph, CrewAI, LlamaIndex, AutoGen,
Haystack, Semantic Kernel, Pydantic AI) AND, where possible, the tools each
agent exposes. The tool list is the load-bearing differentiator vs. generic
"AI inventory" tools: knowing an agent has authority over `refund_payment` is
materially different from knowing the repo "uses LangChain".

v0.5 scope: Python-only. AST-free regex/string matching. Good enough for the
common patterns; v0.6 should move to AST + cross-file dataflow.
"""
from __future__ import annotations

import logging
import re
from collections import OrderedDict
from dataclasses import dataclass
from typing import TypedDict

from ..types import CATEGORY_AGENT_FRAMEWORK, Evidence, Finding
from ..utils.walk import read_text_safe, relative_to_root, walk_files

log = logging.getLogger(__name__)


class _FrameworkInfo(TypedDict):
    """Per-framework metadata stored in FRAMEWORK_PATTERNS."""

    display: str
    imports: list[re.Pattern[str]]
    usage: list[re.Pattern[str]]

# Framework signatures. Each entry: (key, display, import_roots, usage_patterns).
# Order matters: more specific (langgraph) before more general (langchain).
_FRAMEWORK_SPECS: list[tuple[str, str, list[str], list[str]]] = [
    # (key, display, import_roots, usage_patterns)
    ("langgraph", "LangGraph", ["langgraph"], [r"\bStateGraph\s*\(", r"\bMessageGraph\s*\("]),
    ("langchain", "LangChain", ["langchain", "langchain_core", "langchain_community"], []),
    ("crewai", "CrewAI", ["crewai"], []),
    ("llama_index", "LlamaIndex", ["llama_index"], []),
    ("autogen", "AutoGen", ["autogen"], [r"\bAssistantAgent\s*\(", r"\bUserProxyAgent\s*\("]),
    ("haystack", "Haystack", ["haystack"], []),
    ("semantic_kernel", "Semantic Kernel", ["semantic_kernel"], []),
    ("pydantic_ai", "Pydantic AI", ["pydantic_ai"], []),
    ("strands", "AWS Strands", ["strands"], []),
]


def _build_import_regex(roots: list[str]) -> re.Pattern[str]:
    """Build a multiline regex matching `from <root>...import` or `import <root>`."""
    alt = "|".join(re.escape(r) for r in roots)
    return re.compile(
        rf"^\s*(?:from\s+(?:{alt})(?:\.[a-zA-Z0-9_.]+)?\s+import|import\s+(?:{alt}))",
        re.MULTILINE,
    )


FRAMEWORK_PATTERNS: OrderedDict[str, _FrameworkInfo] = OrderedDict(
    (
        key,
        {
            "display": display,
            "imports": [_build_import_regex(roots)],
            "usage": [re.compile(p) for p in usage],
        },
    )
    for key, display, roots, usage in _FRAMEWORK_SPECS
)


# Risk indicator vocabulary.
# Risk-vocabulary tokens, scored against whole *words* in a tool name (not
# substrings). Substring matching produced false positives like "asset_lookup"
# triggering on `set_` and "reset_password" triggering on `set_`.
FINANCIAL_WORDS = frozenset({
    "refund", "refunds", "payment", "payments", "charge", "charges",
    "transfer", "transfers", "withdraw", "withdrawal", "payout",
    "payouts", "invoice", "invoices",
})
DESTRUCTIVE_WORDS = frozenset({
    "delete", "drop", "truncate", "remove", "purge", "destroy",
})
MESSAGING_TOOL_NAMES = frozenset({"send_email", "send_message", "send_slack", "send_sms", "post_to"})
DATABASE_WRITE_TOOL_NAMES = frozenset({"write_db", "update_record", "insert", "modify"})
READ_WORDS = frozenset({
    "query", "get", "fetch", "search", "lookup", "read", "list", "find",
})
WRITE_WORDS = (
    DESTRUCTIVE_WORDS
    | FINANCIAL_WORDS
    | frozenset({"write", "update", "insert", "modify", "create", "send", "post", "set", "save"})
)

# Word boundaries for tool names: snake_case (`refund_payment`), kebab-case
# (`refund-payment`), camelCase (`refundPayment`), dotted (`tools.refund`).
_NAME_WORD_SPLIT_RE = re.compile(r"[_\-\s./:]+|(?<=[a-z])(?=[A-Z])")


def _name_words(name: str) -> frozenset[str]:
    """Tokenize a tool name into its atomic word set, lowercased."""
    return frozenset(w.lower() for w in _NAME_WORD_SPLIT_RE.split(name) if w)


def _classify_tools(tool_names: list[str]) -> list[str]:
    """Map a list of tool names to risk indicator phrases."""
    if not tool_names:
        return []
    name_words = [_name_words(n) for n in tool_names]
    lowered = [t.lower() for t in tool_names]
    indicators: list[str] = []

    if any(words & FINANCIAL_WORDS for words in name_words):
        indicators.append("financial action exposed")
    if any(words & DESTRUCTIVE_WORDS for words in name_words):
        indicators.append("destructive action exposed")
    if any(name in MESSAGING_TOOL_NAMES for name in lowered):
        indicators.append("messaging action exposed")
    if any(name in DATABASE_WRITE_TOOL_NAMES for name in lowered):
        indicators.append("database write exposed")

    has_read = any(words & READ_WORDS for words in name_words)
    has_write = any(words & WRITE_WORDS for words in name_words)
    if has_read and has_write:
        indicators.append("high blast-radius combination")

    return indicators


# Tool & agent extraction patterns.
# tools=[ ... ] kwarg / assignment.
TOOLS_BLOCK_RE = re.compile(r"tools\s*=\s*\[", re.IGNORECASE)
# Tool(name="x", ...) constructor.
TOOL_NAME_KW_RE = re.compile(r"\bTool\s*\(\s*name\s*=\s*['\"]([A-Za-z0-9_\-\.]+)['\"]")
# {"name": "x"} dict literal (Anthropic-shape).
DICT_NAME_RE = re.compile(r"['\"]name['\"]\s*:\s*['\"]([A-Za-z0-9_\-\.]+)['\"]")
# @tool decorator on def.
TOOL_DECORATOR_RE = re.compile(
    r"@tool(?:\s*\([^)]*\))?\s*\n\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)"
)
# Bare-identifier list inside tools=[...] (search_tool, refund_tool, ...).
IDENTIFIER_RE = re.compile(r"\b([a-z_][a-zA-Z0-9_]*)\b")
# tools=<identifier> kwarg: a variable, not an inline list. Resolved against
# in-file list variables so `TOOLS = [a, b]; Agent(tools=TOOLS)` is captured.
# Does NOT match `tools=[` (the next char after = must be an identifier char).
TOOLS_KWARG_VAR_RE = re.compile(r"\btools\s*=\s*([A-Za-z_]\w*)")
# Module/function-level `NAME = [ ... ]` list assignment, used to resolve the
# tools=<identifier> kwarg above. Tuple-unpacks (`a, b = f()`) do not match.
VAR_LIST_ASSIGN_RE = re.compile(r"^[ \t]*([A-Za-z_]\w*)\s*=\s*\[", re.MULTILINE)

# Agent definition patterns. Each captures the agent's display name (assignment
# LHS, role= kwarg, or name= kwarg). Order matters within (framework -> name).
_LC_CTORS = (
    "AgentExecutor|initialize_agent|create_react_agent"
    "|create_openai_tools_agent|create_tool_calling_agent"
)
# Match `agent=identifier` kwarg in a constructor's argument list. Used to
# detect that an AgentExecutor is wrapping an already-captured agent so we
# don't double-count the same logical agent twice.
_AGENT_KWARG_RE = re.compile(r"\bagent\s*=\s*([A-Za-z_]\w*)")

# Agent-constructor anchor patterns. For frameworks where the agent's "name"
# comes from a kwarg inside the constructor body (crewai, autogen), we match
# ONLY the opening `Ctor(` here; the body is then extracted with the
# bracket-balanced ``_match_bracket`` helper, after which a simple non-DOTALL
# regex pulls out ``role=`` / ``name=``. That two-step design is deliberate:
# the previous single-regex form with ``[^)]*?`` inside ``re.DOTALL`` exhibited
# catastrophic backtracking on adversarial input (~5s per 5K unmatched
# ``Agent(`` tokens, ~unbounded at 100K). See ``tests/test_redos.py``.
#
# The capture group convention is:
#   * langchain / pydantic_ai / strands: group(1) = LHS variable name
#   * crewai / autogen: group(1) = empty (filled in later from ctor body)

AGENT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("langchain", re.compile(rf"^([A-Za-z_]\w*)\s*=\s*(?:{_LC_CTORS})\s*\(", re.MULTILINE)),
    ("crewai", re.compile(r"\bAgent\s*(\()")),
    ("autogen", re.compile(r"\bAssistantAgent\s*(\()")),
    ("pydantic_ai", re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*Agent\s*\(", re.MULTILINE)),
    ("strands", re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*Agent\s*\(", re.MULTILINE)),
]

# Within a (bracket-bounded) ctor body, pull a ``role=`` or ``name=`` kwarg.
# Operates on the body string only, which is already capped at the
# matching ``)`` distance — no DOTALL-with-lazy-quantifier hazard.
_CTOR_ROLE_KW_RE = re.compile(r"""\brole\s*=\s*['"]([^'"\n]{1,200})['"]""")
_CTOR_NAME_KW_RE = re.compile(r"""\bname\s*=\s*['"]([^'"\n]{1,200})['"]""")


_BRACKET_PAIRS = {"[": "]", "(": ")", "{": "}"}

# Safety cap for ``_match_bracket`` so a hostile input full of unmatched
# openers (e.g. 100k ``Agent(`` tokens with no closing paren) can't make the
# detector quadratic. Real constructors fit in a few KB; the cap is generous.
_MATCH_BRACKET_MAX_SCAN = 16 * 1024

# Per-file cap on bracket-match attempts. A real source file has at most a
# few dozen agent constructors; a file with thousands of unmatched ``Agent(``
# openers is adversarial input designed to drive quadratic traversal cost.
# Stop after the cap and rely on the rest of the analysis for a partial
# inventory.
_BRACKET_ATTEMPTS_PER_FILE = 256


def _match_bracket(text: str, open_idx: int) -> int | None:
    """Return the index of the bracket matching the one at open_idx, or None.

    Skips over Python string literals (single/double quoted) so brackets inside
    strings don't break the count. Handles `[`, `(`, `{`.

    Bounded scan: refuses to look further than ``_MATCH_BRACKET_MAX_SCAN``
    bytes past ``open_idx``. Constructors larger than this are treated as
    unmatched, which prevents an attacker from driving traversal cost to
    O(N * file_size) by sprinkling many unclosed openers.
    """
    if open_idx >= len(text):
        return None
    open_ch = text[open_idx]
    close_ch = _BRACKET_PAIRS.get(open_ch)
    if close_ch is None:
        return None
    depth = 0
    in_str: str | None = None
    i = open_idx
    scan_limit = min(len(text), open_idx + _MATCH_BRACKET_MAX_SCAN)
    while i < scan_limit:
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in ("'", '"'):
            in_str = ch
        elif ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _balanced_content(text: str, open_idx: int) -> str | None:
    """Return the inner content of the bracket pair starting at open_idx."""
    end = _match_bracket(text, open_idx)
    if end is None:
        return None
    return text[open_idx + 1 : end]


_IDENT_SKIP = {"True", "False", "None", "Tool", "and", "or", "not"}


def _extract_tools_from_block(block: str) -> list[str]:
    """Pull tool names out of a tools=[ ... ] block content.

    Tries (in order): Tool(name="x") constructors, {"name": "x"} dicts, and
    finally bare identifier references (search_tool, refund_tool). The bare
    identifier path runs only when neither structured pattern matched — this
    avoids double-counting an identifier appearing as a Tool's func= arg.
    """
    names: list[str] = []
    seen: set[str] = set()

    def _add(n: str) -> None:
        if n not in seen:
            seen.add(n)
            names.append(n)

    for m in TOOL_NAME_KW_RE.finditer(block):
        _add(m.group(1))
    for m in DICT_NAME_RE.finditer(block):
        _add(m.group(1))

    if not names:
        for ident in IDENTIFIER_RE.findall(block):
            if ident in _IDENT_SKIP:
                continue
            _add(ident)

    return names


def _extract_decorator_tools(text: str) -> list[tuple[str, int]]:
    """Find @tool-decorated functions. Returns list of (tool_name, line_no)."""
    out: list[tuple[str, int]] = []
    for m in TOOL_DECORATOR_RE.finditer(text):
        line_no = text.count("\n", 0, m.start()) + 1
        out.append((m.group(1), line_no))
    return out


def _extract_tools_blocks(text: str) -> list[tuple[list[str], int, str]]:
    """Find every tools=[ ... ] block in text.

    Returns list of (tool_names, line_no, block_content) tuples.
    """
    out: list[tuple[list[str], int, str]] = []
    for m in TOOLS_BLOCK_RE.finditer(text):
        bracket_idx = text.find("[", m.end() - 1)
        if bracket_idx < 0:
            continue
        block = _balanced_content(text, bracket_idx)
        if block is None:
            continue
        names = _extract_tools_from_block(block)
        line_no = text.count("\n", 0, m.start()) + 1
        out.append((names, line_no, block))
    return out


def _collect_list_vars(text: str) -> dict[str, list[str]]:
    """Map in-file ``NAME = [ ... ]`` list variables to their extracted tool names.

    Lets a constructor that passes ``tools=NAME`` (a variable) resolve to the
    list literal ``NAME`` was assigned, the very common
    ``TOOLS = [a, b]; Agent(tools=TOOLS)`` shape. Same file only; a list built
    by a function call (``tools = make_tools()``) is not resolvable here and is
    left for a future AST/dataflow pass.
    """
    out: dict[str, list[str]] = {}
    attempts = 0
    for m in VAR_LIST_ASSIGN_RE.finditer(text):
        if attempts >= _BRACKET_ATTEMPTS_PER_FILE:
            break
        attempts += 1
        bracket_idx = text.find("[", m.end() - 1)
        if bracket_idx < 0:
            continue
        block = _balanced_content(text, bracket_idx)
        if block is None:
            continue
        name = m.group(1)
        if name not in out:  # keep the first assignment
            out[name] = _extract_tools_from_block(block)
    return out


def _enclosing_function(text: str, char_offset: int) -> str | None:
    """Find the name of the function containing `char_offset`. Best-effort."""
    # Scan backwards for the most recent `def name(` or `async def name(` at
    # column 0 (module-level) or any indentation.
    pre = text[:char_offset]
    matches = list(re.finditer(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", pre, re.MULTILINE))
    if not matches:
        return None
    return matches[-1].group(1)


def _detect_frameworks_in_file(text: str) -> set[str]:
    """Return the set of framework keys detected in `text`."""
    found: set[str] = set()
    for key, info in FRAMEWORK_PATTERNS.items():
        patterns = [*info["imports"], *info["usage"]]
        if any(pat.search(text) is not None for pat in patterns):
            found.add(key)
    return found


@dataclass
class _AgentDef:
    """An identified agent definition. Internal use only."""

    framework: str
    agent_name: str
    file: str
    line_no: int
    snippet: str
    tools: list[str]


# --------------------------------------------------------------------------- #
# JavaScript / TypeScript agent detection (v0.6)
#
# LLM-SDK and MCP-source detection already cover JS/TS elsewhere; agents were
# the Python-only gap. AST-free, same regex + bracket-matching approach as the
# Python path, so it reuses _match_bracket, _balanced_content, and _classify_tools.
# --------------------------------------------------------------------------- #

_JS_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]

# key -> (display, import-package roots, agent-usage anchors)
_JS_FRAMEWORK_SPECS: list[tuple[str, str, list[str], list[str]]] = [
    ("langgraph", "LangGraph", ["@langchain/langgraph"],
     [r"\bnew\s+StateGraph\b", r"\bcreateReactAgent\b"]),
    ("langchain", "LangChain", ["langchain", "@langchain"],
     [r"\bAgentExecutor\b", r"\bcreateToolCallingAgent\b", r"\binitializeAgentExecutor"]),
    ("vercel_ai", "Vercel AI SDK", ["ai", "@ai-sdk"],
     [r"\bgenerateText\s*\(", r"\bstreamText\s*\("]),
    ("mastra", "Mastra", ["@mastra/core", "@mastra"],
     [r"\bnew\s+Agent\s*\(", r"\bcreateAgent\s*\("]),
    ("openai_agents", "OpenAI Agents", ["@openai/agents"],
     [r"\bnew\s+Agent\s*\("]),
    ("llama_index", "LlamaIndex", ["llamaindex"],
     [r"\bOpenAIAgent\b", r"\bReActAgent\b"]),
]


def _build_js_import_regex(pkgs: list[str]) -> re.Pattern[str]:
    """Match ``from "pkg"`` / ``require("pkg")`` / ``import "pkg"`` incl. subpaths.

    The package must be quote-bounded, so "ai" does not match "openai" and
    "./ai" does not match the "ai" package.
    """
    alt = "|".join(re.escape(p) for p in pkgs)
    return re.compile(rf"""(?:from|require|import)\s*\(?\s*['"](?:{alt})(?:/[^'"]*)?['"]""")


_JS_FRAMEWORK_IMPORTS: dict[str, re.Pattern[str]] = {
    key: _build_js_import_regex(pkgs) for key, _d, pkgs, _u in _JS_FRAMEWORK_SPECS
}
_JS_DISPLAY = {key: disp for key, disp, _p, _u in _JS_FRAMEWORK_SPECS}

# Combined display map (Python + JS frameworks) for findings and fallbacks.
_FRAMEWORK_DISPLAY: dict[str, str] = {
    **{k: v["display"] for k, v in FRAMEWORK_PATTERNS.items()},
    **_JS_DISPLAY,
}


def _detect_js_frameworks(text: str) -> set[str]:
    """Framework keys whose package is imported in this JS/TS file."""
    return {key for key, rx in _JS_FRAMEWORK_IMPORTS.items() if rx.search(text) is not None}


def _first_js_import_line(text: str, fw: str) -> str:
    rx = _JS_FRAMEWORK_IMPORTS.get(fw)
    m = rx.search(text) if rx else None
    if not m:
        return ""
    start = text.rfind("\n", 0, m.start()) + 1
    end = text.find("\n", m.start())
    return text[start: end if end >= 0 else len(text)].strip()[:200]


# Named JS agent constructors -> framework key. "Agent" is ambiguous (Mastra /
# OpenAI Agents) and resolved against the file's imports at match time.
_JS_CTOR_FRAMEWORK = {
    "AgentExecutor": "langchain",
    "createToolCallingAgent": "langchain",
    "initializeAgentExecutorWithOptions": "langchain",
    "StateGraph": "langgraph",
    "createReactAgent": "langgraph",
    "createAgent": "mastra",
    "OpenAIAgent": "llama_index",
    "ReActAgent": "llama_index",
}
_JS_CTOR_ALT = ("AgentExecutor|createToolCallingAgent|initializeAgentExecutorWithOptions|"
                "StateGraph|createReactAgent|createAgent|OpenAIAgent|ReActAgent|Agent")
_JS_AGENT_RE = re.compile(
    rf"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:new\s+)?({_JS_CTOR_ALT})\s*\(",
)
_JS_VERCEL_RE = re.compile(r"\b(generateText|streamText)\s*\(")
_JS_VAR_ASSIGN_RE = re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([\[{])", re.MULTILINE)
_JS_NAME_RE = re.compile(r"""\bname\s*:\s*['"]([A-Za-z0-9_\-.]+)['"]""")
_JS_TOOLKEY_RE = re.compile(r"""([A-Za-z_$][\w$]*)\s*:\s*(?:tool\s*\(|new\s+[A-Za-z_$]|async\b)""")
_JS_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")
_JS_IDENT_SKIP = frozenset({
    "new", "tool", "async", "await", "const", "let", "var", "true", "false",
    "null", "undefined", "function", "return", "name", "description",
})


def _extract_js_tools_from_block(block: str) -> list[str]:
    """Pull tool names from a JS ``tools`` array or object block.

    Handles ``[toolA, toolB]`` (identifiers), ``[tool({name:"x"})]`` and
    ``{name:"x"}`` (name fields), and the Vercel-style object
    ``{ getWeather: tool({...}) }`` (the keys are the tool names).
    """
    names: list[str] = []
    seen: set[str] = set()

    def add(n: str) -> None:
        if n and n not in seen and n not in _JS_IDENT_SKIP:
            seen.add(n)
            names.append(n)

    for m in _JS_NAME_RE.finditer(block):
        add(m.group(1))
    for m in _JS_TOOLKEY_RE.finditer(block):
        add(m.group(1))
    if not names:
        for m in _JS_IDENT_RE.finditer(block):
            add(m.group(0))
    return names


def _collect_js_list_vars(text: str) -> dict[str, list[str]]:
    """Map in-file ``const NAME = [...]`` / ``{...}`` to extracted tool names,
    so a ``tools: NAME`` reference can be resolved."""
    out: dict[str, list[str]] = {}
    attempts = 0
    for m in _JS_VAR_ASSIGN_RE.finditer(text):
        if attempts >= _BRACKET_ATTEMPTS_PER_FILE:
            break
        attempts += 1
        block = _balanced_content(text, m.start(2))
        if block is None:
            continue
        name = m.group(1)
        if name not in out:
            out[name] = _extract_js_tools_from_block(block)
    return out


def _extract_js_tools_from_ctor(ctor_text: str, list_vars: dict[str, list[str]]) -> list[str]:
    """Pull tools from a ctor/call argument list: inline ``tools: [...]`` /
    ``tools: {...}``, or a ``tools: NAME`` variable resolved in-file."""
    m = re.search(r"tools\s*:\s*([\[{])", ctor_text)
    if m:
        block = _balanced_content(ctor_text, m.start(1))
        if block is not None:
            return _extract_js_tools_from_block(block)
    m2 = re.search(r"tools\s*:\s*([A-Za-z_$][\w$]*)", ctor_text)
    if m2:
        return list(list_vars.get(m2.group(1), []))
    # object shorthand: `{ agent, tools }` resolves the in-file `tools` variable
    if re.search(r"[,{]\s*tools\s*[,}]", ctor_text) and "tools" in list_vars:
        return list(list_vars["tools"])
    return []


def _js_enclosing_function(text: str, offset: int) -> str | None:
    """Best-effort name of the function/const containing ``offset``."""
    pre = text[:offset]
    matches = list(re.finditer(
        r"function\s+([A-Za-z_$][\w$]*)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(",
        pre))
    if not matches:
        return None
    last = matches[-1]
    return last.group(1) or last.group(2)


def _extract_js_agent_defs(
    text: str, rel_file: str, frameworks: set[str], list_vars: dict[str, list[str]],
) -> list[_AgentDef]:
    """Identify JS/TS agent definitions and the tools each exposes."""
    defs: list[_AgentDef] = []
    if not frameworks:
        return defs
    attempts = 0

    # 1. Named agent constructors (const x = new Agent({...}) etc.)
    for m in _JS_AGENT_RE.finditer(text):
        if attempts >= _BRACKET_ATTEMPTS_PER_FILE:
            break
        attempts += 1
        name, ctor = m.group(1), m.group(2)
        if ctor == "Agent":
            fw = ("mastra" if "mastra" in frameworks
                  else "openai_agents" if "openai_agents" in frameworks else None)
        else:
            fw = _JS_CTOR_FRAMEWORK.get(ctor)
            if fw == "langgraph" and "langgraph" not in frameworks and "langchain" in frameworks:
                fw = "langchain"  # createReactAgent is also a LangChain prebuilt
        if fw is None or fw not in frameworks:
            continue
        paren = text.find("(", m.end() - 1)
        if paren < 0:
            continue
        end = _match_bracket(text, paren)
        if end is None:
            continue
        line_no = text.count("\n", 0, m.start()) + 1
        defs.append(_AgentDef(
            framework=fw, agent_name=name, file=rel_file, line_no=line_no,
            snippet=_line_snippet(text, line_no),
            tools=_extract_js_tools_from_ctor(text[paren: end + 1], list_vars),
        ))

    # 2. Vercel AI SDK call sites that actually wire tools.
    if "vercel_ai" in frameworks:
        for m in _JS_VERCEL_RE.finditer(text):
            if attempts >= _BRACKET_ATTEMPTS_PER_FILE:
                break
            attempts += 1
            paren = text.find("(", m.end() - 1)
            if paren < 0:
                continue
            end = _match_bracket(text, paren)
            if end is None:
                continue
            tools = _extract_js_tools_from_ctor(text[paren: end + 1], list_vars)
            if not tools:
                continue  # plain generateText with no tools is not an agent
            line_no = text.count("\n", 0, m.start()) + 1
            defs.append(_AgentDef(
                framework="vercel_ai",
                agent_name=_js_enclosing_function(text, m.start()) or m.group(1),
                file=rel_file, line_no=line_no,
                snippet=_line_snippet(text, line_no), tools=tools,
            ))
    return defs


class AgentFrameworkDetector:
    """Detect agent frameworks and the tools each agent exposes.

    Produces one Finding per identified agent definition. When a framework is
    imported but no specific agent definition is identifiable, produces one
    aggregated Finding for the framework with file count.
    """

    name = "agent_frameworks"
    category = CATEGORY_AGENT_FRAMEWORK

    def detect(self, root_path: str) -> list[Finding]:
        framework_files: dict[str, list[str]] = {}
        framework_first_snippet: dict[str, str] = {}
        agent_defs: list[_AgentDef] = []
        anthropic_tool_blocks: list[_AgentDef] = []

        # --- Python pass ---
        for path in walk_files(root_path, extensions=[".py"]):
            text = read_text_safe(path)
            if not text:
                continue
            rel = relative_to_root(path, root_path)

            frameworks = _detect_frameworks_in_file(text)
            for fw in frameworks:
                framework_files.setdefault(fw, []).append(rel)
                if fw not in framework_first_snippet:
                    framework_first_snippet[fw] = self._first_import_line(text, fw)

            blocks = _extract_tools_blocks(text)
            decorator_tools = _extract_decorator_tools(text)
            list_vars = _collect_list_vars(text)
            agent_defs.extend(
                self._extract_agent_defs(text, rel, frameworks, blocks, decorator_tools, list_vars)
            )

            # Anthropic-shape standalone: tools=[{"name": "..."}] dict literals
            # in files with no recognized agent framework.
            if not frameworks:
                for tools, line_no, block in blocks:
                    if DICT_NAME_RE.search(block) is None:
                        continue
                    fn = _enclosing_function(text, _line_to_offset(text, line_no)) or "module"
                    anthropic_tool_blocks.append(
                        _AgentDef(
                            framework="anthropic_tools",
                            agent_name=fn,
                            file=rel,
                            line_no=line_no,
                            snippet=_line_snippet(text, line_no),
                            tools=tools,
                        )
                    )

        # --- JavaScript / TypeScript pass ---
        for path in walk_files(root_path, extensions=_JS_EXTENSIONS):
            text = read_text_safe(path)
            if not text:
                continue
            frameworks = _detect_js_frameworks(text)
            if not frameworks:
                continue
            rel = relative_to_root(path, root_path)
            for fw in frameworks:
                framework_files.setdefault(fw, []).append(rel)
                if fw not in framework_first_snippet:
                    framework_first_snippet[fw] = _first_js_import_line(text, fw)
            agent_defs.extend(
                _extract_js_agent_defs(text, rel, frameworks, _collect_js_list_vars(text))
            )

        findings: list[Finding] = []
        files_used_by_agents: dict[str, set[str]] = {}

        # 1. Per-agent findings (frameworks + anthropic-shape standalone).
        for ad in agent_defs + anthropic_tool_blocks:
            findings.append(self._finding_from_agent_def(ad))
            files_used_by_agents.setdefault(ad.framework, set()).add(ad.file)

        # 2. Framework-only fallbacks: one Finding per framework imported in
        #    files where no specific agent definition could be identified.
        for fw, files in framework_files.items():
            leftover = sorted(set(files) - files_used_by_agents.get(fw, set()))
            if not leftover:
                continue
            display = _FRAMEWORK_DISPLAY.get(fw, fw.replace("_", " ").title())
            n = len(leftover)
            findings.append(
                Finding(
                    surface=f"{display} (used in {n} file{'s' if n != 1 else ''})",
                    category=CATEGORY_AGENT_FRAMEWORK,
                    evidence=Evidence(
                        files=leftover,
                        snippet=framework_first_snippet.get(fw, ""),
                        metadata={"framework": fw, "file_count": n},
                    ),
                )
            )
        return findings

    # ----- helpers --------------------------------------------------------

    @staticmethod
    def _first_import_line(text: str, framework_key: str) -> str:
        info = FRAMEWORK_PATTERNS[framework_key]
        patterns = [*info["imports"], *info["usage"]]
        for pat in patterns:
            m = pat.search(text)
            if m:
                start = text.rfind("\n", 0, m.start()) + 1
                end = text.find("\n", m.start())
                return text[start : end if end >= 0 else len(text)].strip()[:200]
        return ""

    def _extract_agent_defs(
        self,
        text: str,
        rel_file: str,
        frameworks: set[str],
        blocks: list[tuple[list[str], int, str]],
        decorator_tools: list[tuple[str, int]],
        list_vars: dict[str, list[str]],
    ) -> list[_AgentDef]:
        """Identify named agent definitions and attach the closest tools block.

        Tool resolution falls back in priority order: tools=[...] inside the
        constructor itself, a tools=<var> kwarg resolved to an in-file list
        variable, the nearest tools=[...] block in the file, then any
        @tool-decorated functions in the file. v0.6 should track these with
        real dataflow.
        """
        defs: list[_AgentDef] = []
        decorator_tool_names = [name for name, _ in decorator_tools]
        # Track agent names already captured so we can detect when an
        # AgentExecutor merely wraps one of them (langchain's common pattern:
        # `agent = create_react_agent(...); executor = AgentExecutor(agent=agent)`).
        # In that case the executor is the same logical agent and should not
        # produce a separate finding.
        captured_names: set[str] = set()
        wrapped_names: set[str] = set()

        bracket_attempts = 0
        # Track the end index of the last successfully matched constructor.
        # Subsequent regex hits whose ``(`` falls inside that already-scanned
        # window are skipped so a single deeply-nested call doesn't get
        # re-bracket-matched repeatedly.
        last_match_end = -1

        for fw, pat in AGENT_PATTERNS:
            if fw not in frameworks:
                continue
            for m in pat.finditer(text):
                paren_idx = text.find("(", m.end() - 1)
                if paren_idx < 0:
                    continue
                if paren_idx <= last_match_end:
                    continue
                if bracket_attempts >= _BRACKET_ATTEMPTS_PER_FILE:
                    log.debug(
                        "agent_frameworks: bracket-match budget exhausted for %s",
                        rel_file,
                    )
                    break
                bracket_attempts += 1
                end_idx = _match_bracket(text, paren_idx)
                if end_idx is None:
                    # No matching close paren within the scan cap — treat the
                    # whole capped region as consumed so we don't re-scan it
                    # for subsequent regex hits inside the same window.
                    last_match_end = paren_idx + _MATCH_BRACKET_MAX_SCAN
                    continue
                last_match_end = end_idx
                ctor_text = text[paren_idx : end_idx + 1]
                line_no = text.count("\n", 0, m.start()) + 1
                # For crewai/autogen the regex match anchors only the
                # constructor opening; the actual agent identifier lives
                # inside the (now bracket-bounded) ctor body. For other
                # frameworks group(1) holds the LHS variable name.
                if fw == "crewai":
                    rm = _CTOR_ROLE_KW_RE.search(ctor_text) or _CTOR_NAME_KW_RE.search(ctor_text)
                    if rm is None:
                        continue
                    this_name = rm.group(1)
                elif fw == "autogen":
                    rm = _CTOR_NAME_KW_RE.search(ctor_text)
                    if rm is None:
                        continue
                    this_name = rm.group(1)
                else:
                    this_name = m.group(1)

                tools = self._extract_tools_from_constructor(ctor_text)
                if not tools:
                    tools = self._tools_from_kwarg_var(ctor_text, list_vars)
                if not tools:
                    tools = self._nearest_tools_block(blocks, line_no)
                if not tools and decorator_tool_names:
                    tools = list(decorator_tool_names)

                # If this is an AgentExecutor that wraps an already-captured
                # agent (e.g., `AgentExecutor(agent=support_agent, ...)`),
                # mark it as a wrapper rather than emitting a duplicate finding.
                wrapped_ref = _AGENT_KWARG_RE.search(ctor_text)
                if (
                    fw == "langchain"
                    and "AgentExecutor" in text[m.start() : m.end()]
                    and wrapped_ref is not None
                    and wrapped_ref.group(1) in captured_names
                ):
                    wrapped_names.add(wrapped_ref.group(1))
                    continue

                captured_names.add(this_name)
                defs.append(
                    _AgentDef(
                        framework=fw,
                        agent_name=this_name,
                        file=rel_file,
                        line_no=line_no,
                        snippet=_line_snippet(text, line_no),
                        tools=tools,
                    )
                )
        return defs

    @staticmethod
    def _tools_from_kwarg_var(ctor_text: str, list_vars: dict[str, list[str]]) -> list[str]:
        """Resolve a ``tools=<identifier>`` kwarg to an in-file list variable."""
        m = TOOLS_KWARG_VAR_RE.search(ctor_text)
        if not m:
            return []
        return list(list_vars.get(m.group(1), []))

    @staticmethod
    def _extract_tools_from_constructor(ctor_text: str) -> list[str]:
        """Pull tools=[...] from inside a single constructor's argument list."""
        m = TOOLS_BLOCK_RE.search(ctor_text)
        if not m:
            return []
        bracket_idx = ctor_text.find("[", m.end() - 1)
        if bracket_idx < 0:
            return []
        block = _balanced_content(ctor_text, bracket_idx)
        if block is None:
            return []
        return _extract_tools_from_block(block)

    @staticmethod
    def _nearest_tools_block(
        blocks: list[tuple[list[str], int, str]], target_line: int
    ) -> list[str]:
        """Return the tool names from the tools=[...] block closest to target_line."""
        best: tuple[int, list[str]] | None = None
        for tools, line_no, _ in blocks:
            dist = abs(line_no - target_line)
            if dist > 30:
                continue
            if best is None or dist < best[0]:
                best = (dist, tools)
        return list(best[1]) if best else []

    @staticmethod
    def _finding_from_agent_def(ad: _AgentDef) -> Finding:
        if ad.framework == "anthropic_tools":
            label = "Claude Tools"
        else:
            display = _FRAMEWORK_DISPLAY.get(ad.framework, ad.framework.replace("_", " ").title())
            label = f"{display} Agent"
        surface = f"{label}: {ad.agent_name}"
        if ad.file:
            surface = f"{surface} (in {ad.file})"
        language = "python" if ad.file.endswith(".py") else "javascript/typescript"
        return Finding(
            surface=surface,
            category=CATEGORY_AGENT_FRAMEWORK,
            evidence=Evidence(
                files=[ad.file] if ad.file else [],
                snippet=ad.snippet,
                line_numbers=[ad.line_no] if ad.line_no else [],
                metadata={
                    "framework": ad.framework,
                    "agent_name": ad.agent_name,
                    "tool_count": len(ad.tools),
                    "language": language,
                },
            ),
            permissions=list(ad.tools),
            risk_indicators=_classify_tools(ad.tools),
        )


# Tiny utilities.
def _line_snippet(text: str, line_no: int, max_len: int = 200) -> str:
    """Return the source line at line_no (1-based), trimmed to max_len."""
    if line_no < 1:
        return ""
    lines = text.splitlines()
    if line_no > len(lines):
        return ""
    return lines[line_no - 1].strip()[:max_len]


def _line_to_offset(text: str, line_no: int) -> int:
    """Return the character offset of the start of line `line_no` (1-based)."""
    if line_no <= 1:
        return 0
    count = 0
    pos = 0
    for ch in text:
        if ch == "\n":
            count += 1
            if count == line_no - 1:
                return pos + 1
        pos += 1
    return pos
