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

import re
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from ..types import CATEGORY_AGENT_FRAMEWORK, Evidence, Finding
from ..utils.walk import read_text_safe, relative_to_root, walk_files


# Framework signatures. Each entry: (key, display, import_roots, usage_patterns).
# Order matters: more specific (langgraph) before more general (langchain).
_FRAMEWORK_SPECS: List[Tuple[str, str, List[str], List[str]]] = [
    # (key, display, import_roots, usage_patterns)
    ("langgraph", "LangGraph", ["langgraph"], [r"\bStateGraph\s*\(", r"\bMessageGraph\s*\("]),
    ("langchain", "LangChain", ["langchain", "langchain_core", "langchain_community"], []),
    ("crewai", "CrewAI", ["crewai"], []),
    ("llama_index", "LlamaIndex", ["llama_index"], []),
    ("autogen", "AutoGen", ["autogen"], [r"\bAssistantAgent\s*\(", r"\bUserProxyAgent\s*\("]),
    ("haystack", "Haystack", ["haystack"], []),
    ("semantic_kernel", "Semantic Kernel", ["semantic_kernel"], []),
    ("pydantic_ai", "Pydantic AI", ["pydantic_ai"], []),
]


def _build_import_regex(roots: List[str]) -> "re.Pattern[str]":
    """Build a multiline regex matching `from <root>...import` or `import <root>`."""
    alt = "|".join(re.escape(r) for r in roots)
    return re.compile(
        rf"^\s*(?:from\s+(?:{alt})(?:\.[a-zA-Z0-9_.]+)?\s+import|import\s+(?:{alt}))",
        re.MULTILINE,
    )


FRAMEWORK_PATTERNS: "OrderedDict[str, Dict[str, object]]" = OrderedDict(
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
FINANCIAL_TOKENS = ("refund", "payment", "charge", "transfer", "withdraw", "payout", "invoice")
DESTRUCTIVE_TOKENS = ("delete", "drop", "truncate", "remove", "purge", "destroy")
MESSAGING_TOOL_NAMES = {"send_email", "send_message", "send_slack", "send_sms", "post_to"}
DATABASE_WRITE_TOOL_NAMES = {"write_db", "update_record", "insert", "modify"}
DATABASE_WRITE_PREFIXES = ("set_", "save_")
READ_TOKENS = ("query", "get", "fetch", "search", "lookup", "read", "list_", "find")
WRITE_TOKENS = (
    DESTRUCTIVE_TOKENS
    + FINANCIAL_TOKENS
    + ("write", "update", "insert", "modify", "create", "send", "post", "set_", "save_")
)


def _classify_tools(tool_names: List[str]) -> List[str]:
    """Map a list of tool names to risk indicator phrases."""
    if not tool_names:
        return []
    lowered = [t.lower() for t in tool_names]
    indicators: List[str] = []

    if any(any(tok in name for tok in FINANCIAL_TOKENS) for name in lowered):
        indicators.append("financial action exposed")
    if any(any(tok in name for tok in DESTRUCTIVE_TOKENS) for name in lowered):
        indicators.append("destructive action exposed")
    if any(name in MESSAGING_TOOL_NAMES for name in lowered):
        indicators.append("messaging action exposed")
    if any(
        name in DATABASE_WRITE_TOOL_NAMES or name.startswith(DATABASE_WRITE_PREFIXES)
        for name in lowered
    ):
        indicators.append("database write exposed")

    has_read = any(any(name.startswith(t) or t in name for t in READ_TOKENS) for name in lowered)
    has_write = any(any(t in name for t in WRITE_TOKENS) for name in lowered)
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

# Agent definition patterns. Each captures the agent's display name (assignment
# LHS, role= kwarg, or name= kwarg). Order matters within (framework -> name).
_LC_CTORS = (
    "AgentExecutor|initialize_agent|create_react_agent"
    "|create_openai_tools_agent|create_tool_calling_agent"
)
AGENT_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("langchain", re.compile(rf"^([A-Za-z_]\w*)\s*=\s*(?:{_LC_CTORS})\s*\(", re.MULTILINE)),
    ("crewai", re.compile(r"\bAgent\s*\(\s*[^)]*?\brole\s*=\s*['\"]([^'\"]+)['\"]", re.DOTALL)),
    ("crewai", re.compile(r"\bAgent\s*\(\s*[^)]*?\bname\s*=\s*['\"]([^'\"]+)['\"]", re.DOTALL)),
    (
        "autogen",
        re.compile(r"\bAssistantAgent\s*\(\s*[^)]*?\bname\s*=\s*['\"]([^'\"]+)['\"]", re.DOTALL),
    ),
    ("pydantic_ai", re.compile(r"^([A-Za-z_]\w*)\s*=\s*Agent\s*\(", re.MULTILINE)),
]


_BRACKET_PAIRS = {"[": "]", "(": ")", "{": "}"}


def _match_bracket(text: str, open_idx: int) -> Optional[int]:
    """Return the index of the bracket matching the one at open_idx, or None.

    Skips over Python string literals (single/double quoted) so brackets inside
    strings don't break the count. Handles `[`, `(`, `{`.
    """
    if open_idx >= len(text):
        return None
    open_ch = text[open_idx]
    close_ch = _BRACKET_PAIRS.get(open_ch)
    if close_ch is None:
        return None
    depth = 0
    in_str: Optional[str] = None
    i = open_idx
    while i < len(text):
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


def _balanced_content(text: str, open_idx: int) -> Optional[str]:
    """Return the inner content of the bracket pair starting at open_idx."""
    end = _match_bracket(text, open_idx)
    if end is None:
        return None
    return text[open_idx + 1 : end]


_IDENT_SKIP = {"True", "False", "None", "Tool", "and", "or", "not"}


def _extract_tools_from_block(block: str) -> List[str]:
    """Pull tool names out of a tools=[ ... ] block content.

    Tries (in order): Tool(name="x") constructors, {"name": "x"} dicts, and
    finally bare identifier references (search_tool, refund_tool). The bare
    identifier path runs only when neither structured pattern matched — this
    avoids double-counting an identifier appearing as a Tool's func= arg.
    """
    names: List[str] = []
    seen: Set[str] = set()

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


def _extract_decorator_tools(text: str) -> List[Tuple[str, int]]:
    """Find @tool-decorated functions. Returns list of (tool_name, line_no)."""
    out: List[Tuple[str, int]] = []
    for m in TOOL_DECORATOR_RE.finditer(text):
        line_no = text.count("\n", 0, m.start()) + 1
        out.append((m.group(1), line_no))
    return out


def _extract_tools_blocks(text: str) -> List[Tuple[List[str], int, str]]:
    """Find every tools=[ ... ] block in text.

    Returns list of (tool_names, line_no, block_content) tuples.
    """
    out: List[Tuple[List[str], int, str]] = []
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


def _enclosing_function(text: str, char_offset: int) -> Optional[str]:
    """Find the name of the function containing `char_offset`. Best-effort."""
    # Scan backwards for the most recent `def name(` or `async def name(` at
    # column 0 (module-level) or any indentation.
    pre = text[:char_offset]
    matches = list(re.finditer(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", pre, re.MULTILINE))
    if not matches:
        return None
    return matches[-1].group(1)


def _detect_frameworks_in_file(text: str) -> Set[str]:
    """Return the set of framework keys detected in `text`."""
    found: Set[str] = set()
    for key, info in FRAMEWORK_PATTERNS.items():
        patterns = list(info["imports"]) + list(info["usage"])  # type: ignore[arg-type]
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
    tools: List[str]


class AgentFrameworkDetector:
    """Detect agent frameworks and the tools each agent exposes.

    Produces one Finding per identified agent definition. When a framework is
    imported but no specific agent definition is identifiable, produces one
    aggregated Finding for the framework with file count.
    """

    name = "agent_frameworks"
    category = CATEGORY_AGENT_FRAMEWORK

    def detect(self, root_path: str) -> List[Finding]:
        framework_files: Dict[str, List[str]] = {k: [] for k in FRAMEWORK_PATTERNS}
        framework_first_snippet: Dict[str, str] = {}
        agent_defs: List[_AgentDef] = []
        anthropic_tool_blocks: List[_AgentDef] = []

        for path in walk_files(root_path, extensions=[".py"]):
            text = read_text_safe(path)
            if not text:
                continue
            rel = relative_to_root(path, root_path)

            frameworks = _detect_frameworks_in_file(text)
            for fw in frameworks:
                framework_files[fw].append(rel)
                if fw not in framework_first_snippet:
                    framework_first_snippet[fw] = self._first_import_line(text, fw)

            blocks = _extract_tools_blocks(text)
            decorator_tools = _extract_decorator_tools(text)
            agent_defs.extend(
                self._extract_agent_defs(text, rel, frameworks, blocks, decorator_tools)
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

        findings: List[Finding] = []
        files_used_by_agents: Dict[str, Set[str]] = {k: set() for k in FRAMEWORK_PATTERNS}

        # 1. Per-agent findings (frameworks + anthropic-shape standalone).
        for ad in agent_defs + anthropic_tool_blocks:
            findings.append(self._finding_from_agent_def(ad))
            if ad.framework in FRAMEWORK_PATTERNS:
                files_used_by_agents.setdefault(ad.framework, set()).add(ad.file)

        # 2. Framework-only fallbacks: one Finding per framework imported in
        #    files where no specific agent definition could be identified.
        for fw, files in framework_files.items():
            leftover = sorted(set(files) - files_used_by_agents.get(fw, set()))
            if not leftover:
                continue
            display = FRAMEWORK_PATTERNS[fw]["display"]  # type: ignore[index]
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
        patterns = list(info["imports"]) + list(info["usage"])  # type: ignore[arg-type]
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
        frameworks: Set[str],
        blocks: List[Tuple[List[str], int, str]],
        decorator_tools: List[Tuple[str, int]],
    ) -> List[_AgentDef]:
        """Identify named agent definitions and attach the closest tools block.

        Tool resolution falls back in priority order: tools=[...] inside the
        constructor itself, the nearest tools=[...] block in the file, then
        any @tool-decorated functions in the file. v0.6 should track these
        with real dataflow.
        """
        defs: List[_AgentDef] = []
        decorator_tool_names = [name for name, _ in decorator_tools]

        for fw, pat in AGENT_PATTERNS:
            if fw not in frameworks:
                continue
            for m in pat.finditer(text):
                paren_idx = text.find("(", m.end() - 1)
                if paren_idx < 0:
                    continue
                end_idx = _match_bracket(text, paren_idx)
                if end_idx is None:
                    continue
                ctor_text = text[paren_idx : end_idx + 1]
                line_no = text.count("\n", 0, m.start()) + 1

                tools = self._extract_tools_from_constructor(ctor_text)
                if not tools:
                    tools = self._nearest_tools_block(blocks, line_no)
                if not tools and decorator_tool_names:
                    tools = list(decorator_tool_names)

                defs.append(
                    _AgentDef(
                        framework=fw,
                        agent_name=m.group(1),
                        file=rel_file,
                        line_no=line_no,
                        snippet=_line_snippet(text, line_no),
                        tools=tools,
                    )
                )
        return defs

    @staticmethod
    def _extract_tools_from_constructor(ctor_text: str) -> List[str]:
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
        blocks: List[Tuple[List[str], int, str]], target_line: int
    ) -> List[str]:
        """Return the tool names from the tools=[...] block closest to target_line."""
        best: Optional[Tuple[int, List[str]]] = None
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
            label = f"{FRAMEWORK_PATTERNS[ad.framework]['display']} Agent"  # type: ignore[index]
        surface = f"{label}: {ad.agent_name}"
        if ad.file:
            surface = f"{surface} (in {ad.file})"
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
