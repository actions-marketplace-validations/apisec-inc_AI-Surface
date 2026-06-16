"""MCP server detector.

Inventories Model Context Protocol (MCP) servers the application runs or
hosts in production. Two surfaces are detected:

1. Repo-level MCP config files: ``.mcp.json`` / ``mcp.json`` at the repo
   root or under ``config/`` / ``configs/`` / ``deployment/``, plus any
   ``*.json`` / ``*.yaml`` / ``*.yml`` inside an ``mcp_servers/`` directory
   at one of those locations. Each declared server becomes one Finding.
2. In-house MCP server source code (Python ``mcp.server`` / ``FastMCP``,
   JS/TS ``@modelcontextprotocol/sdk``, ``new Server(...)``, ``server.tool``).
   Each source file that defines a server becomes one Finding; tool names
   from ``@server.tool`` / ``server.tool("name", ...)`` populate permissions.

Dev-tooling configs (Claude Desktop on a laptop) are deliberately not
matched — only files that ship with the application. Malformed JSON/YAML
is skipped silently. PyYAML is used if importable, otherwise a tiny
hand-rolled YAML scanner recovers top-level keys.
"""
from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ..types import CATEGORY_MCP_SERVER, Evidence, Finding
from ..utils.walk import read_text_safe, relative_to_root, walk_files

log = logging.getLogger(__name__)


_MCP_CONFIG_FILENAMES = frozenset({".mcp.json", "mcp.json"})
_MCP_CONFIG_DIR_PARENTS = frozenset({"", "config", "configs", "deployment"})
_MCP_SERVERS_DIRNAME = "mcp_servers"

# Cheap content prefilters — files that don't contain any of these tokens
# are skipped before any regex work.
_PY_PREFILTER_TOKENS = (
    "mcp.server", "from mcp ", "from mcp.", "import mcp", "FastMCP", "Server(",
)
_JS_PREFILTER_TOKENS = (
    "@modelcontextprotocol/sdk", "modelcontextprotocol", "FastMCP",
    "new Server(", "setRequestHandler", "server.tool(",
)

_PY_SERVER_PATTERNS = (
    re.compile(r"from\s+mcp\.server\b"),
    re.compile(r"from\s+mcp\s+import\s+[^\n]*\bServer\b"),
    re.compile(r"\bFastMCP\s*\("),
    re.compile(r"\bmcp\.Server\s*\("),
)
_JS_SERVER_PATTERNS = (
    re.compile(r"""['"]@modelcontextprotocol/sdk[^'"]*['"]"""),
    re.compile(r"\bnew\s+Server\s*\("),
    re.compile(r"\bserver\.setRequestHandler\s*\("),
    re.compile(r"\bserver\.tool\s*\("),
    re.compile(r"\bFastMCP\s*\("),
)

# @server.tool / @app.tool decorator → captures the def name that follows.
_PY_TOOL_DECORATOR_RE = re.compile(
    r"@\s*(?:[a-zA-Z_][a-zA-Z_0-9]*\.)?(?:tool|app\.tool)\s*(?:\([^)]*\))?\s*\n"
    r"\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z_0-9]*)",
)
# server.tool("name", ...) registration (JS/TS or Python).
_TOOL_CALL_RE = re.compile(
    r"""(?:server|app|mcp)\.tool\s*\(\s*['"]([A-Za-z_][A-Za-z_0-9\-]*)['"]""",
)

_FINANCIAL_TOKENS = (
    "refund", "refunds", "payment", "payments", "charge", "charges",
    "payout", "payouts", "invoice", "invoices", "billing",
    "wire", "transfer", "transfers", "withdraw", "withdrawal",
)
_BROAD_PERMISSION_TOKENS = frozenset({"admin", "write", "delete", "*", "all", "owner", "root"})

# Word-boundary split for permission strings. Permissions in real MCP configs
# look like `repo:read`, `issues:write`, `admin`, `read:all`, `*`, `wallet_balance`.
# Splitting on these separators avoids substring false positives such as
# `install_app` (contains "all") or `co-administrator` (contains "admin").
_PERM_WORD_SPLIT_RE = re.compile(r"[_\-\s./:]+|(?<=[a-z])(?=[A-Z])")


def _perm_words(s: str) -> frozenset[str]:
    """Tokenize a permission string into atomic words, lowercased."""
    return frozenset(w for w in _PERM_WORD_SPLIT_RE.split(s.lower()) if w)
_SNIPPET_MAX = 200


class McpServerDetector:
    """Inventory MCP servers declared or implemented in the scanned repo.

    See module docstring for the patterns covered. Produces one
    :class:`Finding` per declared/implemented server. Safe to run on any
    directory tree.
    """

    name = "mcp_servers"
    category = CATEGORY_MCP_SERVER

    def detect(self, root_path: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._detect_configs(root_path))
        findings.extend(self._detect_source(root_path))
        return findings

    def _detect_configs(self, root_path: str) -> list[Finding]:
        out: list[Finding] = []
        root = Path(root_path).resolve()
        for path in walk_files(root_path, extensions=[".json", ".yaml", ".yml"]):
            if not _is_mcp_config_path(path, root):
                continue
            text = read_text_safe(path)
            if not text:
                continue
            servers = _parse_mcp_config(path, text)
            if not servers:
                continue
            rel = relative_to_root(path, root_path)
            for server_name, server_cfg in servers:
                out.append(_finding_from_config(rel, server_name, server_cfg, text))
        return out

    def _detect_source(self, root_path: str) -> list[Finding]:
        out: list[Finding] = []
        exts = [".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]
        for path in walk_files(root_path, extensions=exts, skip_tests=True):
            text = read_text_safe(path)
            if not text:
                continue
            is_python = path.suffix.lower() == ".py"
            tokens = _PY_PREFILTER_TOKENS if is_python else _JS_PREFILTER_TOKENS
            if not any(tok in text for tok in tokens):
                continue
            patterns = _PY_SERVER_PATTERNS if is_python else _JS_SERVER_PATTERNS
            match = _first_match(patterns, text)
            if match is None:
                continue
            tools = _extract_tools(text, is_python=is_python)
            rel = relative_to_root(path, root_path)
            out.append(_finding_from_source(rel, text, match, tools))
        return out


def _is_mcp_config_path(path: Path, root: Path) -> bool:
    """Return True iff ``path`` looks like a repo-level MCP config file.

    Recognised: ``<root>/.mcp.json`` or ``<root>/mcp.json``;
    ``<config|configs|deployment>/.mcp.json`` (or ``mcp.json``);
    any file under ``mcp_servers/`` at the root or under those parents.
    """
    name = path.name
    try:
        rel_parts = path.resolve().relative_to(root).parts
    except ValueError:
        return False
    if not rel_parts:
        return False

    if name in _MCP_CONFIG_FILENAMES:
        if len(rel_parts) == 1:
            return True
        return len(rel_parts) == 2 and rel_parts[0] in _MCP_CONFIG_DIR_PARENTS

    if _MCP_SERVERS_DIRNAME in rel_parts:
        prefix = rel_parts[: rel_parts.index(_MCP_SERVERS_DIRNAME)]
        if len(prefix) == 0:
            return True
        if len(prefix) == 1 and prefix[0] in _MCP_CONFIG_DIR_PARENTS:
            return True
    return False


def _parse_mcp_config(path: Path, text: str) -> list[tuple[str, dict[str, Any]]]:
    """Parse an MCP config file → ``[(server_name, cfg), ...]``. Empty on failure."""
    if path.suffix.lower() == ".json":
        try:
            data: Any = json.loads(text)
        except (json.JSONDecodeError, ValueError) as exc:
            log.debug("skipping malformed MCP JSON %s: %s", path, exc)
            return []
    else:
        data = _parse_yaml_lenient(text)
        if data is None:
            log.debug("skipping unparseable MCP YAML %s", path)
            return []
    return _extract_servers_from_config(data, path)


def _extract_servers_from_config(
    data: Any, path: Path
) -> list[tuple[str, dict[str, Any]]]:
    """Recognise common MCP-config shapes and yield server entries.

    Shapes: ``{"mcpServers": {name: cfg}}``, ``{"servers": {name: cfg}}``,
    ``{"servers": [{"name": ..., ...}]}``, or a single-server file under
    ``mcp_servers/`` shaped like ``{"name": ..., ...}``.
    """
    if not isinstance(data, dict):
        return []
    for key in ("mcpServers", "servers", "mcp_servers"):
        block = data.get(key)
        if isinstance(block, dict) and block:
            return [(str(k), v if isinstance(v, dict) else {}) for k, v in block.items()]
        if isinstance(block, list) and block:
            out: list[tuple[str, dict[str, Any]]] = []
            for entry in block:
                if not isinstance(entry, dict):
                    continue
                nm = entry.get("name") or entry.get("id") or "unnamed-mcp"
                out.append((str(nm), entry))
            if out:
                return out
    # Per-server file under mcp_servers/.
    if path.parent.name == _MCP_SERVERS_DIRNAME:
        nm = data.get("name") or data.get("id") or path.stem
        return [(str(nm), data)]

    return []


def _parse_yaml_lenient(text: str) -> dict[str, Any] | None:
    """Best-effort YAML parser. Uses PyYAML if importable, else a fallback."""
    try:  # pragma: no cover - depends on environment
        import yaml  # type: ignore

        loaded = yaml.safe_load(text)
        return loaded if isinstance(loaded, dict) else None
    except ImportError:
        pass
    except Exception as exc:  # pragma: no cover - defensive
        log.debug("PyYAML failed to parse: %s", exc)
        return None
    return _yaml_lenient_fallback(text)


def _yaml_lenient_fallback(text: str) -> dict[str, Any]:
    """Recover top-level mapping keys plus one level of nested mappings.

    Good enough for synthetic configs and the common MCP-server YAML shape;
    indentation-sensitive, ignores list entries.
    """
    result: dict[str, Any] = {}
    current_parent: str | None = None
    parent_block: dict[str, Any] = {}
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip().strip('"').strip("'")
        value = value.strip()
        if indent == 0:
            if current_parent is not None:
                result[current_parent] = parent_block
            current_parent = key
            parent_block = {}
            if value and value not in {"|", ">"}:
                result[key] = value.strip('"').strip("'")
                current_parent = None
        else:
            if current_parent is None:
                continue
            parent_block.setdefault(key, value.strip('"').strip("'") if value else {})
    if current_parent is not None:
        result[current_parent] = parent_block
    return result


def _first_match(patterns: Iterable[re.Pattern], text: str) -> re.Match | None:
    """Return the earliest match of any pattern in ``patterns``."""
    best: re.Match | None = None
    for pat in patterns:
        m = pat.search(text)
        if m is not None and (best is None or m.start() < best.start()):
            best = m
    return best


def _extract_tools(text: str, *, is_python: bool) -> list[str]:
    """Tool names from ``@server.tool``/``@app.tool`` (Python) and ``server.tool("name", ...)``."""
    found: list[str] = []
    seen: set[str] = set()
    iters = []
    if is_python:
        iters.append(_PY_TOOL_DECORATOR_RE.finditer(text))
    iters.append(_TOOL_CALL_RE.finditer(text))
    for it in iters:
        for m in it:
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                found.append(name)
    return found


def _finding_from_config(
    rel_path: str, server_name: str, server_cfg: dict[str, Any], full_text: str,
) -> Finding:
    """Build a Finding for one server declared in a config file."""
    permissions = _permissions_from_cfg(server_cfg)
    risks: list[str] = []
    if _has_broad_permissions(permissions, server_cfg):
        risks.append("broad permissions")
    if _has_financial_action(permissions + [server_name]):
        risks.append("financial action exposed")
    return Finding(
        surface=f"MCP Server: {server_name}",
        category=CATEGORY_MCP_SERVER,
        evidence=Evidence(
            files=[rel_path],
            snippet=_snippet_for_server(server_name, full_text),
            metadata={
                "server_name": server_name,
                "config_keys": sorted(server_cfg.keys()) if isinstance(server_cfg, dict) else [],
                "source": "config",
            },
        ),
        permissions=permissions,
        risk_indicators=risks,
    )


def _finding_from_source(
    rel_path: str, text: str, match: re.Match, tools: list[str],
) -> Finding:
    """Build a Finding for an in-house MCP server defined in source."""
    risks: list[str] = ["in-house MCP server (custom code, audit recommended)"]
    if _has_financial_action(tools):
        risks.append("financial action exposed")
    return Finding(
        surface=f"MCP Server (in-house): {rel_path}",
        category=CATEGORY_MCP_SERVER,
        evidence=Evidence(
            files=[rel_path],
            snippet=_snippet_around(text, match.start()),
            line_numbers=[1 + text.count("\n", 0, match.start())],
            metadata={"tools": tools, "source": "code"},
        ),
        permissions=list(tools),
        risk_indicators=risks,
    )


def _permissions_from_cfg(cfg: dict[str, Any]) -> list[str]:
    """Flatten permission/capability strings from a server config."""
    if not isinstance(cfg, dict):
        return []
    out: list[str] = []
    for key in ("capabilities", "permissions", "scopes", "tools", "allowedTools"):
        val = cfg.get(key)
        if val is None:
            continue
        if isinstance(val, str):
            out.append(val)
        elif isinstance(val, list):
            out.extend(str(x) for x in val if isinstance(x, (str, int)))
        elif isinstance(val, dict):
            out.extend(str(k) for k in val)
    seen: set[str] = set()
    uniq: list[str] = []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def _has_broad_permissions(permissions: list[str], cfg: dict[str, Any]) -> bool:
    """True if any permission string contains a broad-permission token as a
    whole word. Uses word-boundary tokenization to avoid substring false
    positives (e.g., `install_app` containing "all").
    """
    haystack: list[str] = list(permissions)
    if isinstance(cfg, dict):
        for key in ("scope", "role", "access"):
            v = cfg.get(key)
            if isinstance(v, str):
                haystack.append(v)
    return any(_perm_words(p) & _BROAD_PERMISSION_TOKENS for p in haystack)


def _has_financial_action(names: Iterable[str]) -> bool:
    """True if any tool name contains a financial token as a whole word."""
    for n in names:
        words = _perm_words(str(n))
        if any(tok in words for tok in _FINANCIAL_TOKENS):
            return True
    return False


def _snippet_around(text: str, pos: int, width: int = _SNIPPET_MAX) -> str:
    half = width // 2
    snippet = text[max(0, pos - half): min(len(text), pos + half)]
    snippet = snippet.replace("\n", " ").strip()
    return snippet[:_SNIPPET_MAX]


def _snippet_for_server(server_name: str, full_text: str) -> str:
    """Return the line containing ``server_name`` if findable, else file head."""
    idx = full_text.find(f'"{server_name}"')
    if idx == -1:
        idx = full_text.find(server_name)
    if idx == -1:
        return full_text[:_SNIPPET_MAX].replace("\n", " ").strip()
    line_start = full_text.rfind("\n", 0, idx) + 1
    line_end = full_text.find("\n", idx)
    if line_end == -1:
        line_end = len(full_text)
    return full_text[line_start:line_end].strip()[:_SNIPPET_MAX]


__all__ = ["McpServerDetector"]
