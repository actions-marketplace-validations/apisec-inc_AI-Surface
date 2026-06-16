"""HTTP / REST / OpenAPI endpoint detector.

Inventories the HTTP API surface of a codebase so each discovered endpoint
becomes a candidate for the paid "API outside-in runtime testing" SKU. Two
sources are mined, statically and offline:

1. **OpenAPI / Swagger specs** (``openapi.{yaml,yml,json}``, ``swagger.{json,
   yaml,yml}``): every ``path`` + HTTP method pair becomes one Finding. Auth is
   derived from ``security`` / ``securitySchemes`` when possible, else
   ``"unknown"``.
2. **Framework route definitions** (best-effort, regex/AST-light): FastAPI /
   Starlette, Flask, Express (JS/TS), Spring (Java), and Django ``urls.py``.

Discovery only: ``severity`` and ``audit`` stay ``None``; ``bridges`` is left
empty for the funnel layer (``cross_promo``) to fill. A plain-English
``risk_indicator`` ("object-id in path (BOLA candidate)") fires when a path
contains an id-like segment such as ``{id}``, ``:id`` or ``<int:id>``.

YAML parsing uses PyYAML when importable, and falls back to a small
indentation-based path/method scanner when it is not, so the detector degrades
gracefully rather than dropping YAML specs entirely.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from ..types import CATEGORY_API, Evidence, Finding
from ..utils.walk import read_text_safe, relative_to_root, walk_files

log = logging.getLogger(__name__)

# Optional dependency. Imported defensively: when absent we fall back to a
# minimal structural scan for YAML specs (see _yaml_paths_fallback).
try:
    import yaml as _yaml  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover - exercised only without PyYAML
    _yaml = None


# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

_HTTP_METHODS = ("get", "post", "put", "delete", "patch", "head", "options", "trace")

# id-like path segments that flag a likely object reference (BOLA candidate):
#   {id}, {orderId}, {order_id}      -- OpenAPI / FastAPI / Express(:style aside)
#   :id, :orderId                    -- Express / some routers
#   <int:id>, <id>, <slug:name>      -- Flask / Django converters
# Path parameter segments, matched with single bounded character classes so a
# hostile path (e.g. thousands of unbalanced `{`) cannot drive backtracking.
# Each segment's name is then checked for "id" membership in Python rather than
# embedding a literal between two lazy quantifiers (the previous ReDoS shape):
#   {id}, {orderId}, {order_id}   -- OpenAPI / FastAPI / Express
#   :id, :orderId                 -- Express / some routers
#   <int:id>, <id>, <slug:name>   -- Flask / Django converters
_PARAM_SEGMENT_RE = re.compile(
    r"\{[^{}/]*\}|:[A-Za-z0-9_]+|<[^<>/]*>",
)

_BOLA_INDICATOR = "object-id in path (BOLA candidate)"


def _has_id_segment(path: str) -> bool:
    """True if the path contains an id-like (object reference) segment."""
    for seg in _PARAM_SEGMENT_RE.findall(path):
        name = seg.strip("{}<>:")
        # For typed converters like <int:user_id>, the name is after the colon.
        if ":" in name:
            name = name.rsplit(":", 1)[-1]
        if "id" in name.lower():
            return True
    return False


def _risk_indicators_for(path: str) -> list[str]:
    return [_BOLA_INDICATOR] if _has_id_segment(path) else []


def _metadata(
    *,
    method: str,
    path: str,
    source_spec: str = "",
    auth: str = "unknown",
    framework: str = "",
) -> dict[str, Any]:
    """Build the documented CATEGORY_API metadata block.

    All five contract keys are always present (empty string when N/A) so the UI
    and the api-runtime onboarding bridge can read them without guards.
    """
    return {
        "method": method,
        "path": path,
        "source_spec": source_spec,
        "auth": auth,
        "framework": framework,
    }


# ---------------------------------------------------------------------------
# OpenAPI / Swagger spec parsing
# ---------------------------------------------------------------------------

def _looks_like_spec_name(name: str) -> bool:
    lname = name.lower()
    stem = lname.rsplit(".", 1)[0] if "." in lname else lname
    ext = lname.rsplit(".", 1)[1] if "." in lname else ""
    if ext not in ("json", "yaml", "yml"):
        return False
    return stem in ("openapi", "swagger") or stem.startswith(("openapi", "swagger"))


def _auth_from_spec(doc: dict[str, Any]) -> str:
    """Best-effort auth style from an OpenAPI document.

    Looks at top-level ``security`` plus ``securitySchemes`` (OpenAPI 3) or
    ``securityDefinitions`` (Swagger 2). Returns a coarse style string. When a
    document declares ``security: []`` (explicitly no auth) we report
    ``"none"``; when nothing is derivable we report ``"unknown"``.
    """
    components = doc.get("components")
    schemes = {}
    if isinstance(components, dict) and isinstance(components.get("securitySchemes"), dict):
        schemes = components["securitySchemes"]
    elif isinstance(doc.get("securityDefinitions"), dict):  # Swagger 2
        schemes = doc["securityDefinitions"]

    security = doc.get("security")
    # Explicit empty security means the API declares itself unauthenticated.
    if security == []:
        return "none"

    if not isinstance(schemes, dict) or not schemes:
        return "unknown"

    styles: list[str] = []
    for scheme in schemes.values():
        if not isinstance(scheme, dict):
            continue
        styles.append(_classify_scheme(scheme))
    styles = [s for s in styles if s]
    if not styles:
        return "unknown"
    # Prefer a stable, deterministic single label.
    for preferred in ("bearer", "oauth2", "apiKey", "basic"):
        if preferred in styles:
            return preferred
    return styles[0]


def _classify_scheme(scheme: dict[str, Any]) -> str:
    stype = str(scheme.get("type", "")).lower()
    sbearer = str(scheme.get("scheme", "")).lower()
    if stype == "http" and sbearer == "bearer":
        return "bearer"
    if stype == "http" and sbearer == "basic":
        return "basic"
    if stype == "oauth2":
        return "oauth2"
    if stype == "apikey":
        return "apiKey"
    if stype == "openidconnect":
        return "oauth2"
    if stype == "basic":  # Swagger 2 style
        return "basic"
    return ""


def _parse_spec(text: str, filename: str) -> dict[str, Any] | None:
    """Parse a spec file into a dict. Returns None if it can't be parsed."""
    lname = filename.lower()
    is_json = lname.endswith(".json")
    if is_json:
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return None
        return data if isinstance(data, dict) else None

    # YAML (or unknown): try PyYAML first.
    if _yaml is not None:
        try:
            data = _yaml.safe_load(text)
        except Exception:  # noqa: BLE001 - PyYAML raises a broad family of errors
            return None
        return data if isinstance(data, dict) else None
    return None  # fallback handled by caller via _yaml_paths_fallback


# Indentation-based fallback (no PyYAML). Captures path keys under a top-level
# `paths:` block and the methods nested beneath each. Intentionally narrow: it
# handles the conventional 2-space-indented spec layout and quietly produces
# nothing for shapes it can't read, rather than guessing.
_PATH_KEY_RE = re.compile(r"^(\s+)(/[^\s:]*)\s*:\s*$")
_METHOD_KEY_RE = re.compile(r"^(\s+)(get|post|put|delete|patch|head|options|trace)\s*:", re.IGNORECASE)


def _yaml_paths_fallback(text: str) -> dict[str, list[str]]:
    """Extract {path: [methods]} from a YAML spec without PyYAML.

    Best-effort, deterministic. Tracks the indent of the ``paths:`` block, the
    path keys directly under it, and the HTTP-method keys nested beneath each
    path. Returns an appearance-ordered mapping; paths with no methods are
    dropped.
    """
    out: dict[str, list[str]] = {}
    in_paths = False
    paths_indent = -1
    current_path: str | None = None
    path_indent = -1

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))

        if not in_paths:
            if raw.strip() == "paths:" or _re_paths_header(raw):
                in_paths = True
                paths_indent = indent
                current_path = None
            continue

        # Dedent back to/above the paths header ends the block.
        if indent <= paths_indent:
            in_paths = False
            current_path = None
            continue

        pm = _PATH_KEY_RE.match(raw)
        if pm is not None and indent > paths_indent:
            current_path = pm.group(2)
            path_indent = indent
            out.setdefault(current_path, [])
            continue

        mm = _METHOD_KEY_RE.match(raw)
        if mm is not None and current_path is not None and indent > path_indent:
            method = mm.group(2).upper()
            if method not in out[current_path]:
                out[current_path].append(method)

    return {p: m for p, m in out.items() if m}


def _re_paths_header(raw: str) -> bool:
    """True if the line is a ``paths:`` mapping key (allowing trailing spaces)."""
    return re.match(r"^\s*paths\s*:\s*$", raw) is not None


def _spec_findings(text: str, rel: str) -> list[Finding]:
    """Emit one Finding per path+method declared in an OpenAPI/Swagger spec."""
    findings: list[Finding] = []
    doc = _parse_spec(text, rel)

    if doc is not None:
        paths = doc.get("paths")
        if not isinstance(paths, dict):
            return []
        auth = _auth_from_spec(doc)
        for path, item in paths.items():
            if not isinstance(path, str) or not isinstance(item, dict):
                continue
            for method in _HTTP_METHODS:
                if method not in item:
                    continue
                findings.append(
                    _make_finding(
                        method=method.upper(),
                        path=path,
                        rel=rel,
                        snippet=_spec_snippet(text, path),
                        source_spec=rel,
                        auth=auth,
                        framework="",
                    )
                )
        return findings

    # PyYAML unavailable (or unparseable JSON already returned []): try the
    # structural YAML fallback so YAML specs still produce an inventory.
    if rel.lower().endswith((".yaml", ".yml")):
        for path, methods in _yaml_paths_fallback(text).items():
            for method in methods:
                findings.append(
                    _make_finding(
                        method=method,
                        path=path,
                        rel=rel,
                        snippet=_spec_snippet(text, path),
                        source_spec=rel,
                        auth="unknown",
                        framework="",
                    )
                )
    return findings


def _spec_snippet(text: str, path: str) -> str:
    """Return a short snippet anchored at the path's first appearance."""
    idx = text.find(path)
    if idx < 0:
        return path[:200]
    line_start = text.rfind("\n", 0, idx) + 1
    # Grab up to two lines from the path key for context.
    end = text.find("\n", idx)
    end = text.find("\n", end + 1) if end >= 0 else -1
    if end < 0:
        end = len(text)
    return text[line_start:end].strip()[:200]


def _line_no_of(text: str, needle: str) -> int:
    idx = text.find(needle)
    if idx < 0:
        return 0
    return text.count("\n", 0, idx) + 1


# ---------------------------------------------------------------------------
# Framework route patterns
# ---------------------------------------------------------------------------
#
# Each entry produces (method, path) pairs. Method is upper-cased; "*" means
# the framework registered the route for all/any methods (e.g. Spring
# @RequestMapping without an explicit method, or a Django path()).

# FastAPI / Starlette: @app.get("...") / @router.post("...") etc.
# Group 1 = the router/app object, so a router's prefix can be resolved.
_FASTAPI_RE = re.compile(
    r"""@\s*([A-Za-z_]\w*)\s*\.\s*"""
    r"""(get|post|put|delete|patch|head|options|trace)\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
# APIRouter(prefix="/orders") so routes declared on that router resolve to the
# full path (a real FastAPI pattern; without this, paths look truncated).
_APIROUTER_PREFIX_RE = re.compile(
    r"""\b([A-Za-z_]\w*)\s*=\s*APIRouter\s*\([^)]*?prefix\s*=\s*['"]([^'"]+)['"]""",
    re.DOTALL,
)

# Flask: @app.route("/path", methods=["GET","POST"]) / @bp.route(...)
_FLASK_ROUTE_RE = re.compile(
    r"""@\s*(?:[A-Za-z_]\w*)\s*\.\s*(?:route|add_url_rule)\s*\(\s*['"]([^'"]+)['"]([^)]*)\)""",
    re.IGNORECASE | re.DOTALL,
)
_FLASK_METHODS_RE = re.compile(r"""methods\s*=\s*[\[\(]([^\]\)]*)[\]\)]""", re.IGNORECASE)

# Express (JS/TS): app.get("/path", ...) / router.post('/path', ...)
_EXPRESS_RE = re.compile(
    r"""\b(?:app|router|[A-Za-z_]\w*Router|api)\s*\.\s*"""
    r"""(get|post|put|delete|patch|head|options|all)\s*\(\s*['"`]([^'"`]+)['"`]""",
)

# Spring (Java): @GetMapping("/path"), @RequestMapping(value="/path", method=...)
_SPRING_MAPPING_RE = re.compile(
    r"""@(Get|Post|Put|Delete|Patch|Request)Mapping\s*(?:\(\s*(?:value\s*=\s*)?(?:\{\s*)?['"]([^'"]+)['"])?""",
)

# Django: path("route/", view) / re_path(r"^route/$", view)
_DJANGO_RE = re.compile(
    r"""\b(?:re_path|path)\s*\(\s*[rR]?['"]([^'"]+)['"]""",
)


def _join_prefix(prefix: str, path: str) -> str:
    """Join an APIRouter prefix with a route path into one normalized path."""
    if not prefix:
        return path
    base = prefix.rstrip("/")
    if not path or path == "/":
        return base or "/"
    return base + "/" + path.lstrip("/")


def _fastapi_routes(text: str) -> list[tuple[str, str, int]]:
    # Map each router variable to its APIRouter(prefix=...), if any.
    prefixes = {m.group(1): m.group(2) for m in _APIROUTER_PREFIX_RE.finditer(text)}
    out: list[tuple[str, str, int]] = []
    for m in _FASTAPI_RE.finditer(text):
        obj, method, path = m.group(1), m.group(2).upper(), m.group(3)
        out.append((method, _join_prefix(prefixes.get(obj, ""), path),
                    text.count("\n", 0, m.start()) + 1))
    return out


def _flask_routes(text: str) -> list[tuple[str, str, int]]:
    out: list[tuple[str, str, int]] = []
    for m in _FLASK_ROUTE_RE.finditer(text):
        path = m.group(1)
        rest = m.group(2) or ""
        methods_m = _FLASK_METHODS_RE.search(rest)
        line_no = text.count("\n", 0, m.start()) + 1
        if methods_m:
            raw = methods_m.group(1)
            methods = [v.strip().strip("'\"").upper() for v in raw.split(",") if v.strip()]
            methods = [v for v in methods if v]
        else:
            methods = ["GET"]  # Flask default when methods= omitted
        for method in methods:
            out.append((method, path, line_no))
    return out


def _express_routes(text: str) -> list[tuple[str, str, int]]:
    out: list[tuple[str, str, int]] = []
    for m in _EXPRESS_RE.finditer(text):
        method = m.group(1).upper()
        if method == "ALL":
            method = "*"
        out.append((method, m.group(2), text.count("\n", 0, m.start()) + 1))
    return out


def _spring_routes(text: str) -> list[tuple[str, str, int]]:
    out: list[tuple[str, str, int]] = []
    for m in _SPRING_MAPPING_RE.finditer(text):
        verb = m.group(1)
        path = m.group(2) or "/"
        line_no = text.count("\n", 0, m.start()) + 1
        if verb == "Request":
            # @RequestMapping may carry method=RequestMethod.POST; pull it if present.
            tail = text[m.start():m.start() + 300]
            method_m = re.search(r"method\s*=\s*(?:\{\s*)?RequestMethod\.([A-Z]+)", tail)
            method = method_m.group(1).upper() if method_m else "*"
        else:
            method = verb.upper()
        out.append((method, path, line_no))
    return out


def _django_routes(text: str) -> list[tuple[str, str, int]]:
    out: list[tuple[str, str, int]] = []
    for m in _DJANGO_RE.finditer(text):
        path = m.group(1)
        # Normalize a leading slash for display consistency.
        if not path.startswith(("/", "^")):
            path = "/" + path
        out.append(("*", path, text.count("\n", 0, m.start()) + 1))
    return out


# Per-extension framework dispatch. Each framework runs only on file types it
# can plausibly appear in, keeping false positives down.
_PY_FRAMEWORKS: list[tuple[str, Any]] = [
    ("fastapi", _fastapi_routes),
    ("flask", _flask_routes),
    ("django", _django_routes),
]
_JS_FRAMEWORKS: list[tuple[str, Any]] = [
    ("express", _express_routes),
]
_JAVA_FRAMEWORKS: list[tuple[str, Any]] = [
    ("spring", _spring_routes),
]


def _make_finding(
    *,
    method: str,
    path: str,
    rel: str,
    snippet: str,
    source_spec: str,
    auth: str,
    framework: str,
    line_no: int = 0,
) -> Finding:
    return Finding(
        surface=f"REST API: {method} {path}",
        category=CATEGORY_API,
        evidence=Evidence(
            files=[rel],
            snippet=snippet[:200],
            line_numbers=[line_no] if line_no else [],
            metadata=_metadata(
                method=method,
                path=path,
                source_spec=source_spec,
                auth=auth,
                framework=framework,
            ),
        ),
        permissions=[],
        risk_indicators=_risk_indicators_for(path),
        # severity / audit stay None (discovery only); bridges left for funnel.
    )


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

# File extensions per language family.
_SPEC_EXTS = (".json", ".yaml", ".yml")
_PY_EXTS = (".py",)
_JS_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs")
_JAVA_EXTS = (".java",)

_ALL_EXTS = (*_SPEC_EXTS, *_PY_EXTS, *_JS_EXTS, *_JAVA_EXTS)


class ApiEndpointDetector:
    """Detect HTTP/REST endpoints and OpenAPI specs in a codebase.

    Produces one Finding per (path, method) pair, from OpenAPI/Swagger specs
    and from framework route definitions (FastAPI/Starlette, Flask, Express,
    Spring, Django). Discovery only: no severity, no audit, no bridges.
    """

    name = "api_endpoints"
    category = CATEGORY_API

    def detect(self, root_path: str) -> list[Finding]:
        findings: list[Finding] = []
        # Deduplicate identical (method, path, framework/source, file) surfaces.
        seen: set[tuple[str, str, str]] = set()

        for file_path in walk_files(root_path, extensions=list(_ALL_EXTS)):
            text = read_text_safe(file_path)
            if not text:
                continue
            rel = relative_to_root(file_path, root_path)
            name = file_path.name
            suffix = file_path.suffix.lower()

            # 1. OpenAPI / Swagger specs.
            if suffix in _SPEC_EXTS and _looks_like_spec_name(name):
                for f in _spec_findings(text, rel):
                    key = (
                        f.evidence.metadata["method"],
                        f.evidence.metadata["path"],
                        f"spec:{rel}",
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(f)
                # A spec file is not also a framework source; skip framework pass.
                continue

            # 2. Framework route definitions.
            if suffix in _PY_EXTS:
                self._collect_framework(text, rel, _PY_FRAMEWORKS, seen, findings)
            elif suffix in _JS_EXTS:
                self._collect_framework(text, rel, _JS_FRAMEWORKS, seen, findings)
            elif suffix in _JAVA_EXTS:
                self._collect_framework(text, rel, _JAVA_FRAMEWORKS, seen, findings)

        return findings

    @staticmethod
    def _collect_framework(
        text: str,
        rel: str,
        frameworks: list[tuple[str, Any]],
        seen: set[tuple[str, str, str]],
        findings: list[Finding],
    ) -> None:
        for framework, extractor in frameworks:
            for method, path, line_no in extractor(text):
                key = (method, path, framework)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    _make_finding(
                        method=method,
                        path=path,
                        rel=rel,
                        snippet=_line_snippet(text, line_no),
                        source_spec="",
                        auth="unknown",
                        framework=framework,
                        line_no=line_no,
                    )
                )


def _line_snippet(text: str, line_no: int, max_len: int = 200) -> str:
    if line_no < 1:
        return ""
    lines = text.splitlines()
    if line_no > len(lines):
        return ""
    return lines[line_no - 1].strip()[:max_len]


# Backwards/forwards-compatible alias in case the integrator references either
# spelling. The orchestrator registration uses ApiEndpointDetector.
ApiEndpointsDetector = ApiEndpointDetector
