"""AI observability / logging-presence audit pass.

EU AI Act Art. 12 (record-keeping), ISO/IEC 42001 A.6.2.6 (operation and
monitoring), NIST AI RMF MEASURE 3 (the AI system is monitored in operation):
AI execution surfaces should be logged and traced. This pass checks whether the
repo wires ANY AI observability/tracing, and if it does not, flags each
autonomous execution surface (agents and MCP servers) with ``no-observability``.

Why repo-wide, not per-file: observability is configured once (you wire
LangSmith / OpenTelemetry / Langfuse for the whole app), so the signal is
detected across the tree, not inside a single finding's evidence. If a signal
is found anywhere, no surface is flagged.

Why only agents and MCP servers: those are the autonomous, action-taking
surfaces that already carry a deep-dive Audit. Pure LLM-SDK call sites stay
discovery-only by design (the codebase deliberately does not invent severity
for posture/discovery findings), so they are not flagged here.

Design choices that keep this honest:

* Static and conservative. It checks for the *presence* of tracing wiring, not
  whether the tracing is complete or correct.
* Precise signal list. False "observability is present" would suppress a real
  gap, so the patterns are AI/ML-observability specific (low false-positive).
* It never tests the model. Structural code/config check only.
* Remediation says to confirm if observability is configured somewhere this
  scan cannot see (an infra sidecar, a platform agent, outside the repo).
"""
from __future__ import annotations

import re
from pathlib import Path

from .types import (
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_MCP_SERVER,
    SEVERITY_LOW,
    SEVERITY_ORDER,
    Audit,
    Finding,
    RiskFlag,
)
from .utils.walk import read_text_safe, walk_files

# Autonomous execution surfaces that should be observable (and already carry,
# or can carry, an Audit). LLM-SDK call sites are intentionally excluded.
_EXECUTION_CATEGORIES = frozenset(
    {
        CATEGORY_AGENT_FRAMEWORK,
        CATEGORY_MCP_SERVER,
    }
)

# Cheap substring prefilter before the regex. AI/ML-observability specific.
_PREFILTER = (
    "langsmith",
    "langfuse",
    "helicone",
    "traceloop",
    "openllmetry",
    "openinference",
    "opentelemetry",
    "otel_",
    "otel-",
    ".otel",
    "langchain_tracing",
    "langchain_api_key",
    "wandb",
    "weave",
    "mlflow",
    "logfire",
    "arize",
)

# Precise observability signals. Kept AI/ML specific to avoid false positives
# that would wrongly mark a repo as "observed" and suppress a real gap.
_SIGNAL_RE = re.compile(
    r"langsmith|langfuse|helicone|traceloop|openllmetry|openinference|"
    r"opentelemetry|\botel[_-]|langchain[_-]?tracing|langchain_api_key|"
    # \bwandb\b is distinctive; "weave" is a dictionary word (and appears in
    # minified bundles), so require real W&B Weave usage; \barize\b not "singularize".
    r"\bwandb\b|weave\.(?:init|op)|(?:import|from)\s+weave\b|mlflow|logfire|\barize\b",
    re.IGNORECASE,
)

# File shapes worth reading for an observability signal: source, config, env.
_RELEVANT_EXTS = frozenset(
    {
        ".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs",
        ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".sh",
    }
)


# Dependency manifests and lockfiles list installed/transitive packages, not
# wiring. ``langsmith`` ships as a transitive dependency of ``langchain`` and
# ``opentelemetry`` is transitive in countless packages, so reading these files
# made every langchain/otel-dependent repo look "observed" and wrongly
# suppressed the no-observability flag (validated empirically: tiny demo repos
# matched ONLY in package-lock.json / pnpm-lock.yaml). Observability must be
# evidenced by real wiring: a source import, or an enabled tracing flag in an
# env/config file (e.g. LANGCHAIN_TRACING_V2). A package merely appearing in a
# manifest is never proof.
_DEP_MANIFEST_NAMES = frozenset(
    {
        "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
        "poetry.lock", "pipfile", "pipfile.lock", "pyproject.toml",
        "setup.py", "setup.cfg", "go.mod", "go.sum",
        "cargo.toml", "cargo.lock", "gemfile", "gemfile.lock",
        "composer.json", "composer.lock", "environment.yml", "environment.yaml",
    }
)


def _is_dep_manifest(name: str) -> bool:
    """True for dependency manifests/lockfiles (transitive deps, not wiring)."""
    low = name.lower()
    if low in _DEP_MANIFEST_NAMES:
        return True
    if low.endswith(".lock"):
        return True
    return low.startswith("requirements") and low.endswith(".txt")


def _is_relevant(path: Path) -> bool:
    if _is_dep_manifest(path.name):
        return False
    if path.suffix.lower() in _RELEVANT_EXTS:
        return True
    name = path.name
    return name == ".envrc" or name == ".env" or name.startswith(".env.") or name.endswith(".env")


def repo_has_observability(scan_root: str | None) -> bool:
    """True if any AI observability/tracing signal is wired anywhere in the repo.

    Walks source/config/env files once, short-circuiting on the first signal.
    Returns False when ``scan_root`` is unavailable (callers also consult the
    findings via :func:`observability_in_findings`)."""
    if not scan_root:
        return False
    for path in walk_files(scan_root):
        if not _is_relevant(path):
            continue
        text = read_text_safe(path)
        if not text:
            continue
        low = text.lower()
        if not any(tok in low for tok in _PREFILTER):
            continue
        if _SIGNAL_RE.search(text):
            return True
    return False


def observability_in_findings(findings: list[Finding]) -> bool:
    """True if the findings themselves strongly evidence observability/tracing.

    Lets the pass work in-memory (fixtures, tests) without a repo to scan. Only
    a *strong* signal counts: a finding surface naming a tracing provider/proxy
    (Helicone, LangSmith, Langfuse, etc.). A mere observability API *key* sitting
    in an env file is deliberately NOT treated as proof: the key can be present
    while tracing is disabled, and over-crediting it would suppress a real gap.
    A genuinely observable app shows the SDK import or an enabled tracing flag,
    both of which the repo scan catches."""
    return any(_SIGNAL_RE.search(f.surface or "") for f in findings)


def _bump_severity(finding: Finding) -> None:
    if not finding.audit or not finding.audit.risk_flags:
        return
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    sevs = [rf.severity for rf in finding.audit.risk_flags]
    finding.severity = min(sevs, key=lambda s: rank.get(s, 99))


def _observability_flag() -> RiskFlag:
    return RiskFlag(
        flag="no-observability",
        severity=SEVERITY_LOW,
        description=(
            "AI execution surface has no logging/tracing configured "
            "(no observability signal found in the repo)"
        ),
        owasp=[],  # not an OWASP LLM Top 10 weakness; a record-keeping control
        remediation=(
            "Wire AI tracing/logging (OpenTelemetry, LangSmith, Langfuse, or app "
            "logging around the calls). If observability is configured outside this "
            "repo (a sidecar or platform agent), confirm it covers this surface."
        ),
    )


def enrich_observability(findings: list[Finding], scan_root: str | None = None) -> None:
    """Add ``no-observability`` flags, in place, to agent/MCP findings when the
    repo wires no AI observability anywhere.

    No-op when an observability signal is present (in the repo or already in the
    findings). Creates an Audit on a finding that lacks one (e.g. a benign agent
    with no risk flags). Idempotent: skips a finding already carrying the flag.
    """
    if observability_in_findings(findings) or repo_has_observability(scan_root):
        return

    targets = [f for f in findings if f.category in _EXECUTION_CATEGORIES]
    if not targets:
        return

    for f in targets:
        if f.audit and any(rf.flag == "no-observability" for rf in f.audit.risk_flags):
            continue
        flag = _observability_flag()
        if f.audit is None:
            f.audit = Audit(risk_flags=[flag], owasp_mappings=[])
        else:
            f.audit.risk_flags.append(flag)
        _bump_severity(f)


__all__ = [
    "repo_has_observability",
    "observability_in_findings",
    "enrich_observability",
]
