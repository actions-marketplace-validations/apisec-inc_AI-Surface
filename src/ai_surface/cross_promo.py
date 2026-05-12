"""Cross-promotion: deep-links from ai-surface findings into the rest of the
APIsec Labs OSS family and into the APIsec validation platform.

Two kinds of cross-promotion supported:

  * Vertical (OSS -> APIsec validation). Every report links back to APIsec
    for runtime exploit validation, with finding category and risk indicator
    embedded as URL params and UTM attribution for marketing analytics.

  * Lateral (OSS -> sibling specialist tool). When ai-surface detects a
    surface that has a deeper-analysis specialist (e.g., MCP server -> mcp-audit),
    the report points at it. Lateral pointers respect a per-tool availability
    flag, so we can register agent-audit / prompt-audit etc. without rendering
    them until they ship.

Design notes:
  - Risk indicator slugs are mapped explicitly (not regex-slugified) so the
    URL params are predictable and deterministic.
  - UTM attribution lets APIsec marketing track which OSS tool drove which
    click. When other specialists ship (agent-audit, etc.), each gets its
    own utm_source.
  - URL params layer additively: defaults work today, missing finding context
    falls back to a generic upgrade URL.
"""
from __future__ import annotations

from typing import TypedDict
from urllib.parse import urlencode

from .types import (
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_AI_INFRA,
    CATEGORY_ENV_KEY,
    CATEGORY_LLM_SDK,
    CATEGORY_MCP_SERVER,
    CATEGORY_MODEL_GATEWAY,
    Finding,
)


class SpecialistTool(TypedDict):
    """Per-category specialist tool metadata in SPECIALIST_TOOLS."""

    tool: str
    available: bool
    url: str
    tagline: str
    install: str

# ---------------------------------------------------------------------------
# Vertical: APIsec validation (the conversion link)
# ---------------------------------------------------------------------------

#: Base URL for the APIsec validation upgrade landing page. The page exists
#: today and reads ?surface= and ?risk= params; UTM params are standard.
APISEC_BASE_URL = "https://apisec.ai/ai-validation"

#: Default UTM campaign value for OSS-funnel attribution. APIsec marketing
#: dashboards filter on this to measure conversion.
DEFAULT_UTM_CAMPAIGN = "oss-funnel"


# ---------------------------------------------------------------------------
# Lateral: sibling OSS specialists in the APIsec Labs family
# ---------------------------------------------------------------------------
#
# Per-category specialist registry. When ai-surface detects a finding in
# `category`, the corresponding specialist (if `available`) gets a "for
# deeper analysis, run X" pointer in the report. Flip `available` to True
# when each tool ships.

SPECIALIST_TOOLS: dict[str, SpecialistTool] = {
    CATEGORY_MCP_SERVER: {
        "tool": "mcp-audit",
        "available": True,
        "url": "https://github.com/apisec-inc/mcp-audit",
        "tagline": "for deep MCP server analysis",
        "install": "pip install mcp-audit",
    },
    CATEGORY_AGENT_FRAMEWORK: {
        "tool": "agent-audit",
        "available": False,  # ships Q3 2026; framework ready
        "url": "https://github.com/apisec-inc/agent-audit",
        "tagline": "for deep agent framework analysis (coming Q3 2026)",
        "install": "pip install agent-audit",
    },
    CATEGORY_MODEL_GATEWAY: {
        "tool": "gateway-audit",
        "available": False,  # demand-driven, no commit yet
        "url": "https://github.com/apisec-inc/gateway-audit",
        "tagline": "for deep model gateway analysis",
        "install": "pip install gateway-audit",
    },
}


# ---------------------------------------------------------------------------
# Risk indicator slug mapping
# ---------------------------------------------------------------------------
#
# Stable, deterministic mapping from human-readable risk indicator phrases to
# URL slugs. Adding a new indicator requires adding a slug here. We chose this
# over regex slugification to keep URLs predictable for analytics and to
# make the slug an explicit product surface, not a side effect.

RISK_SLUG: dict[str, str] = {
    # MCP server risks
    "broad permissions": "broad-permissions",
    "in-house MCP server (custom code, audit recommended)": "in-house-mcp",
    # Agent framework risks
    "financial action exposed": "financial-action",
    "destructive action exposed": "destructive-action",
    "messaging action exposed": "messaging-action",
    "database write exposed": "database-write",
    "high blast-radius combination": "high-blast-radius",
    # LLM SDK risks
    "non-literal data flows into LLM call": "non-literal-data-flow",
    # Env key risks
    "multiple AI provider keys present": "multiple-providers",
    "observability/tracing key present (production telemetry to third party)": "observability-key",
    # Model gateway / AI infra risks
    "multi-model routing layer (production traffic flows through this)": "multi-model-routing",
    "self-hosted LLM runtime (operational responsibility on the team)": "self-hosted-llm",
    "high-cost AI infrastructure (billing exposure)": "high-cost-ai-infra",
}


def slugify_risk(indicator: str) -> str:
    """Map a risk indicator phrase to a URL slug.

    Returns the explicit slug from RISK_SLUG when known. For unknown indicators
    (forward-compatibility for future risk types), falls back to a permissive
    slugifier so links still work.
    """
    if indicator in RISK_SLUG:
        return RISK_SLUG[indicator]
    # Permissive fallback: lowercase, alnum + dashes, length-capped
    out: list[str] = []
    for ch in indicator.lower():
        if ch.isalnum():
            out.append(ch)
        elif ch in (" ", "-", "_", "/"):
            out.append("-")
    slug = "".join(out)
    # Collapse runs of dashes and trim
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-")[:60]


# ---------------------------------------------------------------------------
# Public API: URL construction
# ---------------------------------------------------------------------------


def build_upgrade_url(
    finding: Finding | None = None,
    source: str = "ai-surface",
    medium: str = "cli",
    campaign: str = DEFAULT_UTM_CAMPAIGN,
) -> str:
    """Return an APIsec upgrade URL with optional finding context and UTM attribution.

    Args:
        finding: if provided, embeds the finding's category and top risk
            indicator as query params for context-aware landing.
        source: utm_source value. Defaults to "ai-surface". When other tools
            join the family, each gets its own source name.
        medium: utm_medium. "cli" for terminal, "pr-comment" for the GitHub
            Action PR comment, "markdown" for the .ai-inventory.md artifact.
        campaign: utm_campaign. Defaults to the family-wide oss-funnel value.

    Returns:
        A fully-qualified URL safe to embed in markdown or terminal output.
    """
    params: list[tuple[str, str]] = []

    if finding is not None:
        if finding.category:
            params.append(("surface", finding.category))
        if finding.risk_indicators:
            # Pick the first risk indicator as the headline. Findings list them
            # in priority order from the detector that produced them.
            params.append(("risk", slugify_risk(finding.risk_indicators[0])))

    params.append(("utm_source", source))
    params.append(("utm_medium", medium))
    params.append(("utm_campaign", campaign))

    query = urlencode(params)
    return f"{APISEC_BASE_URL}?{query}"


def headline_finding(findings: list[Finding]) -> Finding | None:
    """Return the most severe finding from a list, for use in footer links.

    Severity heuristic: number of risk indicators on the finding. Tied counts
    fall back to category priority (MCP > agent > LLM > env > gateway > infra).
    """
    if not findings:
        return None
    category_priority = {
        CATEGORY_MCP_SERVER: 6,
        CATEGORY_AGENT_FRAMEWORK: 5,
        CATEGORY_LLM_SDK: 4,
        CATEGORY_ENV_KEY: 3,
        CATEGORY_MODEL_GATEWAY: 2,
        CATEGORY_AI_INFRA: 1,
    }
    return max(
        findings,
        key=lambda f: (
            len(f.risk_indicators),
            category_priority.get(f.category, 0),
        ),
    )


# ---------------------------------------------------------------------------
# Public API: lateral specialist pointers
# ---------------------------------------------------------------------------


def specialist_for(category: str) -> SpecialistTool | None:
    """Return the specialist tool entry for a category if one is registered AND
    available. Returns None when no specialist exists or the registered
    specialist is not yet shipped (`available: False`).

    Use this in reporters to conditionally render "for deeper analysis, run X"
    lines without code changes when new specialists ship; flipping the
    `available` flag in SPECIALIST_TOOLS is enough.
    """
    entry = SPECIALIST_TOOLS.get(category)
    if entry is None:
        return None
    if not entry.get("available"):
        return None
    return entry


def specialists_for_report(findings: list[Finding]) -> list[SpecialistTool]:
    """Return the deduplicated set of available specialists relevant to a report.

    Walks the findings, collects categories, and returns one entry per
    available specialist whose category appears in the report.
    """
    seen_categories = set()
    out: list[SpecialistTool] = []
    for f in findings:
        if f.category in seen_categories:
            continue
        seen_categories.add(f.category)
        spec = specialist_for(f.category)
        if spec is not None:
            out.append(spec)
    return out
