"""Tests for the cross-promotion module."""
from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from ai_surface.cross_promo import (
    APISEC_BASE_URL,
    DEFAULT_UTM_CAMPAIGN,
    SPECIALIST_TOOLS,
    build_upgrade_url,
    headline_finding,
    slugify_risk,
    specialist_for,
    specialists_for_report,
)
from ai_surface.types import (
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_LLM_SDK,
    CATEGORY_MCP_SERVER,
    CATEGORY_MODEL_GATEWAY,
    Evidence,
    Finding,
)


def _f(
    surface: str = "Test SDK",
    category: str = CATEGORY_LLM_SDK,
    risk_indicators: list = None,
) -> Finding:
    return Finding(
        surface=surface,
        category=category,
        evidence=Evidence(),
        risk_indicators=list(risk_indicators or []),
    )


# ---------------------------------------------------------------------------
# slugify_risk
# ---------------------------------------------------------------------------


def test_slugify_known_risk_uses_explicit_mapping() -> None:
    assert slugify_risk("broad permissions") == "broad-permissions"
    assert slugify_risk("financial action exposed") == "financial-action"
    assert slugify_risk("high blast-radius combination") == "high-blast-radius"
    assert slugify_risk("non-literal data flows into LLM call") == "non-literal-data-flow"


def test_slugify_unknown_risk_falls_back_to_permissive_slugifier() -> None:
    # Permissive slug: lowercase, alnum + dashes, no consecutive dashes
    assert slugify_risk("Some Future Risk!") == "some-future-risk"
    assert slugify_risk("multiple   spaces") == "multiple-spaces"
    assert slugify_risk("with/slash") == "with-slash"


def test_slugify_caps_length_for_unknown_risks() -> None:
    very_long = "a" * 200
    slug = slugify_risk(very_long)
    assert len(slug) <= 60


# ---------------------------------------------------------------------------
# build_upgrade_url
# ---------------------------------------------------------------------------


def test_build_url_no_finding_returns_default_with_utm() -> None:
    url = build_upgrade_url()
    parsed = urlparse(url)
    assert parsed.scheme == "https"
    assert "apisec.ai" in parsed.netloc
    params = parse_qs(parsed.query)
    assert params["utm_source"] == ["ai-surface"]
    assert params["utm_medium"] == ["cli"]
    assert params["utm_campaign"] == [DEFAULT_UTM_CAMPAIGN]
    assert "category" not in params
    assert "risk" not in params


def test_build_url_with_finding_embeds_category_and_risk() -> None:
    finding = _f(
        category=CATEGORY_MCP_SERVER,
        risk_indicators=["broad permissions", "in-house MCP server (custom code, audit recommended)"],
    )
    url = build_upgrade_url(finding)
    params = parse_qs(urlparse(url).query)
    assert params["category"] == [CATEGORY_MCP_SERVER]
    # First risk indicator wins (priority order from detector)
    assert params["risk"] == ["broad-permissions"]


def test_build_url_with_finding_no_risks_omits_risk_param() -> None:
    finding = _f(category=CATEGORY_LLM_SDK, risk_indicators=[])
    url = build_upgrade_url(finding)
    params = parse_qs(urlparse(url).query)
    assert params["category"] == [CATEGORY_LLM_SDK]
    assert "risk" not in params


def test_build_url_respects_source_and_medium_overrides() -> None:
    url = build_upgrade_url(source="mcp-audit", medium="pr-comment", campaign="custom")
    params = parse_qs(urlparse(url).query)
    assert params["utm_source"] == ["mcp-audit"]
    assert params["utm_medium"] == ["pr-comment"]
    assert params["utm_campaign"] == ["custom"]


def test_build_url_starts_with_apisec_base() -> None:
    url = build_upgrade_url(_f(category=CATEGORY_MCP_SERVER))
    assert url.startswith(APISEC_BASE_URL)


# ---------------------------------------------------------------------------
# headline_finding
# ---------------------------------------------------------------------------


def test_headline_returns_none_for_empty_list() -> None:
    assert headline_finding([]) is None


def test_headline_picks_finding_with_most_risk_indicators() -> None:
    a = _f(surface="A", risk_indicators=["one"])
    b = _f(surface="B", risk_indicators=["one", "two", "three"])
    c = _f(surface="C", risk_indicators=[])
    assert headline_finding([a, b, c]) is b


def test_headline_breaks_ties_by_category_priority() -> None:
    """MCP server > agent framework > LLM SDK on tied risk counts."""
    mcp = _f(surface="mcp", category=CATEGORY_MCP_SERVER, risk_indicators=["x"])
    agent = _f(surface="agent", category=CATEGORY_AGENT_FRAMEWORK, risk_indicators=["y"])
    llm = _f(surface="llm", category=CATEGORY_LLM_SDK, risk_indicators=["z"])
    assert headline_finding([llm, agent, mcp]) is mcp
    assert headline_finding([llm, agent]) is agent


# ---------------------------------------------------------------------------
# specialist_for / specialists_for_report
# ---------------------------------------------------------------------------


def test_specialist_for_returns_mcp_audit_when_available() -> None:
    spec = specialist_for(CATEGORY_MCP_SERVER)
    assert spec is not None
    assert spec["tool"] == "mcp-audit"
    assert spec["available"] is True


def test_specialist_for_returns_none_when_unavailable() -> None:
    """agent-audit isn't shipped yet, so the lateral pointer suppresses."""
    assert specialist_for(CATEGORY_AGENT_FRAMEWORK) is None
    assert specialist_for(CATEGORY_MODEL_GATEWAY) is None


def test_specialist_for_returns_none_for_unregistered_category() -> None:
    assert specialist_for(CATEGORY_LLM_SDK) is None


def test_specialists_for_report_dedupes_by_category() -> None:
    findings = [
        _f(surface="MCP A", category=CATEGORY_MCP_SERVER),
        _f(surface="MCP B", category=CATEGORY_MCP_SERVER),
        _f(surface="LLM", category=CATEGORY_LLM_SDK),
    ]
    out = specialists_for_report(findings)
    # MCP server has a specialist (mcp-audit, available); LLM has no specialist
    assert len(out) == 1
    assert out[0]["tool"] == "mcp-audit"


def test_specialists_for_report_skips_unavailable() -> None:
    findings = [
        _f(surface="LangChain", category=CATEGORY_AGENT_FRAMEWORK),
        _f(surface="MCP", category=CATEGORY_MCP_SERVER),
    ]
    out = specialists_for_report(findings)
    # agent-audit is unavailable; only mcp-audit shows up
    tools = [s["tool"] for s in out]
    assert "agent-audit" not in tools
    assert "mcp-audit" in tools


def test_specialist_registry_has_expected_categories() -> None:
    """Sanity check: confirm we have entries for the categories we care about."""
    assert CATEGORY_MCP_SERVER in SPECIALIST_TOOLS
    assert CATEGORY_AGENT_FRAMEWORK in SPECIALIST_TOOLS
    assert CATEGORY_MODEL_GATEWAY in SPECIALIST_TOOLS
