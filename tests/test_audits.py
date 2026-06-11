"""Tests for deep-dive audit enrichment (agents + the post-process layer)."""
from __future__ import annotations

from ai_surface.audits import agent_audit, enrich_audits
from ai_surface.types import (
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_MCP_SERVER,
    CATEGORY_MODEL_GATEWAY,
    SEVERITY_HIGH,
    Audit,
    Evidence,
    Finding,
    RiskFlag,
)


def _agent(perms, risks=None):
    return Finding(surface="LangChain Agent: x", category=CATEGORY_AGENT_FRAMEWORK,
                   evidence=Evidence(), permissions=perms, risk_indicators=risks or [])


def test_financial_tool_flags_high() -> None:
    a = agent_audit(_agent(["query_customer_db", "issue_refund"]))
    assert a is not None
    flags = {rf.flag: rf for rf in a.risk_flags}
    assert "financial-action" in flags
    assert flags["financial-action"].severity == SEVERITY_HIGH
    assert "LLM06" in a.owasp_mappings


def test_read_plus_financial_is_high_blast_radius() -> None:
    a = agent_audit(_agent(["list_orders", "refund_payment"]))
    assert any(rf.flag == "high-blast-radius" for rf in a.risk_flags)


def test_pii_indicator_maps_to_llm02() -> None:
    a = agent_audit(_agent(["read_profile"], ["PII flows into LLM call"]))
    assert any(rf.flag == "pii-to-llm" and "LLM02" in rf.owasp for rf in a.risk_flags)


def test_benign_agent_gets_no_audit() -> None:
    assert agent_audit(_agent(["get_weather"])) is None


def test_enrich_sets_severity_and_skips_already_audited() -> None:
    agent = _agent(["issue_refund"])
    mcp = Finding(surface="MCP", category=CATEGORY_MCP_SERVER, evidence=Evidence(),
                  audit=Audit(risk_flags=[RiskFlag("x", SEVERITY_HIGH, "d")]), severity=SEVERITY_HIGH)
    gw = Finding(surface="gw", category=CATEGORY_MODEL_GATEWAY, evidence=Evidence())
    findings = [agent, mcp, gw]
    enrich_audits(findings)
    assert agent.audit is not None and agent.severity == SEVERITY_HIGH  # newly audited
    assert mcp.audit.risk_flags[0].flag == "x"  # untouched (already audited)
    assert gw.audit is None  # posture category, not audited
