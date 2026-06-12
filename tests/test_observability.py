"""Tests for the AI observability / logging-presence audit pass.

EU AI Act Art. 12 / ISO A.6.2.6 / NIST MEASURE 3: AI execution surfaces should
be traced. The pass flags agent/MCP surfaces when the repo wires no observability
anywhere, and stays quiet when any tracing signal is present.
"""
from __future__ import annotations

from ai_surface.observability import (
    enrich_observability,
    observability_in_findings,
    repo_has_observability,
)
from ai_surface.types import (
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_ENV_KEY,
    CATEGORY_LLM_SDK,
    CATEGORY_MCP_SERVER,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    Audit,
    Evidence,
    Finding,
    RiskFlag,
)


def _agent(audit: Audit | None = None) -> Finding:
    return Finding(
        surface="LangChain Agent: refund_agent",
        category=CATEGORY_AGENT_FRAMEWORK,
        evidence=Evidence(),
        audit=audit,
    )


def _mcp() -> Finding:
    return Finding(
        surface="MCP Server: stripe-mcp",
        category=CATEGORY_MCP_SERVER,
        evidence=Evidence(),
        audit=Audit(risk_flags=[RiskFlag("financial-action", SEVERITY_HIGH, "", ["LLM06"], "")]),
    )


def test_flags_agent_and_mcp_when_no_observability() -> None:
    findings = [_agent(), _mcp()]
    enrich_observability(findings, scan_root=None)
    for f in findings:
        flags = [rf.flag for rf in f.audit.risk_flags]
        assert "no-observability" in flags


def test_creates_audit_for_benign_agent() -> None:
    f = _agent(audit=None)  # benign agent, no prior audit
    enrich_observability([f], scan_root=None)
    assert f.audit is not None
    assert any(rf.flag == "no-observability" for rf in f.audit.risk_flags)
    assert f.severity == SEVERITY_LOW


def test_no_flag_when_findings_show_observability() -> None:
    # A tracing provider/proxy finding (Helicone) is a strong signal.
    gw = Finding(surface="Helicone", category=CATEGORY_ENV_KEY, evidence=Evidence())
    findings = [_agent(), gw]
    enrich_observability(findings, scan_root=None)
    assert not any(
        rf.flag == "no-observability" for rf in (findings[0].audit.risk_flags if findings[0].audit else [])
    )


def test_observability_key_in_env_is_not_proof() -> None:
    # A bare observability key present does NOT suppress the gap (weak signal).
    env = Finding(
        surface="Observability key (.env)",
        category=CATEGORY_ENV_KEY,
        evidence=Evidence(),
        risk_indicators=["observability/tracing key present (production telemetry to third party)"],
    )
    findings = [_agent(), env]
    enrich_observability(findings, scan_root=None)
    assert any(rf.flag == "no-observability" for rf in findings[0].audit.risk_flags)


def test_does_not_flag_llm_sdk_surface() -> None:
    llm = Finding(surface="Anthropic SDK", category=CATEGORY_LLM_SDK, evidence=Evidence())
    enrich_observability([llm], scan_root=None)
    # LLM-SDK stays discovery-only: no audit invented for it.
    assert llm.audit is None


def test_idempotent() -> None:
    f = _mcp()
    enrich_observability([f], scan_root=None)
    enrich_observability([f], scan_root=None)
    assert [rf.flag for rf in f.audit.risk_flags].count("no-observability") == 1


def test_observability_in_findings_detects_provider_surface() -> None:
    gw = Finding(surface="Helicone", category=CATEGORY_ENV_KEY, evidence=Evidence())
    assert observability_in_findings([gw]) is True
    plain = Finding(surface="Anthropic SDK", category=CATEGORY_LLM_SDK, evidence=Evidence())
    assert observability_in_findings([plain]) is False


def test_repo_scan_detects_source_signal(tmp_path) -> None:
    (tmp_path / "trace.py").write_text("from langsmith import Client\nclient = Client()\n")
    assert repo_has_observability(str(tmp_path)) is True


def test_repo_scan_detects_env_signal(tmp_path) -> None:
    (tmp_path / ".env").write_text("LANGCHAIN_TRACING_V2=true\nLANGCHAIN_API_KEY=x\n")
    assert repo_has_observability(str(tmp_path)) is True


def test_repo_scan_negative(tmp_path) -> None:
    (tmp_path / "app.py").write_text("import anthropic\nclient = anthropic.Anthropic()\n")
    assert repo_has_observability(str(tmp_path)) is False


def test_repo_scan_no_substring_false_positive(tmp_path) -> None:
    # Regression: "arize" must not match inside "singularize" (caught dogfooding
    # on a real repo). Word boundaries keep observability signals precise.
    (tmp_path / "util.py").write_text("def _singularize(w):\n    return w[:-1]\n")
    assert repo_has_observability(str(tmp_path)) is False


def test_repo_signal_suppresses_flag(tmp_path) -> None:
    (tmp_path / "obs.py").write_text("import opentelemetry\n")
    f = _mcp()
    enrich_observability([f], scan_root=str(tmp_path))
    assert not any(rf.flag == "no-observability" for rf in f.audit.risk_flags)
