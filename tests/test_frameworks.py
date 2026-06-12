"""Tests for governance-framework evidence mapping (honest evidence-for)."""
from __future__ import annotations

from ai_surface.frameworks import framework_evidence, framework_names
from ai_surface.types import (
    CATEGORY_LLM_SDK,
    CATEGORY_MCP_SERVER,
    SEVERITY_HIGH,
    Audit,
    Evidence,
    Finding,
    Report,
    RiskFlag,
)


def _report(findings) -> Report:
    return Report(findings=findings, scan_root="x",
                  scan_timestamp="2026-06-11T00:00:00+00:00", detectors_run=[])


def test_empty_scan_has_no_framework_evidence() -> None:
    assert framework_evidence(_report([])) == []


def test_inventory_only_backs_inventory_requirements_not_risk() -> None:
    f = Finding(surface="Anthropic SDK", category=CATEGORY_LLM_SDK,
                evidence=Evidence(files=["a.py"]))  # no risk, no severity
    names = framework_names(_report([f]))
    # Inventory frameworks appear; OWASP (needs owasp evidence) does not.
    assert "EU AI Act" in names and "NIST AI RMF" in names and "ISO/IEC 42001" in names
    assert "OWASP LLM Top 10" not in names


def test_audited_finding_backs_risk_and_owasp() -> None:
    f = Finding(
        surface="MCP Server: x", category=CATEGORY_MCP_SERVER,
        evidence=Evidence(files=[".mcp.json"]), severity=SEVERITY_HIGH,
        audit=Audit(risk_flags=[RiskFlag("broad-permissions", SEVERITY_HIGH, "", ["LLM06"])],
                    owasp_mappings=["LLM06"]),
    )
    ev = {e["name"]: e["provides"] for e in framework_evidence(_report([f]))}
    assert "OWASP LLM Top 10" in ev
    # EU AI Act risk-management requirement is now backed.
    assert any("Risk management" in p for p in ev["EU AI Act"])


def test_standards_for_flag_specific_clauses() -> None:
    from ai_surface.frameworks import standards_for_flag

    obs = standards_for_flag("no-observability")
    fws = {s["framework"] for s in obs}
    assert fws == {"EU AI Act", "NIST AI RMF", "ISO 42001"}
    assert any(s["clause"] == "Art. 12" for s in obs)

    assert standards_for_flag("no-human-oversight") == [
        {"framework": "EU AI Act", "framework_id": "eu-ai-act", "clause": "Art. 14"}
    ]
    # Capability flags carry OWASP only, no specific clause here.
    assert standards_for_flag("shell-access") == []
    assert standards_for_flag("unknown-flag") == []


def test_json_reporter_attaches_standards_to_flags() -> None:
    from ai_surface.reporters.json_reporter import report_to_dict

    f = Finding(
        surface="MCP Server: x", category=CATEGORY_MCP_SERVER,
        evidence=Evidence(files=[".mcp.json"]), severity=SEVERITY_HIGH,
        audit=Audit(
            risk_flags=[RiskFlag("no-human-oversight", SEVERITY_HIGH, "", ["LLM06", "LLM09"])],
            owasp_mappings=["LLM06", "LLM09"],
        ),
    )
    d = report_to_dict(_report([f]))
    rf = d["findings"][0]["audit"]["risk_flags"][0]
    assert rf["standards"] == [
        {"framework": "EU AI Act", "framework_id": "eu-ai-act", "clause": "Art. 14"}
    ]
