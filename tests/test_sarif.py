"""Tests for the SARIF 2.1.0 reporter (GitHub code scanning)."""
from __future__ import annotations

import json

from ai_surface.reporters.sarif_reporter import render_sarif, to_sarif
from ai_surface.types import (
    CATEGORY_API,
    CATEGORY_LLM_SDK,
    CATEGORY_MCP_SERVER,
    SEVERITY_CRITICAL,
    SEVERITY_MEDIUM,
    Audit,
    Evidence,
    Finding,
    Report,
    RiskFlag,
    Secret,
)


def _report() -> Report:
    crit = Finding(
        surface="MCP Server: stripe-mcp", category=CATEGORY_MCP_SERVER,
        evidence=Evidence(files=[".mcp.json"], line_numbers=[4]),
        severity=SEVERITY_CRITICAL,
        audit=Audit(
            risk_flags=[RiskFlag("secrets-detected", SEVERITY_CRITICAL, "secret", ["LLM02"])],
            secrets=[Secret(name="STRIPE_SECRET_KEY", secret_type="stripe-key")],
        ),
    )
    med = Finding(surface="REST API: GET /x/{id}", category=CATEGORY_API,
                  evidence=Evidence(files=["openapi.yaml"]), severity=SEVERITY_MEDIUM)
    inv = Finding(surface="Anthropic SDK", category=CATEGORY_LLM_SDK,
                  evidence=Evidence(files=["a.py"]))  # no severity
    return Report(findings=[crit, med, inv], scan_root="x",
                  scan_timestamp="2026-06-11T00:00:00+00:00", detectors_run=[])


def test_valid_sarif_envelope() -> None:
    log = json.loads(render_sarif(_report()))
    assert log["version"] == "2.1.0"
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "ai-surface"
    assert len(run["results"]) == 3
    assert any(r["id"] == "mcp-server" for r in run["tool"]["driver"]["rules"])


def test_severity_maps_to_sarif_levels() -> None:
    run = to_sarif(_report())["runs"][0]
    by_surface = {r["message"]["text"].split(" | ")[0]: r["level"] for r in run["results"]}
    assert by_surface["MCP Server: stripe-mcp"] == "error"   # critical
    assert by_surface["REST API: GET /x/{id}"] == "warning"  # medium
    assert by_surface["Anthropic SDK"] == "note"             # inventory


def test_location_and_no_secret_leak() -> None:
    out = render_sarif(_report())
    log = json.loads(out)
    mcp = next(r for r in log["runs"][0]["results"] if r["ruleId"] == "mcp-server")
    loc = mcp["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == ".mcp.json"
    assert loc["region"]["startLine"] == 4
    assert mcp["properties"]["owasp"] == ["LLM02"]
    # SARIF does not emit secrets at all, and no secret value can ever appear.
    assert "sk_live" not in out
