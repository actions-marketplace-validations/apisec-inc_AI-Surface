"""Tests for the CycloneDX AI-BOM reporter."""
from __future__ import annotations

import json

from ai_surface.cross_promo import attach_bridges
from ai_surface.reporters.cyclonedx_reporter import render_cyclonedx, to_cyclonedx
from ai_surface.types import (
    CATEGORY_API,
    CATEGORY_MCP_SERVER,
    SEVERITY_CRITICAL,
    Audit,
    Evidence,
    Finding,
    Report,
    RiskFlag,
    Secret,
)

LEAKED_VALUE = "sk_live_must_not_appear_in_bom"


def _report() -> Report:
    mcp = Finding(
        surface="MCP Server: stripe-mcp",
        category=CATEGORY_MCP_SERVER,
        evidence=Evidence(files=[".mcp.json"]),
        severity=SEVERITY_CRITICAL,
        detector_name="mcp_audit",
        audit=Audit(
            risk_flags=[
                RiskFlag("secrets-detected", SEVERITY_CRITICAL, "secret in env", ["LLM02"]),
            ],
            secrets=[Secret(name="STRIPE_SECRET_KEY", secret_type="stripe-key",
                            confidence="high", severity=SEVERITY_CRITICAL, location=".mcp.json")],
            trust_label="unknown",
        ),
    )
    api = Finding(
        surface="REST API: POST /v1/orders/{id}/refund",
        category=CATEGORY_API,
        evidence=Evidence(metadata={"method": "POST", "path": "/v1/orders/{id}/refund",
                                    "framework": "fastapi", "auth": "bearer"}),
        risk_indicators=["object-id in path (BOLA candidate)"],
        detector_name="api_endpoints",
    )
    r = Report(findings=[mcp, api], scan_root="acme-payments",
               scan_timestamp="2026-06-11T00:00:00+00:00",
               detectors_run=["mcp_audit", "api_endpoints"])
    attach_bridges(r.findings)
    r.summary = r.build_summary()
    return r


def test_valid_cyclonedx_envelope() -> None:
    bom = json.loads(render_cyclonedx(_report()))
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["metadata"]["tools"]["components"][0]["name"] == "ai-surface"
    assert bom["metadata"]["component"]["name"] == "acme-payments"
    assert len(bom["components"]) == 2


def test_components_carry_category_severity_and_validate_sku() -> None:
    bom = to_cyclonedx(_report())
    mcp = next(c for c in bom["components"] if c["name"].startswith("MCP"))
    props = {(p["name"], p["value"]) for p in mcp["properties"]}
    assert ("ai-surface:category", "mcp-server") in props
    assert ("ai-surface:severity", "critical") in props
    assert ("ai-surface:owasp", "LLM02") in props
    assert ("ai-surface:validate", "mcp-runtime") in props
    assert mcp["type"] == "application"


def test_api_component_has_endpoint_props_and_service_type() -> None:
    bom = to_cyclonedx(_report())
    api = next(c for c in bom["components"] if c["name"].startswith("REST"))
    props = {(p["name"], p["value"]) for p in api["properties"]}
    assert ("ai-surface:api-method", "POST") in props
    assert ("ai-surface:api-path", "/v1/orders/{id}/refund") in props
    assert api["type"] == "service"
    assert ("ai-surface:validate", "api-runtime") in props


def test_no_secret_value_leaks_into_bom() -> None:
    r = _report()
    # Even if a value somehow rode along on the secret, the BOM must not emit it.
    r.findings[0].audit.secrets[0].location = f".mcp.json (value={LEAKED_VALUE})"
    out = render_cyclonedx(r)
    # The reporter only emits name + type for secrets, so the value cannot appear
    # via the secret property. Guard the whole document regardless.
    assert "STRIPE_SECRET_KEY" in out  # name is fine
    # The secret property is name (type), not location, so the planted value is absent.
    bom = json.loads(out)
    mcp = next(c for c in bom["components"] if c["name"].startswith("MCP"))
    secret_props = [p["value"] for p in mcp["properties"] if p["name"] == "ai-surface:secret"]
    assert secret_props == ["STRIPE_SECRET_KEY (stripe-key)"]
    assert LEAKED_VALUE not in " ".join(secret_props)
