"""Generate the canonical schema-1.0 sample report.

This fixture is the contract the parallel build tracks code against:
  - the UI viewer renders fixtures/sample_report.json directly (no scanning)
  - detector authors check their output shape against it
  - the funnel layer checks bridge link shape against it

Run:  python fixtures/generate_sample.py
Writes: fixtures/sample_report.json

The sample intentionally covers every category, a deep-dive MCP audit with
risk flags + secrets + trust, an API finding for the API-runtime SKU, and all
three paid bridges, so downstream tracks see the full surface.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running from repo root without install.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ai_surface.cross_promo import attach_bridges  # noqa: E402
from ai_surface.reporters.json_reporter import render_json  # noqa: E402
from ai_surface.types import (  # noqa: E402
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_API,
    CATEGORY_LLM_SDK,
    CATEGORY_MCP_SERVER,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    Audit,
    Evidence,
    Finding,
    Report,
    RiskFlag,
    Secret,
)


def build() -> Report:
    findings = [
        # 1. Pure discovery finding (no severity, no audit) — the baseline shape.
        Finding(
            surface="Anthropic SDK",
            category=CATEGORY_LLM_SDK,
            evidence=Evidence(
                files=["src/agents/refund.py", "src/agents/support.py"],
                snippet="client = anthropic.Anthropic()\nclient.messages.create(model=...)",
                line_numbers=[12, 48],
                metadata={"model": "claude-opus-4-8", "non_literal_input": True},
            ),
            permissions=["network: api.anthropic.com"],
            risk_indicators=["user input flows into prompt"],
            detector_name="llm_sdks",
        ),
        # 2. Agent framework discovery with bridge to agent validation.
        Finding(
            surface="LangChain Agent: refund_agent",
            category=CATEGORY_AGENT_FRAMEWORK,
            evidence=Evidence(
                files=["src/agents/refund.py"],
                snippet="AgentExecutor(tools=[query_customer_db, refund_payment])",
                line_numbers=[60],
                metadata={"tools": ["query_customer_db", "refund_payment"]},
            ),
            permissions=["query_customer_db", "refund_payment"],
            risk_indicators=["financial action exposed"],
            detector_name="agent_frameworks",
        ),
        # 3. MCP discovery WITH deep-dive audit (the merged mcp-audit layer).
        Finding(
            surface="MCP Server: stripe-mcp",
            category=CATEGORY_MCP_SERVER,
            evidence=Evidence(
                files=[".mcp.json"],
                snippet='"stripe-mcp": {"command": "npx", "args": ["stripe-mcp"], "env": {...}}',
                line_numbers=[4],
                metadata={"tools": ["create_charge", "refund", "list_customers"]},
            ),
            permissions=["create_charge", "refund", "list_customers"],
            risk_indicators=["financial action exposed", "secrets in env block"],
            detector_name="mcp_audit",
            severity=SEVERITY_CRITICAL,
            audit=Audit(
                risk_flags=[
                    RiskFlag(
                        flag="secrets-in-env",
                        severity=SEVERITY_CRITICAL,
                        description="Live Stripe secret key present in MCP env block",
                        owasp=["LLM02"],
                        remediation="Move the key to a secrets manager; reference by name only.",
                    ),
                    RiskFlag(
                        flag="financial-action",
                        severity=SEVERITY_HIGH,
                        description="MCP exposes refund and charge tools to the model",
                        owasp=["LLM06"],
                        remediation="Gate financial tools behind human approval.",
                    ),
                    RiskFlag(
                        flag="unverified-source",
                        severity=SEVERITY_MEDIUM,
                        description="MCP server not found in known registry",
                        owasp=["LLM03"],
                    ),
                ],
                secrets=[
                    Secret(
                        name="STRIPE_SECRET_KEY",
                        secret_type="stripe-key",
                        confidence="high",
                        severity=SEVERITY_CRITICAL,
                        location=".mcp.json:env",
                    )
                ],
                trust_score=None,
                trust_label="unknown",
                registry_match="unknown",
                owasp_mappings=["LLM02", "LLM06", "LLM03"],
            ),
        ),
        # 4. API discovery (NEW) feeding the API outside-in runtime SKU.
        Finding(
            surface="REST API: POST /v1/orders/{id}/refund",
            category=CATEGORY_API,
            evidence=Evidence(
                files=["openapi.yaml"],
                snippet="paths:\n  /v1/orders/{id}/refund:\n    post:",
                line_numbers=[142],
                metadata={
                    "method": "POST",
                    "path": "/v1/orders/{id}/refund",
                    "source_spec": "openapi.yaml",
                    "auth": "bearer",
                    "framework": "fastapi",
                },
            ),
            permissions=["mutates order state", "financial"],
            risk_indicators=["object-id in path (BOLA candidate)"],
            detector_name="api_endpoints",
        ),
    ]

    report = Report(
        findings=findings,
        scan_root="/example/acme-payments",
        scan_timestamp="2026-06-11T00:00:00+00:00",
        detectors_run=[
            "llm_sdks",
            "agent_frameworks",
            "mcp_audit",
            "api_endpoints",
        ],
    )
    # Classify dispositions then attach bridges, so the fixture equals real
    # engine output (resolve-here vs validate-runtime, capability-aware bridges).
    from ai_surface.audits import enrich_audits  # noqa: PLC0415
    from ai_surface.dispositions import attach_dispositions  # noqa: PLC0415

    enrich_audits(report.findings)
    attach_dispositions(report.findings)
    attach_bridges(report.findings)
    report.summary = report.build_summary()
    return report


def main() -> None:
    out = Path(__file__).resolve().parent / "sample_report.json"
    report = build()
    out.write_text(render_json(report) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(report.findings)} findings, schema {report.schema_version})")


if __name__ == "__main__":
    main()
