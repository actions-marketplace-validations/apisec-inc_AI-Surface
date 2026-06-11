"""Generate the rich DEMO report used by the hosted demo and launch screenshots.

Unlike fixtures/sample_report.json (the minimal contract example), this is a
realistic, dense scan of a believable fintech app ("acme-payments") with ~two
dozen AI surfaces across every category, several audited MCP servers at varied
severities, and a dozen API endpoints. Density is the point: it makes the
Attack Surface Map in the UI look like a real production codebase.

Run:    python3 fixtures/generate_demo.py
Writes: fixtures/demo_report.json AND src/ai_surface/ui/report.json
        (the UI fetches ./report.json, so this is what the hosted demo shows)

This is synthetic demo data for a tool demo, not a real customer scan.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ai_surface.cross_promo import attach_bridges  # noqa: E402
from ai_surface.reporters.json_reporter import render_json  # noqa: E402
from ai_surface.types import (  # noqa: E402
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_AI_INFRA,
    CATEGORY_API,
    CATEGORY_ENV_KEY,
    CATEGORY_LLM_SDK,
    CATEGORY_MCP_SERVER,
    CATEGORY_MODEL_GATEWAY,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    Audit,
    Evidence,
    Finding,
    Report,
    RiskFlag,
    Secret,
)


def _ev(files, snippet="", meta=None, lines=None) -> Evidence:
    return Evidence(
        files=files,
        snippet=snippet,
        line_numbers=lines or [],
        metadata=meta or {},
    )


def _llm_sdks() -> list[Finding]:
    specs = [
        ("Anthropic SDK", ["src/llm/claude.py", "src/agents/refund.py"], "claude-opus-4-8",
         ["user input flows into prompt"]),
        ("OpenAI SDK", ["src/llm/openai_client.py", "src/support/triage.py"], "gpt-4o",
         ["user input flows into prompt"]),
        ("AWS Bedrock", ["src/llm/bedrock.py"], "anthropic.claude-3-sonnet", []),
    ]
    out = []
    for name, files, model, risks in specs:
        out.append(Finding(
            surface=name, category=CATEGORY_LLM_SDK,
            evidence=_ev(files, f"client.messages.create(model='{model}', ...)",
                         {"model": model, "call_sites": len(files)}),
            permissions=["network: model provider"], risk_indicators=risks,
            detector_name="llm_sdks",
        ))
    return out


def _agents() -> list[Finding]:
    specs = [
        ("LangChain Agent: refund_agent", "src/agents/refund.py",
         ["query_customer_db", "issue_refund", "send_email"],
         ["financial action exposed", "high blast-radius combination"]),
        ("CrewAI Crew: support_crew", "src/agents/support_crew.py",
         ["search_kb", "create_ticket", "escalate"], []),
        ("LangGraph Flow: onboarding_kyc", "src/agents/onboarding.py",
         ["read_pii", "verify_identity", "approve_account"],
         ["PII flows into LLM call", "approval action exposed"]),
    ]
    out = []
    for name, f, tools, risks in specs:
        out.append(Finding(
            surface=name, category=CATEGORY_AGENT_FRAMEWORK,
            evidence=_ev([f], f"AgentExecutor(tools={tools})", {"tools": tools}),
            permissions=tools, risk_indicators=risks, detector_name="agent_frameworks",
        ))
    return out


def _mcp() -> list[Finding]:
    out = []
    # Critical: live secret + financial tools, unverified.
    out.append(Finding(
        surface="MCP Server: stripe-mcp", category=CATEGORY_MCP_SERVER,
        evidence=_ev([".mcp.json"], '"stripe-mcp": {"command": "npx", "args": ["stripe-mcp"], "env": {...}}',
                     {"tools": ["create_charge", "refund", "list_customers"],
                      "reaches": [
                          {"category": "saas", "url": "https://api.stripe.com", "source_key": "STRIPE_API_BASE"},
                          {"category": "database", "url": "postgresql://****:****@db.acme.internal/payments", "source_key": "DATABASE_URL"},
                      ],
                      "models": ["gpt-4o"]}, [4]),
        permissions=["create_charge", "refund", "list_customers"],
        risk_indicators=["financial action exposed", "secret in env block"],
        detector_name="mcp_audit", severity=SEVERITY_CRITICAL,
        audit=Audit(
            risk_flags=[
                RiskFlag("secrets-detected", SEVERITY_CRITICAL,
                         "Live Stripe secret key present in MCP env block", ["LLM02"],
                         "Move the key to a secrets manager; reference by name only."),
                RiskFlag("financial-action", SEVERITY_HIGH,
                         "MCP exposes refund and charge tools to the model", ["LLM06"],
                         "Gate financial tools behind human approval."),
                RiskFlag("unverified-source", SEVERITY_MEDIUM,
                         "MCP server not found in known registry", ["LLM03"]),
            ],
            secrets=[Secret("STRIPE_SECRET_KEY", "stripe-key", "high", SEVERITY_CRITICAL, ".mcp.json:env")],
            trust_label="unknown", registry_match="unknown",
            owasp_mappings=["LLM02", "LLM06", "LLM03"],
        ),
    ))
    # High: broad filesystem + shell.
    out.append(Finding(
        surface="MCP Server: github-mcp", category=CATEGORY_MCP_SERVER,
        evidence=_ev([".mcp.json"], '"github-mcp": {"command": "npx", "args": ["@modelcontextprotocol/server-github"]}',
                     {"tools": ["read_repo", "write_repo", "run_workflow"]}, [9]),
        permissions=["read_repo", "write_repo", "run_workflow"],
        risk_indicators=["broad permissions"],
        detector_name="mcp_audit", severity=SEVERITY_HIGH,
        audit=Audit(
            risk_flags=[
                RiskFlag("broad-permissions", SEVERITY_HIGH,
                         "Write + workflow-trigger access to source control", ["LLM06"],
                         "Scope the token to read-only or specific repos."),
                RiskFlag("shell-access", SEVERITY_MEDIUM,
                         "Can trigger CI workflows (indirect command execution)", ["LLM06"]),
            ],
            secrets=[], trust_label="community", registry_match="known", trust_score=62.0,
            owasp_mappings=["LLM06"],
        ),
    ))
    # Medium: in-house, unverified.
    out.append(Finding(
        surface="MCP Server: ledger-mcp", category=CATEGORY_MCP_SERVER,
        evidence=_ev(["services/ledger/mcp_server.py"], "FastMCP('ledger-mcp')",
                     {"tools": ["query_ledger", "post_entry"]}, [22]),
        permissions=["query_ledger", "post_entry"],
        risk_indicators=["in-house MCP server (custom code, audit recommended)", "financial action exposed"],
        detector_name="mcp_audit", severity=SEVERITY_MEDIUM,
        audit=Audit(
            risk_flags=[
                RiskFlag("unverified-source", SEVERITY_MEDIUM, "In-house MCP server, not independently audited", ["LLM03"]),
                RiskFlag("financial-action", SEVERITY_MEDIUM, "Posts ledger entries", ["LLM06"]),
            ],
            secrets=[], trust_label="unknown", registry_match="unknown", owasp_mappings=["LLM03", "LLM06"],
        ),
    ))
    # Low: read-only, verified.
    out.append(Finding(
        surface="MCP Server: weather-mcp", category=CATEGORY_MCP_SERVER,
        evidence=_ev([".mcp.json"], '"weather-mcp": {"command": "npx", "args": ["weather-mcp"]}',
                     {"tools": ["get_forecast"]}, [14]),
        permissions=["get_forecast"], risk_indicators=[],
        detector_name="mcp_audit", severity=SEVERITY_LOW,
        audit=Audit(
            risk_flags=[RiskFlag("remote-mcp", SEVERITY_LOW, "Remote MCP over HTTP", ["LLM03"])],
            secrets=[], trust_label="verified", registry_match="known", trust_score=91.0,
            owasp_mappings=["LLM03"],
        ),
    ))
    return out


def _gateways() -> list[Finding]:
    return [
        Finding(surface="LiteLLM Proxy", category=CATEGORY_MODEL_GATEWAY,
                evidence=_ev(["deploy/litellm.config.yaml"], "model_list: [...]", {"providers": 4}),
                permissions=["routes production LLM traffic"],
                risk_indicators=["multi-model routing layer (production traffic flows through this)"],
                detector_name="model_gateways"),
        Finding(surface="Portkey Gateway", category=CATEGORY_MODEL_GATEWAY,
                evidence=_ev(["src/llm/portkey.py"], "Portkey(api_key=...)", {}),
                permissions=["routes production LLM traffic"], risk_indicators=[],
                detector_name="model_gateways"),
    ]


def _infra() -> list[Finding]:
    return [
        Finding(surface="Self-hosted vLLM", category=CATEGORY_AI_INFRA,
                evidence=_ev(["deploy/k8s/vllm-deployment.yaml"], "image: vllm/vllm-openai", {"runtime": "vllm"}),
                permissions=["self-hosted inference"],
                risk_indicators=["self-hosted LLM runtime (operational responsibility on the team)"],
                detector_name="ai_infra"),
        Finding(surface="AWS Bedrock endpoint", category=CATEGORY_AI_INFRA,
                evidence=_ev(["infra/terraform/bedrock.tf"], 'resource "aws_bedrock_..."', {"cloud": "aws"}),
                permissions=["managed inference"],
                risk_indicators=["high-cost AI infrastructure (billing exposure)"],
                detector_name="ai_infra"),
    ]


def _env_keys() -> list[Finding]:
    return [
        Finding(surface="AI provider keys (.env)", category=CATEGORY_ENV_KEY,
                evidence=_ev([".env.example"], "OPENAI_API_KEY=\nANTHROPIC_API_KEY=\nLANGCHAIN_API_KEY=",
                             {"keys": ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "LANGCHAIN_API_KEY"]}),
                permissions=["names only; values never read"],
                risk_indicators=["multiple AI provider keys present"], detector_name="env_keys"),
        Finding(surface="Observability key (.env)", category=CATEGORY_ENV_KEY,
                evidence=_ev([".env.example"], "LANGSMITH_API_KEY=", {"keys": ["LANGSMITH_API_KEY"]}),
                permissions=["names only"],
                risk_indicators=["observability/tracing key present (production telemetry to third party)"],
                detector_name="env_keys"),
    ]


def _apis() -> list[Finding]:
    routes = [
        ("POST", "/v1/orders/{id}/refund", True), ("GET", "/v1/orders/{id}", True),
        ("POST", "/v1/payments", False), ("GET", "/v1/customers/{id}", True),
        ("PUT", "/v1/customers/{id}", True), ("POST", "/v1/auth/token", False),
        ("GET", "/v1/accounts/{account_id}/balance", True), ("POST", "/v1/transfers", False),
        ("DELETE", "/v1/cards/{card_id}", True), ("GET", "/v1/transactions", False),
        ("POST", "/internal/ledger/post", False), ("GET", "/v1/invoices/{id}", True),
    ]
    out = []
    for method, path, bola in routes:
        risks = ["object-id in path (BOLA candidate)"] if bola else []
        out.append(Finding(
            surface=f"REST API: {method} {path}", category=CATEGORY_API,
            evidence=_ev(["openapi.yaml"], f"{path}:\n    {method.lower()}:",
                         {"method": method, "path": path, "source_spec": "openapi.yaml",
                          "auth": "bearer", "framework": "fastapi"}),
            permissions=["mutates state"] if method != "GET" else ["reads data"],
            risk_indicators=risks, detector_name="api_endpoints",
        ))
    return out


def build() -> Report:
    findings = (
        _llm_sdks() + _agents() + _mcp() + _gateways() + _infra() + _env_keys() + _apis()
    )
    report = Report(
        findings=findings,
        scan_root="acme-payments",
        scan_timestamp="2026-06-11T00:00:00+00:00",
        detectors_run=["mcp_audit", "llm_sdks", "agent_frameworks", "env_keys",
                       "model_gateways", "ai_infra", "api_endpoints"],
    )
    from ai_surface.audits import enrich_audits  # noqa: PLC0415
    from ai_surface.dispositions import attach_dispositions  # noqa: PLC0415

    enrich_audits(report.findings)
    attach_dispositions(report.findings)
    attach_bridges(report.findings)
    report.summary = report.build_summary()
    return report


def main() -> None:
    from ai_surface.reporters.cyclonedx_reporter import render_cyclonedx  # noqa: PLC0415

    report = build()
    text = render_json(report) + "\n"
    bom = render_cyclonedx(report) + "\n"
    repo = Path(__file__).resolve().parent.parent
    ui = repo / "src" / "ai_surface" / "ui"
    (repo / "fixtures" / "demo_report.json").write_text(text, encoding="utf-8")
    (ui / "report.json").write_text(text, encoding="utf-8")
    (ui / "ai-bom.json").write_text(bom, encoding="utf-8")
    print(f"wrote demo report + AI-BOM: {len(report.findings)} findings across "
          f"{len(report.summary.by_category)} categories")


if __name__ == "__main__":
    main()
