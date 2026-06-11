"""Tests for the reporters."""
from __future__ import annotations

import json

import pytest
from rich.console import Console

from ai_surface.reporters.json_reporter import render_json, report_to_dict
from ai_surface.reporters.markdown_reporter import render_markdown
from ai_surface.reporters.terminal_reporter import render_terminal
from ai_surface.types import (
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_LLM_SDK,
    CATEGORY_MCP_SERVER,
    Evidence,
    Finding,
    Report,
)


def _sample_report() -> Report:
    findings = [
        Finding(
            surface="Anthropic SDK",
            category=CATEGORY_LLM_SDK,
            evidence=Evidence(
                files=["src/llm/handler.py", "src/agents/refund.py"],
                snippet="from anthropic import Anthropic",
                metadata={"models_used": ["claude-3-5-sonnet-20241022"], "call_site_count": 3},
            ),
            risk_indicators=["non-literal data flows into LLM call"],
            detector_name="LlmSdkDetector",
        ),
        Finding(
            surface="LangChain Agent: refund_agent",
            category=CATEGORY_AGENT_FRAMEWORK,
            evidence=Evidence(
                files=["src/agents/refund.py"],
                snippet='AgentExecutor(tools=[query_db, refund_payment, send_email])',
                metadata={"framework": "langchain", "agent_name": "refund_agent"},
            ),
            permissions=["query_customer_db", "refund_payment", "send_email", "list_charges"],
            risk_indicators=[
                "financial action exposed",
                "high blast-radius combination",
            ],
            detector_name="AgentFrameworkDetector",
        ),
        Finding(
            surface="MCP Server: stripe-mcp",
            category=CATEGORY_MCP_SERVER,
            evidence=Evidence(
                files=[".mcp.json"],
                snippet='"stripe-mcp": {"capabilities": ["read", "refund"]}',
                metadata={},
            ),
            permissions=["read charges", "refund charges"],
            risk_indicators=["broad permissions"],
            detector_name="McpServerDetector",
        ),
    ]
    return Report(
        findings=findings,
        scan_root="/tmp/example-repo",
        scan_timestamp="2026-05-09T12:00:00+00:00",
        detectors_run=["LlmSdkDetector", "AgentFrameworkDetector", "McpServerDetector"],
    )


def _empty_report() -> Report:
    return Report(
        findings=[],
        scan_root="/tmp/clean-repo",
        scan_timestamp="2026-05-09T12:00:00+00:00",
        detectors_run=["LlmSdkDetector"],
    )


# ---- JSON reporter ----


def test_json_reporter_produces_valid_json() -> None:
    report = _sample_report()
    rendered = render_json(report)
    parsed = json.loads(rendered)
    assert parsed["schema_version"] == "1.0"
    assert parsed["findings_count"] == 3
    assert len(parsed["findings"]) == 3
    surfaces = [f["surface"] for f in parsed["findings"]]
    assert "Anthropic SDK" in surfaces
    assert "LangChain Agent: refund_agent" in surfaces


def test_json_reporter_preserves_evidence_metadata() -> None:
    report = _sample_report()
    parsed = json.loads(render_json(report))
    anthropic = next(f for f in parsed["findings"] if f["surface"] == "Anthropic SDK")
    assert "claude-3-5-sonnet-20241022" in anthropic["evidence"]["metadata"]["models_used"]


def test_json_reporter_handles_empty_report() -> None:
    parsed = json.loads(render_json(_empty_report()))
    assert parsed["findings_count"] == 0
    assert parsed["findings"] == []


def test_report_to_dict_round_trip() -> None:
    report = _sample_report()
    d = report_to_dict(report)
    json.dumps(d)  # raises if not serializable


# ---- Markdown reporter ----


def test_markdown_reporter_includes_header_and_counts() -> None:
    md = render_markdown(_sample_report())
    assert "# AI Inventory" in md
    assert "Production AI surfaces:" in md
    assert "Risk indicators:" in md


def test_markdown_reporter_includes_each_finding() -> None:
    md = render_markdown(_sample_report())
    assert "Anthropic SDK" in md
    assert "LangChain Agent: refund_agent" in md
    assert "MCP Server: stripe-mcp" in md
    assert "claude-3-5-sonnet-20241022" in md


def test_markdown_reporter_includes_risk_summary() -> None:
    md = render_markdown(_sample_report())
    assert "Risk Indicator Summary" in md
    assert "financial action exposed" in md


def test_markdown_reporter_handles_empty_report() -> None:
    md = render_markdown(_empty_report())
    assert "No production AI surfaces detected" in md


def test_markdown_reporter_includes_cross_sell() -> None:
    md = render_markdown(_sample_report())
    assert "apisec.ai/ai-validation" in md


# ---- Terminal reporter ----


def test_terminal_reporter_runs_without_error(capsys: pytest.CaptureFixture[str]) -> None:
    """We don't assert on rich-formatted output, just that it doesn't blow up."""
    console = Console(record=True, force_terminal=True, width=120)
    render_terminal(_sample_report(), console)
    text = console.export_text()
    assert "AI Surface Report" in text
    assert "Anthropic SDK" in text
    assert "refund_agent" in text


def test_terminal_reporter_handles_empty_report() -> None:
    console = Console(record=True, force_terminal=True, width=120)
    render_terminal(_empty_report(), console)
    text = console.export_text()
    assert "No production AI surfaces detected" in text


def test_terminal_reporter_shows_summary_counts() -> None:
    console = Console(record=True, force_terminal=True, width=120)
    render_terminal(_sample_report(), console)
    text = console.export_text()
    assert "3" in text  # surface count
    assert "production AI surfaces" in text or "production AI surface" in text
