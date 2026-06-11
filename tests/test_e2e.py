"""End-to-end test of the merged flagship pipeline.

Scans one fixture app that triggers several detectors at once and asserts the
full schema-1.0 contract flows through: discovery + MCP deep-dive audit + API
inventory + funnel bridges + summary, and the privacy guarantee (no secret
value ever reaches the rendered output).
"""
from __future__ import annotations

import json
from pathlib import Path

from ai_surface.orchestrator import Orchestrator, default_detectors
from ai_surface.reporters.json_reporter import render_json
from ai_surface.reporters.markdown_reporter import render_markdown
from ai_surface.reporters.terminal_reporter import render_terminal

FIXTURE = str(Path(__file__).parent / "fixtures" / "e2e_app")

# Distinctive fragment of the fake secret planted in the fixture's .mcp.json.
# It must never appear in any rendered output.
PLANTED_SECRET_FRAGMENT = "sk_live_FAKE0123456789"


def _scan():
    return Orchestrator(default_detectors()).run(FIXTURE)


def test_e2e_covers_multiple_categories_and_bridges() -> None:
    report = _scan()
    d = json.loads(render_json(report))
    cats = {f["category"] for f in d["findings"]}
    assert {"mcp-server", "llm-sdk", "api"}.issubset(cats)
    assert d["findings_count"] >= 4
    # All three paid SKUs are reachable from this one scan.
    assert set(d["summary"]["bridges_available"]) == {
        "mcp-runtime",
        "agent-validation",
        "api-runtime",
    }


def test_e2e_mcp_deep_dive_audit_flows_through() -> None:
    d = json.loads(render_json(_scan()))
    mcp = [f for f in d["findings"] if f["category"] == "mcp-server"]
    assert mcp, "expected an MCP finding"
    f = mcp[0]
    assert f["severity"] == "critical"
    assert f["audit"] is not None
    assert len(f["audit"]["secrets"]) >= 1
    assert f["audit"]["risk_flags"], "expected at least one risk flag"
    assert f["bridges"][0]["sku"] == "mcp-runtime"


def test_e2e_api_endpoints_inventoried() -> None:
    d = json.loads(render_json(_scan()))
    api = [f for f in d["findings"] if f["category"] == "api"]
    assert len(api) >= 3
    for f in api:
        assert f["evidence"]["metadata"].get("method")
        assert f["evidence"]["metadata"].get("path")
        assert f["bridges"][0]["sku"] == "api-runtime"
    # The id-bearing route is flagged as a BOLA candidate.
    bola = [f for f in api if "{id}" in f["evidence"]["metadata"]["path"]]
    assert bola
    assert any("BOLA" in r for r in bola[0]["risk_indicators"])


def test_e2e_secret_value_never_leaks_in_any_reporter() -> None:
    """The privacy guarantee, checked across every output format."""
    report = _scan()
    json_out = render_json(report)
    md_out = render_markdown(report)
    from rich.console import Console

    console = Console(record=True, width=120)
    render_terminal(report, console)
    term_out = console.export_text()

    for name, out in [("json", json_out), ("markdown", md_out), ("terminal", term_out)]:
        assert PLANTED_SECRET_FRAGMENT not in out, f"secret value leaked into {name} output"
    # The secret NAME is still surfaced (so the finding is actionable).
    assert "STRIPE_SECRET_KEY" in json_out
