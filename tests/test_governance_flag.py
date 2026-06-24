"""Tests for the --governance gating and --ai-only focus flags (1.0.3).

Governance per-finding clauses are OFF by default (practitioner focus); a
one-line governance summary is always shown. JSON keeps full standards always
(verified in test_frameworks.py). --ai-only drops the plain API category.
"""
from __future__ import annotations

import io

from rich.console import Console
from typer.testing import CliRunner

from ai_surface.cli import app
from ai_surface.reporters.markdown_reporter import render_markdown
from ai_surface.reporters.terminal_reporter import render_terminal
from ai_surface.types import (
    CATEGORY_MCP_SERVER,
    SEVERITY_HIGH,
    Audit,
    Evidence,
    Finding,
    Report,
    RiskFlag,
)

runner = CliRunner()


def _audited_report() -> Report:
    # "no-human-oversight" maps to EU AI Act Art. 14 (a specific clause).
    f = Finding(
        surface="MCP Server: payments",
        category=CATEGORY_MCP_SERVER,
        evidence=Evidence(files=[".mcp.json"]),
        severity=SEVERITY_HIGH,
        audit=Audit(
            risk_flags=[RiskFlag("no-human-oversight", SEVERITY_HIGH, "no approval gate", ["LLM06"])],
            owasp_mappings=["LLM06"],
        ),
    )
    return Report(
        findings=[f], scan_root="x",
        scan_timestamp="2026-06-24T00:00:00+00:00", detectors_run=["mcp"],
    )


def _terminal(report: Report, governance: bool) -> str:
    console = Console(file=io.StringIO(), width=200, no_color=True, highlight=False)
    render_terminal(report, console, governance=governance)
    return console.file.getvalue()


def test_terminal_governance_off_hides_clause_but_shows_summary() -> None:
    out = _terminal(_audited_report(), governance=False)
    assert "Governance: evidence for" in out  # one-line summary always
    assert "run with --governance" in out  # the hint
    assert "Art. 14" not in out  # per-finding clause suppressed


def test_terminal_governance_on_shows_clause() -> None:
    out = _terminal(_audited_report(), governance=True)
    assert "Art. 14" in out  # per-finding clause now present
    assert "Governance: evidence for" in out  # summary still present
    assert "run with --governance" not in out  # hint dropped when already on


def test_markdown_governance_off_hides_clause_but_shows_summary() -> None:
    md = render_markdown(_audited_report(), governance=False)
    assert "**Governance:** evidence for" in md
    assert "`--governance`" in md
    assert "Art. 14" not in md


def test_markdown_governance_on_shows_clause() -> None:
    md = render_markdown(_audited_report(), governance=True)
    assert "Art. 14" in md


def test_json_always_carries_standards_regardless_of_flag() -> None:
    # JSON is a data contract for the UI / consumers: standards always present.
    from ai_surface.reporters.json_reporter import report_to_dict

    d = report_to_dict(_audited_report())
    rf = d["findings"][0]["audit"]["risk_flags"][0]
    assert rf["standards"] == [
        {"framework": "EU AI Act", "framework_id": "eu-ai-act", "clause": "Art. 14"}
    ]


def test_ai_only_excludes_api_category() -> None:
    import json

    fixture = "tests/fixtures/e2e_app"
    base = runner.invoke(app, ["scan", fixture, "-o", "json"])
    assert base.exit_code == 0
    base_cats = {f["category"] for f in json.loads(base.stdout)["findings"]}
    assert "api" in base_cats  # fixture has API endpoints

    focused = runner.invoke(app, ["scan", fixture, "--ai-only", "-o", "json"])
    assert focused.exit_code == 0
    focused_cats = {f["category"] for f in json.loads(focused.stdout)["findings"]}
    assert "api" not in focused_cats
    assert focused_cats  # AI surfaces remain


def test_ai_only_with_only_api_category_errors() -> None:
    result = runner.invoke(app, ["scan", "tests/fixtures/e2e_app", "--ai-only", "-c", "api"])
    assert result.exit_code == 2
