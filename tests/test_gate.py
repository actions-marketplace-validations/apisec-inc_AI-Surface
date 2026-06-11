"""Tests for the severity-threshold gate (--fail-on), the painkiller gate."""
from __future__ import annotations

from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from ai_surface.cli import (
    _findings_at_or_above,
    _maybe_fail_on_diff_severity,
    app,
)
from ai_surface.diff import Diff
from ai_surface.types import (
    CATEGORY_API,
    CATEGORY_MCP_SERVER,
    SEVERITY_CRITICAL,
    SEVERITY_LOW,
    Evidence,
    Finding,
)

runner = CliRunner()
E2E = str(Path(__file__).parent / "fixtures" / "e2e_app")  # has a critical MCP
API_ONLY = str(Path(__file__).parent / "fixtures" / "api_endpoints")  # no severity


def _f(sev):
    return Finding(surface=f"MCP Server: x-{sev}", category=CATEGORY_MCP_SERVER,
                   evidence=Evidence(files=[".mcp.json"]), severity=sev)


# ---- unit: severity filter (the low-noise core) ----

def test_filter_ignores_severity_free_inventory() -> None:
    inventory = Finding(surface="api", category=CATEGORY_API, evidence=Evidence())
    assert _findings_at_or_above([inventory], "low") == []


def test_filter_respects_threshold() -> None:
    findings = [_f(SEVERITY_CRITICAL), _f(SEVERITY_LOW)]
    assert len(_findings_at_or_above(findings, "high")) == 1  # only critical
    assert len(_findings_at_or_above(findings, "low")) == 2   # both


# ---- unit: baseline gate fires only on NEW ----

def test_diff_gate_fires_on_new_critical() -> None:
    diff = Diff(added=[_f(SEVERITY_CRITICAL)])
    with pytest.raises(typer.Exit) as exc:
        _maybe_fail_on_diff_severity(diff, "high")
    assert exc.value.exit_code == 1


def test_diff_gate_ignores_new_below_threshold() -> None:
    diff = Diff(added=[_f(SEVERITY_LOW)])
    _maybe_fail_on_diff_severity(diff, "high")  # must not raise


# ---- integration: the CLI ----

def test_fail_on_high_trips_on_critical_mcp() -> None:
    result = runner.invoke(app, ["scan", E2E, "--fail-on", "high", "--quiet"])
    assert result.exit_code == 1
    assert "fail-on high" in result.output
    assert "stripe-mcp" in result.output  # actionable: names the offender


def test_fail_on_high_passes_when_only_inventory() -> None:
    # API-only fixture has findings but no assessed severity.
    result = runner.invoke(app, ["scan", API_ONLY, "--fail-on", "high", "--quiet"])
    assert result.exit_code == 0


def test_invalid_fail_on_is_usage_error() -> None:
    result = runner.invoke(app, ["scan", E2E, "--fail-on", "bogus"])
    assert result.exit_code == 2
    assert "must be one of" in result.output


def test_baseline_does_not_block_preexisting_risk(tmp_path) -> None:
    # Snapshot the e2e app (captures the critical MCP as accepted state)...
    import shutil
    work = tmp_path / "app"
    shutil.copytree(E2E, work)
    snap = runner.invoke(app, ["scan", str(work), "--update-baseline"])
    assert snap.exit_code == 0
    # ...then a baseline scan with a strict gate must NOT block: nothing is new.
    result = runner.invoke(app, ["scan", str(work), "--baseline", "--fail-on", "critical", "--quiet"])
    assert result.exit_code == 0
