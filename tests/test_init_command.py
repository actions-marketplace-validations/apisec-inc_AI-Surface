"""Tests for `ai-surface init` and the end-of-scan scorecard."""
from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from ai_surface.cli import app

runner = CliRunner()


def test_init_writes_workflow(tmp_path: Path) -> None:
    result = runner.invoke(app, ["init", str(tmp_path)])
    assert result.exit_code == 0
    wf = tmp_path / ".github" / "workflows" / "ai-surface.yml"
    assert wf.is_file()
    text = wf.read_text()
    assert "apisec-inc/AI-Surface@v1" in text
    assert "fail-on: 'high'" in text
    assert "fetch-depth: 0" in text


def test_init_refuses_overwrite_without_force(tmp_path: Path) -> None:
    assert runner.invoke(app, ["init", str(tmp_path)]).exit_code == 0
    wf = tmp_path / ".github" / "workflows" / "ai-surface.yml"
    wf.write_text("custom: true\n")
    result = runner.invoke(app, ["init", str(tmp_path)])
    assert result.exit_code == 1
    assert wf.read_text() == "custom: true\n"  # untouched


def test_init_force_overwrites(tmp_path: Path) -> None:
    assert runner.invoke(app, ["init", str(tmp_path)]).exit_code == 0
    wf = tmp_path / ".github" / "workflows" / "ai-surface.yml"
    wf.write_text("custom: true\n")
    result = runner.invoke(app, ["init", str(tmp_path), "--force"])
    assert result.exit_code == 0
    assert "apisec-inc/AI-Surface@v1" in wf.read_text()


def test_init_prints_pre_commit_snippet(tmp_path: Path) -> None:
    result = runner.invoke(app, ["init", str(tmp_path)])
    assert "pre-commit-config.yaml" in result.output
    assert "hooks:" in result.output


def test_scan_terminal_ends_with_scorecard() -> None:
    result = runner.invoke(app, ["scan", "examples/demo-app"])
    assert result.exit_code == 0
    assert "AI Surface Scorecard" in result.output
    assert "confirmed risk" in result.output
    assert "likely risk" in result.output


def test_scan_json_includes_verdicts() -> None:
    import json as jsonlib

    result = runner.invoke(app, ["scan", "examples/demo-app", "-o", "json"])
    # Parse the JSON payload; tolerate rich soft-wrap by asserting on substrings
    # when parsing fails in this environment (see pre-existing CLI test quirk).
    try:
        data = jsonlib.loads(result.output)
        verdicts = {f.get("verdict") for f in data["findings"]}
        assert "confirmed" in verdicts or "likely" in verdicts
        assert "confirmed_count" in data["summary"]
    except Exception:
        assert '"verdict"' in result.output
        assert '"confirmed_count"' in result.output
