"""Tests for CLI helpers and the typer entrypoint."""
from __future__ import annotations

import pytest
import typer
from typer.testing import CliRunner

from ai_surface.cli import (
    CATEGORY_ALIASES,
    _filter_detectors_by_category,
    _resolve_categories,
    app,
)
from ai_surface.types import (
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_LLM_SDK,
    CATEGORY_MCP_SERVER,
    CATEGORY_MODEL_GATEWAY,
)

# ---------------------------------------------------------------------------
# _resolve_categories
# ---------------------------------------------------------------------------


def test_resolve_categories_none_returns_none() -> None:
    assert _resolve_categories(None) is None
    assert _resolve_categories("") is None


def test_resolve_categories_canonical() -> None:
    assert _resolve_categories("mcp-server") == {CATEGORY_MCP_SERVER}
    assert _resolve_categories("agent-framework,llm-sdk") == {
        CATEGORY_AGENT_FRAMEWORK,
        CATEGORY_LLM_SDK,
    }


def test_resolve_categories_aliases() -> None:
    assert _resolve_categories("mcp") == {CATEGORY_MCP_SERVER}
    assert _resolve_categories("agents") == {CATEGORY_AGENT_FRAMEWORK}
    assert _resolve_categories("llm,gateway") == {
        CATEGORY_LLM_SDK,
        CATEGORY_MODEL_GATEWAY,
    }


def test_resolve_categories_case_insensitive() -> None:
    assert _resolve_categories("MCP") == {CATEGORY_MCP_SERVER}
    assert _resolve_categories("Agents") == {CATEGORY_AGENT_FRAMEWORK}


def test_resolve_categories_strips_whitespace() -> None:
    assert _resolve_categories(" mcp , agents ") == {
        CATEGORY_MCP_SERVER,
        CATEGORY_AGENT_FRAMEWORK,
    }


def test_resolve_categories_invalid_raises_exit() -> None:
    with pytest.raises(typer.Exit):
        _resolve_categories("totally-not-a-category")


def test_resolve_categories_aliases_table_complete() -> None:
    """Every alias must point at a real ALL_CATEGORIES value."""
    from ai_surface.types import ALL_CATEGORIES

    for alias, canonical in CATEGORY_ALIASES.items():
        assert canonical in ALL_CATEGORIES, (
            f"alias {alias!r} maps to non-canonical {canonical!r}"
        )


# ---------------------------------------------------------------------------
# _filter_detectors_by_category
# ---------------------------------------------------------------------------


class _StubDetector:
    def __init__(self, name: str, category: str) -> None:
        self.name = name
        self.category = category


def test_filter_detectors_none_returns_all() -> None:
    detectors: list[_StubDetector] = [
        _StubDetector("a", CATEGORY_MCP_SERVER),
        _StubDetector("b", CATEGORY_LLM_SDK),
    ]
    out = _filter_detectors_by_category(detectors, None)
    assert len(out) == 2


def test_filter_detectors_keeps_matching_only() -> None:
    detectors: list[_StubDetector] = [
        _StubDetector("a", CATEGORY_MCP_SERVER),
        _StubDetector("b", CATEGORY_LLM_SDK),
        _StubDetector("c", CATEGORY_AGENT_FRAMEWORK),
    ]
    out = _filter_detectors_by_category(detectors, {CATEGORY_MCP_SERVER, CATEGORY_LLM_SDK})
    names = sorted(d.name for d in out)
    assert names == ["a", "b"]


def test_filter_detectors_empty_when_no_match() -> None:
    detectors: list[_StubDetector] = [_StubDetector("a", CATEGORY_MCP_SERVER)]
    out = _filter_detectors_by_category(detectors, {CATEGORY_LLM_SDK})
    assert out == []


# ---------------------------------------------------------------------------
# CLI integration: typer Test Runner
# ---------------------------------------------------------------------------

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "ai-surface" in result.stdout


def test_scan_quiet_outputs_one_line(tmp_path) -> None:
    # Empty dir, all detectors will run, none will find anything
    result = runner.invoke(app, ["scan", str(tmp_path), "--quiet"])
    assert result.exit_code == 0
    assert "ai-surface:" in result.stdout
    assert "0 surfaces" in result.stdout


def test_scan_invalid_category_exits_with_error(tmp_path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path), "--categories", "bogus-cat"])
    assert result.exit_code == 2
    # CliRunner merges stderr into output by default
    assert "unknown category" in result.output.lower()


def test_scan_categories_aliases_accepted(tmp_path) -> None:
    """Should not error: 'mcp' and 'agents' are valid aliases."""
    result = runner.invoke(app, ["scan", str(tmp_path), "--categories", "mcp,agents", "--quiet"])
    assert result.exit_code == 0


def test_scan_nonexistent_path_exits_with_error() -> None:
    result = runner.invoke(app, ["scan", "/path/that/does/not/exist"])
    assert result.exit_code == 2
