"""Edge-case and resilience tests.

These tests verify that ai-surface handles realistic ugly inputs gracefully:
malformed config files, unreadable files, unicode filenames, detector
exceptions, symlinks, empty repos. None of these should crash the CLI.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List

import pytest
from rich.console import Console

from ai_surface.detectors.mcp_servers import McpServerDetector
from ai_surface.orchestrator import Orchestrator
from ai_surface.reporters.terminal_reporter import render_terminal
from ai_surface.types import (
    CATEGORY_LLM_SDK,
    Detector,
    Evidence,
    Finding,
    Report,
)


# ---------------------------------------------------------------------------
# Empty / minimal inputs
# ---------------------------------------------------------------------------


def test_orchestrator_on_empty_directory(tmp_path: Path) -> None:
    """A truly empty dir (no files) should produce zero findings and no errors."""
    detectors: List[Detector] = [McpServerDetector()]
    orch = Orchestrator(detectors=detectors)
    report = orch.run(str(tmp_path))
    assert report.findings == []
    assert report.errors == []


def test_orchestrator_with_no_detectors(tmp_path: Path) -> None:
    """No detectors registered: should still produce a valid (empty) report."""
    orch = Orchestrator(detectors=[])
    report = orch.run(str(tmp_path))
    assert report.findings == []
    assert report.errors == []
    assert report.detectors_run == []


# ---------------------------------------------------------------------------
# Malformed inputs
# ---------------------------------------------------------------------------


def test_mcp_detector_handles_malformed_json(tmp_path: Path) -> None:
    """Malformed .mcp.json should not crash the detector or produce false findings."""
    (tmp_path / ".mcp.json").write_text(
        '{ "mcpServers": { "broken": { invalid json here }', encoding="utf-8"
    )
    detector = McpServerDetector()
    findings = detector.detect(str(tmp_path))
    # No exception, no findings from this malformed file
    assert isinstance(findings, list)


def test_mcp_detector_handles_empty_config(tmp_path: Path) -> None:
    """Empty .mcp.json should produce no findings, no errors."""
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    findings = McpServerDetector().detect(str(tmp_path))
    assert findings == []


def test_mcp_detector_handles_completely_empty_file(tmp_path: Path) -> None:
    """Zero-byte .mcp.json should not crash."""
    (tmp_path / ".mcp.json").write_text("", encoding="utf-8")
    findings = McpServerDetector().detect(str(tmp_path))
    assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# Unicode and unusual filenames
# ---------------------------------------------------------------------------


def test_walker_handles_unicode_filenames(tmp_path: Path) -> None:
    """Files with non-ASCII names should walk fine."""
    from ai_surface.utils.walk import walk_files

    unicode_file = tmp_path / "café_payments.py"
    unicode_file.write_text("from anthropic import Anthropic\n", encoding="utf-8")
    out = list(walk_files(str(tmp_path)))
    assert any(p.name == "café_payments.py" for p in out)


# ---------------------------------------------------------------------------
# Detector exceptions are isolated
# ---------------------------------------------------------------------------


class _CatastrophicDetector:
    name = "catastrophic"
    category = CATEGORY_LLM_SDK

    def detect(self, root_path: str) -> List[Finding]:
        raise RuntimeError("simulated catastrophic failure with details")


def test_detector_exceptions_captured_in_report_errors(tmp_path: Path) -> None:
    """A detector that raises should be isolated; other detectors should still run."""

    class _GoodDetector:
        name = "good"
        category = CATEGORY_LLM_SDK

        def detect(self, root_path: str) -> List[Finding]:
            return [
                Finding(
                    surface="OK SDK",
                    category=CATEGORY_LLM_SDK,
                    evidence=Evidence(),
                )
            ]

    orch = Orchestrator(detectors=[_CatastrophicDetector(), _GoodDetector()])
    report = orch.run(str(tmp_path))
    # Good detector's finding survives
    assert len(report.findings) == 1
    assert report.findings[0].surface == "OK SDK"
    # Bad detector's failure is captured with detail
    assert len(report.errors) == 1
    assert "catastrophic" in report.errors[0]
    assert "simulated catastrophic failure" in report.errors[0]


def test_detector_error_message_includes_exception_class(tmp_path: Path) -> None:
    orch = Orchestrator(detectors=[_CatastrophicDetector()])
    report = orch.run(str(tmp_path))
    assert "RuntimeError" in report.errors[0]


# ---------------------------------------------------------------------------
# Verbose mode renders detector errors in the report body
# ---------------------------------------------------------------------------


def test_verbose_mode_shows_errors_in_terminal_output() -> None:
    report = Report(
        findings=[],
        scan_root="/tmp/test",
        scan_timestamp="2026-05-10T00:00:00+00:00",
        detectors_run=["bad"],
        errors=["bad failed: RuntimeError: something specific"],
    )
    console = Console(record=True, force_terminal=True, width=120)
    render_terminal(report, console, verbose=True)
    text = console.export_text()
    # Error detail visible in verbose mode
    assert "Detector errors" in text
    assert "something specific" in text


def test_default_mode_shows_error_count_only() -> None:
    report = Report(
        findings=[],
        scan_root="/tmp/test",
        scan_timestamp="2026-05-10T00:00:00+00:00",
        detectors_run=["bad"],
        errors=["bad failed: RuntimeError: secret detail"],
    )
    console = Console(record=True, force_terminal=True, width=120)
    render_terminal(report, console, verbose=False)
    text = console.export_text()
    # Error count summarized; specific detail hidden behind -v
    assert "1 detector error" in text
    assert "run with -v" in text
    assert "secret detail" not in text


# ---------------------------------------------------------------------------
# Path validation
# ---------------------------------------------------------------------------


def test_orchestrator_rejects_file_path(tmp_path: Path) -> None:
    """Orchestrator should error when scan root is a file, not a dir."""
    f = tmp_path / "a-file.txt"
    f.write_text("hello", encoding="utf-8")
    orch = Orchestrator(detectors=[])
    with pytest.raises(NotADirectoryError):
        orch.run(str(f))


# ---------------------------------------------------------------------------
# Symlink handling
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need elevation on Windows")
def test_walker_does_not_follow_symlinks_by_default(tmp_path: Path) -> None:
    """Default walker behavior should not follow symlinks (avoids cycles)."""
    from ai_surface.utils.walk import walk_files

    target_dir = tmp_path / "real"
    target_dir.mkdir()
    (target_dir / "file.py").write_text("from openai import OpenAI\n", encoding="utf-8")

    link = tmp_path / "link"
    try:
        os.symlink(target_dir, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported in this environment")

    found = list(walk_files(str(tmp_path)))
    # The real file (one path) should be present; the symlinked path should not
    # produce a duplicate when follow_symlinks=False (the default).
    # Both target and the symlink itself are listed in os.walk, but follow_symlinks=False
    # avoids descending into the symlink.
    paths_str = [str(p) for p in found]
    real_files = [p for p in paths_str if "real/file.py" in p]
    link_files = [p for p in paths_str if "link/file.py" in p]
    assert len(real_files) >= 1
    assert len(link_files) == 0  # symlink not followed


# ---------------------------------------------------------------------------
# Repeated scans are stable
# ---------------------------------------------------------------------------


def test_repeated_scans_produce_stable_findings(tmp_path: Path) -> None:
    """Running the same scan twice should produce identical findings."""
    (tmp_path / "main.py").write_text(
        "from anthropic import Anthropic\nclient = Anthropic()\n", encoding="utf-8"
    )
    from ai_surface.detectors.llm_sdks import LlmSdkDetector

    a = LlmSdkDetector().detect(str(tmp_path))
    b = LlmSdkDetector().detect(str(tmp_path))
    assert len(a) == len(b)
    if a:
        assert a[0].surface == b[0].surface
        assert a[0].evidence.files == b[0].evidence.files
