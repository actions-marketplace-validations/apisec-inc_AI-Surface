"""Tests for the orchestrator."""
from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from ai_surface.orchestrator import Orchestrator
from ai_surface.types import (
    CATEGORY_LLM_SDK,
    Detector,
    Evidence,
    Finding,
    Report,
)


class StubDetector:
    """A trivial detector for orchestrator tests."""

    name = "stub"
    category = CATEGORY_LLM_SDK

    def __init__(self, findings: List[Finding]) -> None:
        self._findings = findings

    def detect(self, root_path: str) -> List[Finding]:
        return list(self._findings)


class FailingDetector:
    name = "boom"
    category = CATEGORY_LLM_SDK

    def detect(self, root_path: str) -> List[Finding]:
        raise RuntimeError("simulated failure")


def _finding(surface: str = "Test SDK") -> Finding:
    return Finding(
        surface=surface,
        category=CATEGORY_LLM_SDK,
        evidence=Evidence(files=["src/foo.py"], snippet="from openai import OpenAI"),
    )


def test_orchestrator_aggregates_findings(tmp_path: Path) -> None:
    a = StubDetector([_finding("A"), _finding("B")])
    b = StubDetector([_finding("C")])
    orch = Orchestrator(detectors=[a, b])
    report = orch.run(str(tmp_path))
    assert len(report.findings) == 3
    surfaces = {f.surface for f in report.findings}
    assert surfaces == {"A", "B", "C"}


def test_orchestrator_stamps_detector_name(tmp_path: Path) -> None:
    a = StubDetector([_finding("X")])
    orch = Orchestrator(detectors=[a])
    report = orch.run(str(tmp_path))
    assert report.findings[0].detector_name == "stub"


def test_orchestrator_isolates_detector_failures(tmp_path: Path) -> None:
    good = StubDetector([_finding("A")])
    bad = FailingDetector()
    orch = Orchestrator(detectors=[good, bad])
    report = orch.run(str(tmp_path))
    assert len(report.findings) == 1
    assert any("boom" in e for e in report.errors)


def test_orchestrator_rejects_nonexistent_root() -> None:
    orch = Orchestrator()
    with pytest.raises(FileNotFoundError):
        orch.run("/nonexistent/path/does/not/exist")


def test_report_groups_by_category(tmp_path: Path) -> None:
    findings = [
        _finding("A"),
        _finding("B"),
    ]
    report = Report(
        findings=findings,
        scan_root=str(tmp_path),
        scan_timestamp=Report.now(),
        detectors_run=["stub"],
    )
    grouped = report.by_category()
    assert CATEGORY_LLM_SDK in grouped
    assert len(grouped[CATEGORY_LLM_SDK]) == 2
