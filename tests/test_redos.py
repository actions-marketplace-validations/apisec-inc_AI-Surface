"""Regression tests for ReDoS / quadratic-scan vectors.

A previous version of the agent-framework detector used DOTALL regexes with
a lazy ``[^)]*?`` body matcher to extract the ``role=`` / ``name=`` kwargs
from crewai/autogen ``Agent(...)`` constructors. Adversarial input with many
unmatched ``Agent(`` openers triggered catastrophic backtracking and the
quadratic-scan helper ``_match_bracket`` was called once per opener with no
budget, compounding the issue.

These tests pin the fix:

* The dangerous regexes have been narrowed to anchor-only and the body is
  pulled from the bracket-bounded constructor text.
* ``_match_bracket`` has a per-call scan cap.
* ``_extract_agent_defs`` has a per-file bracket-attempt budget and advances
  past already-scanned regions so subsequent matches inside the failed
  window are skipped.

The test fails (timeout / very slow) if any of those guards regress.
"""
from __future__ import annotations

import time
from pathlib import Path

from ai_surface.detectors.agent_frameworks import AgentFrameworkDetector


def test_agent_framework_detector_resists_redos(tmp_path: Path) -> None:
    """A 5MB file full of unmatched ``Agent(`` tokens must scan quickly."""
    payload = "from crewai import Agent\n" + ("Agent(\n" * 700_000)
    f = tmp_path / "evil.py"
    f.write_text(payload)

    start = time.perf_counter()
    findings = AgentFrameworkDetector().detect(str(tmp_path))
    elapsed = time.perf_counter() - start

    # Generous budget: we observe ~2.3s locally; a regressed quadratic scan
    # blows well past 10s before finishing. 8s leaves headroom for slower CI.
    assert elapsed < 8.0, (
        f"agent-framework detector took {elapsed:.1f}s on adversarial input "
        f"({len(payload):,} bytes). A previous regression made this quadratic."
    )
    # We don't care what the inventory looks like for hostile input — only
    # that the scan completes in bounded time.
    assert isinstance(findings, list)
