"""JSON reporter: machine-readable output for automation and CI integrations.

The schema is versioned. Bumps must be backward-compatible within a major or
explicitly noted as breaking. The GitHub Action wrapper consumes this output
to compute PR diffs.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from ..types import Report


def render_json(report: Report, indent: int = 2) -> str:
    """Render `report` as a JSON string. Returns valid JSON suitable for piping."""
    return json.dumps(report_to_dict(report), indent=indent, ensure_ascii=False)


def report_to_dict(report: Report) -> dict[str, Any]:
    """Convert Report to a plain dict (JSON-friendly)."""
    return {
        "schema_version": report.schema_version,
        "tool_version": report.tool_version,
        "scan_root": report.scan_root,
        "scan_timestamp": report.scan_timestamp,
        "detectors_run": list(report.detectors_run),
        "findings_count": len(report.findings),
        "findings": [_finding_to_dict(f) for f in report.findings],
        "errors": list(report.errors),
    }


def _finding_to_dict(finding: Any) -> dict[str, Any]:
    """asdict-compatible conversion that flattens Evidence nicely."""
    d = asdict(finding)
    # asdict already flattens dataclasses to dicts. Just clean up if needed.
    return d
