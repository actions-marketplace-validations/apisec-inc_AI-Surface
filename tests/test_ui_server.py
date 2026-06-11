"""Tests for the --ui viewer prep (no server is started)."""
from __future__ import annotations

import json

from ai_surface.types import (
    CATEGORY_MCP_SERVER,
    Evidence,
    Finding,
    Report,
)
from ai_surface.ui_server import prepare_ui_dir, ui_asset_dir


def _report() -> Report:
    r = Report(
        findings=[
            Finding(
                surface="MCP Server: demo",
                category=CATEGORY_MCP_SERVER,
                evidence=Evidence(files=[".mcp.json"]),
            )
        ],
        scan_root="demo",
        scan_timestamp="2026-06-11T00:00:00+00:00",
        detectors_run=["mcp_audit"],
    )
    r.summary = r.build_summary()
    return r


def test_ui_assets_are_discoverable() -> None:
    assets = ui_asset_dir()
    assert assets is not None, "ui/ assets should ship with the package"
    assert (assets / "index.html").is_file()


def test_prepare_ui_dir_writes_assets_and_report(tmp_path) -> None:
    dest = prepare_ui_dir(_report(), dest=tmp_path / "serve")
    # Static assets copied.
    assert (dest / "index.html").is_file()
    # report.json present and valid schema-1.0.
    data = json.loads((dest / "report.json").read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0"
    assert data["findings_count"] == 1
    assert "summary" in data
