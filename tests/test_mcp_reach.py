"""Tests for MCP reach detection (APIs/models an MCP reaches), masked."""
from __future__ import annotations

from ai_surface.detectors.mcp_audit import _detect_reach


def test_detects_apis_masked_and_models() -> None:
    cfg = {"command": "npx", "args": ["pg-mcp"],
           "env": {"DATABASE_URL": "postgresql://user:secretpw@db.internal:5432/app",
                   "LLM_MODEL": "gpt-4o"}}
    reaches, models = _detect_reach(cfg, cfg["args"], cfg["env"], "pg-mcp")
    cats = {r["category"] for r in reaches}
    assert "database" in cats
    joined = " ".join(r["url"] for r in reaches)
    assert "secretpw" not in joined  # credentials masked, never surfaced
    assert "gpt-4o" in models


def test_no_apis_no_models_is_empty() -> None:
    reaches, models = _detect_reach({"command": "npx", "args": ["x"], "env": {}}, ["x"], {}, "x")
    assert reaches == []
    assert models == []
