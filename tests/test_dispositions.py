"""Tests for the disposition model (resolve-here vs validate-runtime)."""
from __future__ import annotations

from ai_surface.cross_promo import build_bridges
from ai_surface.dispositions import attach_dispositions, disposition_for
from ai_surface.types import (
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_API,
    CATEGORY_ENV_KEY,
    CATEGORY_LLM_SDK,
    CATEGORY_MCP_SERVER,
    CATEGORY_MODEL_GATEWAY,
    DISPOSITION_RESOLVE,
    DISPOSITION_VALIDATE,
    Evidence,
    Finding,
)


def _f(cat):
    return Finding(surface=f"x-{cat}", category=cat, evidence=Evidence())


def test_validatable_categories_are_validate_runtime() -> None:
    for cat in (CATEGORY_API, CATEGORY_MCP_SERVER, CATEGORY_AGENT_FRAMEWORK):
        disp, status, q = disposition_for(_f(cat))
        assert disp == DISPOSITION_VALIDATE
        assert status in ("live", "coming")
        assert q  # carries the runtime question


def test_posture_categories_are_resolve_here() -> None:
    for cat in (CATEGORY_LLM_SDK, CATEGORY_MODEL_GATEWAY, CATEGORY_ENV_KEY):
        disp, status, q = disposition_for(_f(cat))
        assert disp == DISPOSITION_RESOLVE
        assert status == "n/a"
        assert q is None


def test_api_is_live_mcp_and_agent_are_coming() -> None:
    assert disposition_for(_f(CATEGORY_API))[1] == "live"
    assert disposition_for(_f(CATEGORY_MCP_SERVER))[1] == "coming"
    assert disposition_for(_f(CATEGORY_AGENT_FRAMEWORK))[1] == "coming"


def test_only_validate_runtime_categories_bridge() -> None:
    # resolve-here posture categories get no bridge at all.
    assert build_bridges(_f(CATEGORY_LLM_SDK)) == []
    assert build_bridges(_f(CATEGORY_MODEL_GATEWAY)) == []
    assert build_bridges(_f(CATEGORY_ENV_KEY)) == []
    # validate-runtime categories bridge, with honest status.
    api_b = build_bridges(_f(CATEGORY_API))[0]
    assert api_b.status == "live"
    mcp_b = build_bridges(_f(CATEGORY_MCP_SERVER))[0]
    assert mcp_b.status == "coming"
    assert "coming soon" in mcp_b.label.lower()


def test_attach_dispositions_is_idempotent() -> None:
    fs = [_f(CATEGORY_API), _f(CATEGORY_LLM_SDK)]
    attach_dispositions(fs)
    assert fs[0].disposition == DISPOSITION_VALIDATE
    assert fs[1].disposition == DISPOSITION_RESOLVE
    fs[0].disposition = "manual-override"
    attach_dispositions(fs)  # must not overwrite an already-set disposition
    assert fs[0].disposition == "manual-override"
