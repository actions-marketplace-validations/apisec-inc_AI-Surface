"""Regression tests for markdown-injection defences.

The scanner ingests attacker-controlled source code and renders parts of it
into a GitHub PR comment. A pre-fix renderer wrapped snippets in three-tick
fences with no escaping — a single source line containing ``` would break
out of the fence and let downstream content render as raw markdown / HTML.
Surface names, file paths, permissions, and risk indicators also flowed
unsanitised into headings and bullets.

These tests pin the fix.
"""
from __future__ import annotations

from ai_surface.reporters.markdown_reporter import render_markdown
from ai_surface.types import (
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_LLM_SDK,
    Evidence,
    Finding,
    Report,
)
from ai_surface.utils.markdown_safety import safe_fence, sanitise_inline


def test_sanitise_inline_strips_control_chars_and_structural_markers() -> None:
    assert sanitise_inline("\x1b[31mred\x1b[0m") == "[31mred[0m"
    assert sanitise_inline("# fake heading") == "fake heading"
    assert sanitise_inline("- inject\n- list") == "inject - list"
    assert sanitise_inline("<img src=x onerror=alert(1)>") == "img src=x onerror=alert(1)"
    assert sanitise_inline("`code`") == "'code'"
    assert sanitise_inline("a" * 300, max_len=50).endswith("…")


def test_safe_fence_outgrows_internal_backticks() -> None:
    fence, body = safe_fence("hello")
    assert fence == "```"
    assert body == "hello"

    # Three internal backticks need at least four-tick fence.
    fence, body = safe_fence("look at this: ```\nfake close\nstill inside")
    assert len(fence) >= 4
    assert "```" in body  # body preserved; fence is what defeats break-out.


def test_render_markdown_resists_fence_break_out() -> None:
    evil_snippet = (
        "x = 1\n"
        "```\n"
        "# 🚨 Approved by Security\n"
        "[malicious link](https://attacker.example)\n"
    )
    finding = Finding(
        surface="LLM SDK Call Sites",
        category=CATEGORY_LLM_SDK,
        evidence=Evidence(files=["evil.py"], snippet=evil_snippet, metadata={}),
        permissions=[],
        risk_indicators=["non-literal data flows into LLM call"],
    )
    report = Report(
        schema_version="0.5",
        tool_version="test",
        scan_root="/tmp/x",
        scan_timestamp="2026-01-01T00:00:00Z",
        detectors_run=["llm_sdks"],
        findings=[finding],
        errors=[],
    )
    md = render_markdown(report)

    # The malicious "approved" heading must NOT render as a heading at the
    # document level. The OUTER fences (longest backtick runs on their own
    # lines) must be longer than the longest internal run.
    fence_lines = [
        line
        for line in md.split("\n")
        if line and set(line) == {"`"}
    ]
    assert fence_lines, "expected at least one fence line"
    max_run = max(len(f) for f in fence_lines)
    inner_runs = [len(f) for f in fence_lines if len(f) < max_run]
    # The opener and closer use the longest fence; any shorter runs are
    # internal content that must NOT terminate the outer block.
    assert max_run >= 4, f"expected 4+ backtick outer fence; got {fence_lines!r}"
    assert all(r < max_run for r in inner_runs), (
        "internal fences must be strictly shorter than outer fences"
    )


def test_render_markdown_sanitises_surface_and_risks() -> None:
    finding = Finding(
        surface="<script>alert(1)</script>",
        category=CATEGORY_AGENT_FRAMEWORK,
        evidence=Evidence(files=["a.py"], snippet="", metadata={}),
        permissions=["`evil`"],
        risk_indicators=["# pretend heading"],
    )
    report = Report(
        schema_version="0.5",
        tool_version="test",
        scan_root="/tmp/x",
        scan_timestamp="2026-01-01T00:00:00Z",
        detectors_run=["agent_frameworks"],
        findings=[finding],
        errors=[],
    )
    md = render_markdown(report)
    assert "<script>" not in md
    assert "</script>" not in md
    # Backticks inside permissions become single quotes so the inline-code
    # span we render around the permission never gets broken out of.
    assert "`'evil'`" in md
    # A risk indicator starting with `#` must not render as a heading bullet.
    assert "- ⚠️ pretend heading" in md
