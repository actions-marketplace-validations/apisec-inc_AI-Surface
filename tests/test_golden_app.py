"""End-to-end regression guard on a compact multi-language 'golden app'.

This locks the full pipeline (all detectors + enrichment passes) against a
realistic mini-app (a slice of the Lumora demo). If a detector or pass regresses,
the known-answer findings here break. Mirrors what ai-surface must always catch.
"""
from __future__ import annotations

from pathlib import Path

from ai_surface.orchestrator import Orchestrator, default_detectors

GOLDEN = Path(__file__).parent / "fixtures" / "golden_app"


def _report():
    return Orchestrator(default_detectors()).run(str(GOLDEN))


def _flags(findings):
    out = {}
    for f in findings:
        if f.audit:
            out[f.surface] = {rf.flag for rf in f.audit.risk_flags}
    return out


def test_golden_app_known_answers() -> None:
    report = _report()
    by_cat = report.by_category()

    # categories present
    assert "agent-framework" in by_cat
    assert "mcp-server" in by_cat
    assert "api" in by_cat
    assert "vector-store" in by_cat

    # vector / RAG layer: a store + a RAG pipeline, with the data-flow indicator
    vec = {f.surface for f in by_cat["vector-store"]}
    assert any("Vector store" in s for s in vec)
    assert any("RAG pipeline" in s for s in vec)
    assert any(
        "retrieval-augmented generation" in r
        for f in by_cat["vector-store"] for r in f.risk_indicators
    )

    flags = _flags(report.findings)
    allflags = set().union(*flags.values()) if flags else set()

    # Python LangChain agent: financial + messaging + oversight + pii
    py_agent = [s for s in flags if "LangChain Agent" in s]
    assert py_agent, "expected a LangChain agent finding"
    pf = flags[py_agent[0]]
    assert "financial-action" in pf
    assert "no-human-oversight" in pf
    assert "pii-to-llm" in pf

    # TS Vercel agent: financial-action (cross-language)
    ts_agent = [s for s in flags if "Vercel AI SDK Agent" in s]
    assert ts_agent, "expected a Vercel AI SDK agent finding"
    assert "financial-action" in flags[ts_agent[0]]

    # MCP: secret + database + financial (payments-mcp, plural name)
    assert any("secret" in fl for fset in flags.values() for fl in fset), "expected an MCP secret flag"
    assert any("database-access" in fset for fset in flags.values())
    assert any("financial-action" in fset for s, fset in flags.items() if "payments-mcp" in s)

    # observability gap fires somewhere (no tracing wired)
    assert "no-observability" in allflags

    # API BOLA candidate on the prefix-resolved path
    api = [f for f in by_cat["api"] if any("BOLA" in r for r in f.risk_indicators)]
    assert api and api[0].evidence.metadata.get("path") == "/orders/{order_id}"

    # governance frameworks evidenced
    from ai_surface.frameworks import framework_names
    names = framework_names(report)
    assert "EU AI Act" in names and "OWASP LLM Top 10" in names
