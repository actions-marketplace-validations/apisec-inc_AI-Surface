"""Tests for the verdicts layer (confirmed vs likely risk)."""
from __future__ import annotations

from ai_surface.types import (
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    VERDICT_CONFIRMED,
    VERDICT_LIKELY,
    Audit,
    Evidence,
    Finding,
    Report,
    RiskFlag,
    Secret,
)
from ai_surface.verdicts import (
    CONFIRMED_FLAGS,
    LIKELY_FLAGS,
    attach_verdicts,
    verdict_for,
)


def _finding(**kwargs) -> Finding:
    defaults = {"surface": "Test Surface", "category": "mcp-server", "evidence": Evidence()}
    defaults.update(kwargs)
    return Finding(**defaults)


def test_pure_inventory_gets_no_verdict() -> None:
    f = _finding()
    assert verdict_for(f) is None


def test_declared_capability_flag_is_confirmed() -> None:
    f = _finding(
        audit=Audit(risk_flags=[RiskFlag("shell-access", SEVERITY_HIGH)]),
        severity=SEVERITY_HIGH,
    )
    assert verdict_for(f) == VERDICT_CONFIRMED


def test_financial_action_is_confirmed() -> None:
    f = _finding(
        category="agent-framework",
        audit=Audit(risk_flags=[RiskFlag("financial-action", SEVERITY_HIGH)]),
        severity=SEVERITY_HIGH,
    )
    assert verdict_for(f) == VERDICT_CONFIRMED


def test_detected_secret_is_confirmed_even_without_flags() -> None:
    f = _finding(audit=Audit(secrets=[Secret(name="OPENAI_API_KEY")]))
    assert verdict_for(f) == VERDICT_CONFIRMED


def test_inference_flags_are_likely() -> None:
    for flag in ("unverified-source", "pii-to-llm", "no-observability", "no-human-oversight"):
        f = _finding(
            audit=Audit(risk_flags=[RiskFlag(flag, SEVERITY_MEDIUM)]),
            severity=SEVERITY_MEDIUM,
        )
        assert verdict_for(f) == VERDICT_LIKELY, flag


def test_mixed_flags_confirmed_wins() -> None:
    f = _finding(
        audit=Audit(
            risk_flags=[
                RiskFlag("unverified-source", SEVERITY_MEDIUM),
                RiskFlag("database-access", SEVERITY_MEDIUM),
            ]
        ),
        severity=SEVERITY_MEDIUM,
    )
    assert verdict_for(f) == VERDICT_CONFIRMED


def test_risk_indicators_without_audit_cap_at_likely() -> None:
    f = _finding(risk_indicators=["non-literal data flows into LLM call"])
    assert verdict_for(f) == VERDICT_LIKELY


def test_attach_is_idempotent_and_preserves_existing() -> None:
    f1 = _finding(risk_indicators=["something risky"])
    f2 = _finding()
    f2.verdict = VERDICT_CONFIRMED  # pre-classified elsewhere; must not change
    attach_verdicts([f1, f2])
    assert f1.verdict == VERDICT_LIKELY
    assert f2.verdict == VERDICT_CONFIRMED


def test_flag_sets_are_disjoint() -> None:
    assert not (CONFIRMED_FLAGS & LIKELY_FLAGS)


def test_known_flag_vocabulary_is_fully_classified() -> None:
    """Every flag id the codebase can emit must be explicitly classified.

    A new flag id must be added to CONFIRMED_FLAGS or LIKELY_FLAGS; this test
    fails loudly instead of letting it silently default.
    """
    from ai_surface.data.mcp.risk_definitions import RISK_FLAGS

    known = set(RISK_FLAGS.keys()) | {
        # agent audit layer
        "financial-action",
        "destructive-action",
        "messaging-action",
        "high-blast-radius",
        "excessive-agency",
        # cross-layer passes
        "pii-to-llm",
        "no-human-oversight",
        "no-observability",
    }
    unclassified = known - CONFIRMED_FLAGS - LIKELY_FLAGS
    assert not unclassified, f"unclassified risk flags: {sorted(unclassified)}"


def test_summary_counts_verdicts() -> None:
    findings = [
        _finding(
            audit=Audit(risk_flags=[RiskFlag("shell-access", SEVERITY_HIGH)]),
            severity=SEVERITY_HIGH,
        ),
        _finding(risk_indicators=["pattern hit"]),
        _finding(),
    ]
    attach_verdicts(findings)
    report = Report(
        findings=findings, scan_root=".", scan_timestamp=Report.now(), detectors_run=[]
    )
    summary = report.build_summary()
    assert summary.confirmed_count == 1
    assert summary.likely_count == 1
