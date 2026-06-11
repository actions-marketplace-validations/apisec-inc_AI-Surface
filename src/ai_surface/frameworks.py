"""Map a scan to the AI-governance frameworks it produces evidence for.

This is deliberately honest: ai-surface produces *evidence* that maps to
framework requirements (inventory, documentation, risk identification). It does
NOT assert compliance, certify, or attest. The wording everywhere is "produces
evidence for", never "compliant with".

Each framework lists the requirements ai-surface can contribute to, tagged by
the kind of evidence that backs them:
  - "inventory": the discovered AI surface (the AI-BOM)
  - "risk":      risk indicators / severities / audit findings
  - "owasp":     OWASP LLM Top 10 mappings on audited findings
A requirement is reported as covered only if the scan actually produced that
kind of evidence.
"""
from __future__ import annotations

from typing import Any

from .types import Report

#: framework id -> (display name, [(requirement, evidence_kind), ...])
FRAMEWORKS: list[dict[str, Any]] = [
    {
        "id": "eu-ai-act",
        "name": "EU AI Act",
        "requirements": [
            ("Technical documentation and record-keeping (Art. 11-12)", "inventory"),
            ("Risk management of AI systems (Art. 9)", "risk"),
        ],
    },
    {
        "id": "nist-ai-rmf",
        "name": "NIST AI RMF",
        "requirements": [
            ("Map: inventory and context of AI systems", "inventory"),
            ("Measure: identify and assess AI risks", "risk"),
        ],
    },
    {
        "id": "iso-42001",
        "name": "ISO/IEC 42001",
        "requirements": [
            ("AI system inventory (Annex A)", "inventory"),
            ("AI risk assessment", "risk"),
        ],
    },
    {
        "id": "owasp-llm",
        "name": "OWASP LLM Top 10",
        "requirements": [
            ("Mapping of findings to LLM Top 10 categories", "owasp"),
        ],
    },
]


def _evidence_kinds_present(report: Report) -> set[str]:
    kinds: set[str] = set()
    if report.findings:
        kinds.add("inventory")
    for f in report.findings:
        if f.risk_indicators or f.severity:
            kinds.add("risk")
        if f.audit and f.audit.owasp_mappings:
            kinds.add("owasp")
    return kinds


def framework_evidence(report: Report) -> list[dict[str, Any]]:
    """Return, per framework, the requirements this scan produces evidence for.

    Only requirements actually backed by evidence in this scan are listed. A
    framework with no backed requirements is omitted.
    """
    present = _evidence_kinds_present(report)
    out: list[dict[str, Any]] = []
    for fw in FRAMEWORKS:
        provides = [req for (req, kind) in fw["requirements"] if kind in present]
        if provides:
            out.append({"id": fw["id"], "name": fw["name"], "provides": provides})
    return out


def framework_names(report: Report) -> list[str]:
    """Convenience: just the framework display names with any evidence."""
    return [fw["name"] for fw in framework_evidence(report)]
