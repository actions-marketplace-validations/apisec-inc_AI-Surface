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
            ("Human oversight of high-risk actions (Art. 14)", "oversight"),
            ("Logging and monitoring of AI operation (Art. 12)", "observability"),
        ],
    },
    {
        "id": "nist-ai-rmf",
        "name": "NIST AI RMF",
        "requirements": [
            ("Map: inventory and context of AI systems", "inventory"),
            ("Measure: identify and assess AI risks", "risk"),
            ("Measure: AI system monitored in operation (MEASURE 3)", "observability"),
        ],
    },
    {
        "id": "iso-42001",
        "name": "ISO/IEC 42001",
        "requirements": [
            ("AI system inventory (Annex A)", "inventory"),
            ("AI risk assessment", "risk"),
            ("Operation and monitoring (Annex A.6.2.6)", "observability"),
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
        # The human-oversight pass produces Art. 14 evidence: it has assessed a
        # high-risk action and found no approval gate on its path.
        if f.audit and any(rf.flag == "no-human-oversight" for rf in f.audit.risk_flags):
            kinds.add("oversight")
        # The observability pass produces logging/monitoring evidence: it has
        # assessed an execution surface and found no tracing wired for it.
        if f.audit and any(rf.flag == "no-observability" for rf in f.audit.risk_flags):
            kinds.add("observability")
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


# --------------------------------------------------------------------------- #
# Per-flag governance-clause mapping (for badges next to each risk flag)
# --------------------------------------------------------------------------- #
# OWASP LLM ids live on the RiskFlag itself (rf.owasp). This maps a risk flag to
# the specific governance clauses it most directly evidences, so the UI can show
# framework badges alongside the OWASP ones. Only STRONG, defensible mappings are
# listed. Capability flags (shell/filesystem/database/network/broad-permissions)
# are Excessive Agency in OWASP terms and carry no specific clause here, so they
# show OWASP only. Tuples are (framework display name, framework id, clause).
_FLAG_STANDARDS: dict[str, list[tuple[str, str, str]]] = {
    "secrets-detected": [("EU AI Act", "eu-ai-act", "Art. 15")],
    "secrets-in-env": [("EU AI Act", "eu-ai-act", "Art. 15")],
    "admin-credentials": [("EU AI Act", "eu-ai-act", "Art. 15")],
    "financial-action": [("EU AI Act", "eu-ai-act", "Art. 9")],
    "destructive-action": [("EU AI Act", "eu-ai-act", "Art. 9")],
    "high-blast-radius": [("EU AI Act", "eu-ai-act", "Art. 9")],
    "no-human-oversight": [("EU AI Act", "eu-ai-act", "Art. 14")],
    "no-observability": [
        ("EU AI Act", "eu-ai-act", "Art. 12"),
        ("NIST AI RMF", "nist-ai-rmf", "MEASURE 3"),
        ("ISO 42001", "iso-42001", "A.6.2.6"),
    ],
    "unverified-source": [("ISO 42001", "iso-42001", "A.10")],
    "local-binary": [("ISO 42001", "iso-42001", "A.10")],
    "remote-mcp": [("ISO 42001", "iso-42001", "A.10")],
}


def standards_for_flag(flag: str) -> list[dict[str, str]]:
    """Specific governance clauses a risk flag evidences (beyond OWASP).

    Returns a list of ``{"framework", "framework_id", "clause"}`` dicts, possibly
    empty. Consumed by the JSON reporter so the UI can render framework badges.
    """
    return [
        {"framework": fw, "framework_id": fid, "clause": clause}
        for (fw, fid, clause) in _FLAG_STANDARDS.get(flag, [])
    ]
