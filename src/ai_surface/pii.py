"""PII-into-prompt audit pass.

EU AI Act Art. 10 (data governance), ISO/IEC 42001 A.7 (data for AI systems),
OWASP LLM02 (sensitive information disclosure): personal data should not be
interpolated wholesale into LLM prompts. This pass detects prompt templates that
embed PII fields (email, address, SSN, phone, ...) and adds a ``pii-to-llm`` flag
to the agents that use them.

Why a dedicated pass: the agent audit already defines a ``pii-to-llm`` flag, but
it was gated on a risk indicator no detector produced, so it never fired. The
PII is also usually in a separate prompts module from the agent, so a per-file
check misses it. This pass resolves that: it finds prompt-with-PII files, then
flags an agent if its own file is one, or if it imports a prompts module that is.

Static and conservative: it checks the *structure* (a PII field name inside a
prompt template), not actual data. It never reads or stores any value, and it
never tests the model.
"""
from __future__ import annotations

import re
from pathlib import Path

from .types import (
    CATEGORY_AGENT_FRAMEWORK,
    SEVERITY_MEDIUM,
    SEVERITY_ORDER,
    Audit,
    Finding,
    RiskFlag,
)
from .utils.walk import read_text_safe, walk_files

# A placeholder like {customer_email} / {address} / {user_ssn} carrying a PII field.
# PII field token, not glued to a longer alphabetic word (so it matches
# {customer_email} where "email" follows an underscore, but not "emailer").
_PII_PLACEHOLDER_RE = re.compile(
    r"\{[^{}\n]{0,40}(?<![A-Za-z])("
    r"e_?mail|ssn|social.?security|phone|mobile|address|dob|date_of_birth|birth_date|"
    r"credit_card|card_number|full_name|first_name|last_name|passport|tax_id|national_id"
    r")(?![A-Za-z])[^{}\n]{0,40}\}",
    re.IGNORECASE,
)

# Signals that a string is actually a prompt (so a PII placeholder elsewhere,
# e.g. an HTML template, is not mistaken for a prompt).
_PROMPT_CONTEXT_RE = re.compile(
    r"ChatPromptTemplate|PromptTemplate|from_template|from_messages|SystemMessage|"
    r"system_?prompt|\b\w*(?:PROMPT|TEMPLATE|INSTRUCTION)\w*\s*=|you are (?:a|an|the|our|your|\w+'s)",
    re.IGNORECASE,
)

_PII_EXTS = frozenset({".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"})


def has_pii_prompt(text: str) -> bool:
    """True if ``text`` interpolates a PII field into a prompt-like string."""
    return bool(text) and bool(_PII_PLACEHOLDER_RE.search(text)) and bool(_PROMPT_CONTEXT_RE.search(text))


def _pii_prompt_files(scan_root: str) -> tuple[set[str], set[str]]:
    """Return (relative file paths, module stems) of files with PII-in-prompt."""
    files: set[str] = set()
    stems: set[str] = set()
    root = Path(scan_root)
    for path in walk_files(scan_root, extensions=list(_PII_EXTS)):
        text = read_text_safe(path)
        if text and has_pii_prompt(text):
            try:
                rel = path.resolve().relative_to(root.resolve()).as_posix()
            except (ValueError, OSError):
                rel = path.name
            files.add(rel)
            stems.add(path.stem)
    return files, stems


def _imports_a_stem(text: str, stems: set[str]) -> bool:
    return any(
        re.search(rf"(?:from|import|require)\b[^\n]*\b{re.escape(stem)}\b", text)
        for stem in stems
    )


def _pii_flag() -> RiskFlag:
    return RiskFlag(
        flag="pii-to-llm",
        severity=SEVERITY_MEDIUM,
        description="Personal data (PII) is interpolated into a prompt template sent to the model",
        owasp=["LLM02"],
        remediation=(
            "Minimize or redact PII before prompting; pass an opaque id and look the "
            "record up tool-side instead of embedding email/address/SSN in the prompt."
        ),
    )


def _bump_severity(finding: Finding) -> None:
    if not finding.audit or not finding.audit.risk_flags:
        return
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    sevs = [rf.severity for rf in finding.audit.risk_flags]
    finding.severity = min(sevs, key=lambda s: rank.get(s, 99))


def enrich_pii(findings: list[Finding], scan_root: str | None = None) -> None:
    """Add ``pii-to-llm`` flags, in place, to agents whose prompts embed PII.

    An agent is flagged when its own evidence file embeds PII in a prompt, or
    when it imports a prompts module that does. No-op when no PII-in-prompt is
    found. Idempotent.
    """
    if not scan_root:
        return
    pii_files, pii_stems = _pii_prompt_files(scan_root)
    if not pii_files:
        return
    root = Path(scan_root)
    for f in findings:
        if f.category != CATEGORY_AGENT_FRAMEWORK:
            continue
        if f.audit and any(rf.flag == "pii-to-llm" for rf in f.audit.risk_flags):
            continue
        ev_files = (f.evidence.files if f.evidence else []) or []
        flagged = any(rel in pii_files for rel in ev_files)
        if not flagged:
            for rel in ev_files:
                text = read_text_safe(root / rel)
                if text and _imports_a_stem(text, pii_stems):
                    flagged = True
                    break
        if not flagged:
            continue
        flag = _pii_flag()
        if f.audit is None:
            f.audit = Audit(risk_flags=[flag], owasp_mappings=list(flag.owasp))
        else:
            f.audit.risk_flags.append(flag)
            for oid in flag.owasp:
                if oid not in f.audit.owasp_mappings:
                    f.audit.owasp_mappings.append(oid)
        _bump_severity(f)


__all__ = ["has_pii_prompt", "enrich_pii"]
