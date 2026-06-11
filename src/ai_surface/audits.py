"""Deep-dive audit enrichment for validate-runtime surfaces beyond MCP.

MCP findings are audited inside the mcp_audit detector. This layer adds the
same kind of audit (severity + risk flags with OWASP + remediation) to the
OTHER validate-runtime category that would otherwise be bare: AI agents.

Posture categories (model gateways, AI infra, provider keys, LLM call sites)
are resolve-here by design and are NOT audited here: their risk_indicators
carry their substance, and inventing severity for them would be dishonest.

Run as a post-process (enrich_audits) before disposition/bridge attachment so
severity flows into the summary and the map.
"""
from __future__ import annotations

from .types import (
    CATEGORY_AGENT_FRAMEWORK,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_ORDER,
    Audit,
    Finding,
    RiskFlag,
)

# Tool-name keyword buckets for agent risk assessment.
_FINANCIAL = ("refund", "payment", "charge", "transfer", "payout", "invoice", "wire", "ledger")
_DESTRUCTIVE = ("delete", "drop", "truncate", "purge", "remove", "revoke", "terminate")
_MESSAGING = ("send_email", "send_slack", "send_sms", "email", "slack", "sms", "notify", "message")
_READ = ("read", "get", "list", "query", "search", "fetch", "lookup")
_WRITE = ("write", "update", "create", "insert", "post", "approve", "modify")


def _hits(tools: list[str], keys: tuple[str, ...]) -> list[str]:
    return [t for t in tools if any(k in t.lower() for k in keys)]


def _max_severity(flags: list[RiskFlag]) -> str | None:
    if not flags:
        return None
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return min((f.severity for f in flags), key=lambda s: rank.get(s, 99))


def agent_audit(finding: Finding) -> Audit | None:
    """Compute a deep-dive audit for an agent finding from its tools + risks."""
    tools = list(finding.permissions or [])
    flags: list[RiskFlag] = []

    fin = _hits(tools, _FINANCIAL)
    dest = _hits(tools, _DESTRUCTIVE)
    msg = _hits(tools, _MESSAGING)
    reads = _hits(tools, _READ)

    if fin:
        flags.append(RiskFlag(
            "financial-action", SEVERITY_HIGH,
            f"Agent can invoke financial tools ({', '.join(fin)})", ["LLM06"],
            "Gate financial tools behind human approval; least-privilege the agent.",
        ))
    if dest:
        flags.append(RiskFlag(
            "destructive-action", SEVERITY_HIGH,
            f"Agent can invoke destructive tools ({', '.join(dest)})", ["LLM06"],
            "Require confirmation and remove destructive tools from the agent's toolset.",
        ))
    if msg:
        flags.append(RiskFlag(
            "messaging-action", SEVERITY_MEDIUM,
            "Agent can send outbound messages/notifications", ["LLM06"],
            "Rate-limit and gate outbound messaging behind approval.",
        ))
    if reads and (fin or dest):
        flags.append(RiskFlag(
            "high-blast-radius", SEVERITY_HIGH,
            "Agent combines broad read access with financial/destructive actions", ["LLM06"],
            "Split read and write agents; apply least-privilege per agent.",
        ))
    if any("pii" in r.lower() for r in (finding.risk_indicators or [])):
        flags.append(RiskFlag(
            "pii-to-llm", SEVERITY_MEDIUM,
            "PII flows into an LLM call from this agent", ["LLM02"],
            "Redact or minimize PII before prompting; review the data flow.",
        ))
    if len(tools) >= 6:
        flags.append(RiskFlag(
            "excessive-agency", SEVERITY_LOW,
            f"Agent exposes {len(tools)} tools to the model", ["LLM06"],
            "Reduce the agent's toolset to the minimum required.",
        ))

    if not flags:
        return None
    owasp = sorted({o for f in flags for o in f.owasp})
    return Audit(risk_flags=flags, owasp_mappings=owasp)


def enrich_audits(findings: list[Finding]) -> None:
    """Add deep-dive audits (and severity) to validate-runtime findings that the
    detectors left bare. In place. Skips findings already audited (e.g. MCP)."""
    for f in findings:
        if f.audit:
            continue
        audit = None
        if f.category == CATEGORY_AGENT_FRAMEWORK:
            audit = agent_audit(f)
        if audit:
            f.audit = audit
            f.severity = _max_severity(audit.risk_flags)
