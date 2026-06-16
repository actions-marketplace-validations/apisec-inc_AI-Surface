"""SARIF 2.1.0 reporter for GitHub code scanning (the Security tab).

Emits findings as a SARIF log so they show up in GitHub's Security tab and as
inline PR annotations, the way DevOps and security teams already consume SAST
output. One result per finding; severity maps to SARIF levels; each finding
references a per-category rule.
"""
from __future__ import annotations

import json
from typing import Any

from ..types import (
    ALL_CATEGORIES,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    Finding,
    Report,
)

_INFO_URI = "https://github.com/apisec-inc/AI-Surface"

#: Human labels for the per-category rules.
_CATEGORY_LABEL = {
    "llm-sdk": "LLM SDK call site",
    "agent-framework": "AI agent framework",
    "mcp-server": "MCP server",
    "model-gateway": "Model gateway",
    "ai-infra": "AI infrastructure",
    "env-key": "AI provider key reference",
    "api": "HTTP/REST endpoint",
    "vector-store": "Vector store / RAG pipeline",
}

# SARIF result levels: error blocks, warning surfaces, note is informational.
_ERROR = {SEVERITY_CRITICAL, SEVERITY_HIGH}
_WARNING = {SEVERITY_MEDIUM}


def render_sarif(report: Report, indent: int = 2) -> str:
    """Render `report` as a SARIF 2.1.0 JSON string."""
    return json.dumps(to_sarif(report), indent=indent, ensure_ascii=False)


def _level(finding: Finding) -> str:
    if finding.severity in _ERROR:
        return "error"
    if finding.severity in _WARNING:
        return "warning"
    return "note"  # low/info, and severity-free inventory


def _rules() -> list[dict[str, Any]]:
    return [
        {
            "id": cat,
            "name": _CATEGORY_LABEL.get(cat, cat),
            "shortDescription": {"text": f"{_CATEGORY_LABEL.get(cat, cat)} detected by ai-surface"},
            "helpUri": _INFO_URI,
        }
        for cat in ALL_CATEGORIES
    ]


def _message(finding: Finding) -> str:
    parts = [finding.surface]
    if finding.severity:
        parts.append(f"severity: {finding.severity}")
    if finding.audit and finding.audit.risk_flags:
        flags = ", ".join(rf.flag for rf in finding.audit.risk_flags)
        parts.append(f"risk flags: {flags}")
    elif finding.risk_indicators:
        parts.append("; ".join(finding.risk_indicators))
    return " | ".join(parts)


def _result(finding: Finding) -> dict[str, Any]:
    props: dict[str, Any] = {"category": finding.category}
    if finding.severity:
        props["severity"] = finding.severity
    if finding.audit:
        owasp = sorted({o for rf in finding.audit.risk_flags for o in rf.owasp})
        if owasp:
            props["owasp"] = owasp
    if finding.bridges:
        props["validate"] = [b.sku for b in finding.bridges]

    result: dict[str, Any] = {
        "ruleId": finding.category,
        "level": _level(finding),
        "message": {"text": _message(finding)},
        "properties": props,
    }

    # Location: first evidence file, with a line if known.
    files = finding.evidence.files if finding.evidence else []
    if files:
        phys: dict[str, Any] = {"artifactLocation": {"uri": files[0]}}
        lines = finding.evidence.line_numbers if finding.evidence else []
        if lines:
            phys["region"] = {"startLine": lines[0]}
        result["locations"] = [{"physicalLocation": phys}]
    return result


def to_sarif(report: Report) -> dict[str, Any]:
    """Convert a Report to a SARIF 2.1.0 log dict."""
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ai-surface",
                        "version": report.tool_version,
                        "informationUri": _INFO_URI,
                        "rules": _rules(),
                    }
                },
                "results": [_result(f) for f in report.findings],
            }
        ],
    }
