"""CycloneDX AI-BOM reporter (spec 1.6).

Emits a standardized AI Bill of Materials from a scan, so the discovered AI
surface plugs into the same governance and compliance pipelines teams already
run for SBOMs. This is the regulatory artifact: it produces evidence that maps
to AI-governance frameworks (EU AI Act technical documentation, NIST AI RMF
"Map", ISO/IEC 42001 AI system inventory, EU CRA bill-of-materials), generated
the same way and at the same point as an SBOM, in CI.

It is evidence, not a compliance certification: it inventories the AI surface
and attaches the risk context ai-surface found. One component per discovered
surface. Privacy is preserved: secret names/types only, never values.
"""
from __future__ import annotations

import json
import re
from typing import Any

from ..types import (
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_AI_INFRA,
    CATEGORY_API,
    CATEGORY_ENV_KEY,
    CATEGORY_LLM_SDK,
    CATEGORY_MCP_SERVER,
    CATEGORY_MODEL_GATEWAY,
    Finding,
    Report,
)

#: ai-surface category -> CycloneDX component type. Chosen to be meaningful to
#: BOM tooling: models/runtimes are machine-learning-model, callable surfaces
#: are services, agent/MCP code units are applications, key references are data.
_CDX_TYPE = {
    CATEGORY_LLM_SDK: "machine-learning-model",
    CATEGORY_AI_INFRA: "machine-learning-model",
    CATEGORY_AGENT_FRAMEWORK: "application",
    CATEGORY_MCP_SERVER: "application",
    CATEGORY_MODEL_GATEWAY: "service",
    CATEGORY_API: "service",
    CATEGORY_ENV_KEY: "data",
}

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def render_cyclonedx(report: Report, indent: int = 2) -> str:
    """Render `report` as a CycloneDX 1.6 AI-BOM JSON string."""
    return json.dumps(to_cyclonedx(report), indent=indent, ensure_ascii=False)


def to_cyclonedx(report: Report) -> dict[str, Any]:
    """Convert a Report to a CycloneDX 1.6 BOM dict."""
    from ..frameworks import framework_evidence  # noqa: PLC0415

    meta_props: list[dict[str, str]] = [
        {"name": "ai-surface:schema_version", "value": report.schema_version},
        {"name": "ai-surface:findings_count", "value": str(len(report.findings))},
    ]
    # Governance-framework evidence (honest: evidence-for, not compliance).
    for fw in framework_evidence(report):
        meta_props.append(
            {
                "name": f"ai-surface:framework-evidence:{fw['id']}",
                "value": f"{fw['name']}: {'; '.join(fw['provides'])}",
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": report.scan_timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "ai-surface",
                        "version": report.tool_version,
                        "publisher": "APIsec",
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": "root",
                "name": report.scan_root or ".",
            },
            "properties": meta_props,
        },
        "components": [_component(f, i) for i, f in enumerate(report.findings)],
    }


def _slug(text: str) -> str:
    return _SLUG_RE.sub("-", text.lower()).strip("-")[:60] or "surface"


def _component(finding: Finding, index: int) -> dict[str, Any]:
    props: list[dict[str, str]] = [
        {"name": "ai-surface:category", "value": finding.category},
    ]
    if finding.severity:
        props.append({"name": "ai-surface:severity", "value": finding.severity})
    if finding.detector_name:
        props.append({"name": "ai-surface:detector", "value": finding.detector_name})
    for r in finding.risk_indicators:
        props.append({"name": "ai-surface:risk", "value": r})
    if finding.evidence and finding.evidence.files:
        props.append({"name": "ai-surface:file", "value": finding.evidence.files[0]})

    # API endpoint detail from documented metadata keys.
    if finding.category == CATEGORY_API and finding.evidence:
        meta = finding.evidence.metadata or {}
        for key in ("method", "path", "framework", "auth"):
            val = meta.get(key)
            if val:
                props.append({"name": f"ai-surface:api-{key}", "value": str(val)})

    # Deep-dive audit (MCP today): flags + OWASP, secrets by name/type only.
    if finding.audit:
        for rf in finding.audit.risk_flags:
            props.append(
                {"name": "ai-surface:audit-flag", "value": f"{rf.severity}:{rf.flag}"}
            )
            for owasp in rf.owasp:
                props.append({"name": "ai-surface:owasp", "value": owasp})
        for sec in finding.audit.secrets:
            # NAME/TYPE only, never a value (privacy guarantee).
            props.append(
                {"name": "ai-surface:secret", "value": f"{sec.name} ({sec.secret_type})"}
            )
        if finding.audit.trust_label:
            props.append({"name": "ai-surface:trust", "value": finding.audit.trust_label})

    # Upgrade path: which paid validation SKU this surface routes to.
    for b in finding.bridges:
        props.append({"name": "ai-surface:validate", "value": b.sku})

    comp: dict[str, Any] = {
        "type": _CDX_TYPE.get(finding.category, "application"),
        "bom-ref": f"{finding.category}/{_slug(finding.surface)}/{index}",
        "name": finding.surface,
        "properties": props,
    }
    return comp
