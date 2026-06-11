"""Classify each finding's disposition: the boundary between independent DevOps
value and the platform journey.

resolve-here   : statically determinable, fix it now, no platform needed.
validate-runtime: a candidate; only runtime against the deployed app proves
                  exploitability. Carries a runtime status (live/coming) and the
                  exact question the platform answers.

Scope is aligned to the NG platform product strategy:
  - API, MCP, agents are the runtime-validatable attack surface (validate-runtime).
  - LLM call sites, model gateways, AI infra, provider keys are posture /
    inventory (resolve-here). LLM/model behaviour is explicitly out of scope
    (model-independent), gateway concerns belong to the gateway.
Honesty about availability: only API is live today; MCP and agents are "coming".
"""
from __future__ import annotations

from .types import (
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_API,
    CATEGORY_MCP_SERVER,
    DISPOSITION_RESOLVE,
    DISPOSITION_VALIDATE,
    RUNTIME_COMING,
    RUNTIME_LIVE,
    RUNTIME_NA,
    Finding,
)

#: Categories that have a runtime exploit-validation journey. Everything else is
#: resolve-here (posture / inventory). LLM/gateway/infra/keys are deliberately
#: NOT here, per platform scope.
_VALIDATABLE = {
    CATEGORY_API: RUNTIME_LIVE,
    CATEGORY_MCP_SERVER: RUNTIME_COMING,
    CATEGORY_AGENT_FRAMEWORK: RUNTIME_COMING,
}

#: The exploitability question only runtime can answer, per validatable category.
_RUNTIME_QUESTION = {
    CATEGORY_API: "Is this endpoint actually exploitable (BOLA, broken auth, "
    "business-logic abuse) against the running application?",
    CATEGORY_MCP_SERVER: "Can this MCP server's tools be abused at runtime "
    "(tool abuse, agent-to-tool BOLA/BFLA, over-provisioned permissions)?",
    CATEGORY_AGENT_FRAMEWORK: "Can this agent be driven to an unauthorized "
    "action (agent-to-tool authorization abuse, agent-exposed API)?",
}


def disposition_for(finding: Finding) -> tuple[str, str, str | None]:
    """Return (disposition, runtime_status, runtime_question) for a finding."""
    status = _VALIDATABLE.get(finding.category)
    if status is None:
        return DISPOSITION_RESOLVE, RUNTIME_NA, None
    return DISPOSITION_VALIDATE, status, _RUNTIME_QUESTION.get(finding.category)


def attach_dispositions(findings: list[Finding]) -> None:
    """Set disposition / runtime_status / runtime_question in place. Idempotent:
    skips findings already classified."""
    for f in findings:
        if f.disposition:
            continue
        f.disposition, f.runtime_status, f.runtime_question = disposition_for(f)
