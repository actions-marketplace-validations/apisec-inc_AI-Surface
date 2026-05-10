"""Core types for ai-surface.

Every detector produces Findings against a shared schema. The orchestrator
aggregates findings into a Report which reporters render.

Python 3.9 compatible: uses `from __future__ import annotations` so newer
syntax (X | None, list[X]) is allowed in annotations only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable


# Categories that detectors can claim. Keep this list short and stable.
# New detectors should reuse one of these or propose adding a category.
CATEGORY_LLM_SDK = "llm-sdk"
CATEGORY_AGENT_FRAMEWORK = "agent-framework"
CATEGORY_MCP_SERVER = "mcp-server"
CATEGORY_MODEL_GATEWAY = "model-gateway"
CATEGORY_AI_INFRA = "ai-infra"
CATEGORY_ENV_KEY = "env-key"

ALL_CATEGORIES = (
    CATEGORY_LLM_SDK,
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_MCP_SERVER,
    CATEGORY_MODEL_GATEWAY,
    CATEGORY_AI_INFRA,
    CATEGORY_ENV_KEY,
)


@dataclass
class Evidence:
    """Where a finding came from. Always include enough for a human to verify."""

    files: List[str] = field(default_factory=list)
    """File paths (relative to scan root) where the surface was found."""

    snippet: str = ""
    """A short code/config snippet showing the detection. Truncate to ~200 chars."""

    line_numbers: List[int] = field(default_factory=list)
    """Optional: specific line numbers in the primary file."""

    metadata: Dict[str, Any] = field(default_factory=dict)
    """Detector-specific extras (model name, tool list, permissions, etc.)."""


@dataclass
class Finding:
    """A single AI surface detected in the scanned codebase.

    One Finding represents one logical surface. Examples:
      - "Anthropic SDK used in src/agents/"  (one finding, multiple files)
      - "MCP server: stripe-mcp"             (one finding per configured server)
      - "LangChain agent: refund_agent"      (one finding per agent definition)

    Detectors should aggregate sensibly. If Anthropic SDK appears in 12 files,
    that is one Finding with 12 file evidence entries, not 12 findings.
    """

    surface: str
    """User-facing name. Examples: "Anthropic SDK", "MCP Server: stripe-mcp",
    "LangChain Agent: refund_agent"."""

    category: str
    """One of the CATEGORY_* constants above."""

    evidence: Evidence
    """Where this surface was detected."""

    permissions: List[str] = field(default_factory=list)
    """What this surface can reach. Examples: ["read pages", "write pages"],
    ["repo:read", "repo:write"], ["query_customer_db", "refund_payment"]."""

    risk_indicators: List[str] = field(default_factory=list)
    """Plain-English risk flags for human review. Examples:
      - "broad permissions"
      - "financial action exposed"
      - "unaudited (first appearance in repo)"
      - "PII flows into LLM call"
    Do NOT include severity scores. This is descriptive, not prescriptive."""

    detector_name: str = ""
    """The detector that produced this finding. Filled in by orchestrator."""


@dataclass
class Report:
    """The complete output of one scan run."""

    findings: List[Finding]
    scan_root: str
    scan_timestamp: str
    detectors_run: List[str]
    schema_version: str = "0.5"
    tool_version: str = "0.5.0"
    errors: List[str] = field(default_factory=list)
    """Non-fatal errors from individual detectors. Surface to user but do not abort."""

    @classmethod
    def now(cls) -> str:
        """Standard ISO timestamp for scan_timestamp."""
        return datetime.now(timezone.utc).isoformat()

    def by_category(self) -> Dict[str, List[Finding]]:
        """Group findings by category for reporting."""
        out: Dict[str, List[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.category, []).append(f)
        return out

    def all_risk_indicators(self) -> List[str]:
        """Flatten unique risk indicators across all findings."""
        seen = []
        for f in self.findings:
            for r in f.risk_indicators:
                phrase = f"{f.surface}: {r}"
                if phrase not in seen:
                    seen.append(phrase)
        return seen


@runtime_checkable
class Detector(Protocol):
    """Detector protocol. Every detector implements this.

    Implementations should be classes with `name` and `category` set as class
    attributes (or instance attributes) and a `detect()` method.

    Detectors must:
      - Return [] (not raise) when nothing is found.
      - Be safe to run on any directory tree, including non-code directories.
      - Not mutate the filesystem.
      - Be deterministic for the same input.
      - Aggregate sensibly (one finding per logical surface, not per file).
    """

    name: str
    category: str

    def detect(self, root_path: str) -> List[Finding]:
        ...


# Convenience for orchestrator: optional detector context.
@dataclass
class DetectorContext:
    """Optional shared context passed to detectors at run time.

    Some detectors may want to know the scan root absolute path, whether
    git history is available, or share a cache. Passed as a kwarg if the
    detector accepts it.
    """

    scan_root: str
    has_git: bool = False
    cache: Dict[str, Any] = field(default_factory=dict)
