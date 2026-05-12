"""Orchestrator: runs registered detectors and aggregates Findings into a Report."""
from __future__ import annotations

import logging
from pathlib import Path

from .types import Detector, Finding, Report

log = logging.getLogger(__name__)


class Orchestrator:
    """Runs a collection of detectors against a scan root and produces a Report.

    Usage:
        orch = Orchestrator(detectors=[McpDetector(), LlmSdkDetector(), ...])
        report = orch.run("/path/to/repo")
    """

    def __init__(self, detectors: list[Detector] | None = None) -> None:
        self.detectors: list[Detector] = list(detectors or [])

    def register(self, detector: Detector) -> None:
        """Add a detector to the run list."""
        self.detectors.append(detector)

    def run(self, scan_root: str) -> Report:
        """Run every registered detector against scan_root, aggregate findings."""
        root = Path(scan_root).resolve()
        if not root.exists():
            raise FileNotFoundError(f"scan root does not exist: {scan_root}")
        if not root.is_dir():
            raise NotADirectoryError(f"scan root is not a directory: {scan_root}")

        all_findings: list[Finding] = []
        errors: list[str] = []
        detector_names: list[str] = []

        for detector in self.detectors:
            name = getattr(detector, "name", detector.__class__.__name__)
            detector_names.append(name)
            try:
                findings = detector.detect(str(root))
                # Stamp detector_name on every finding for traceability
                for f in findings:
                    if not f.detector_name:
                        f.detector_name = name
                all_findings.extend(findings)
                log.debug("detector %s produced %d findings", name, len(findings))
            except Exception as exc:  # noqa: BLE001 - we want to keep going
                msg = f"detector {name} failed: {exc.__class__.__name__}: {exc}"
                errors.append(msg)
                log.warning(msg)

        return Report(
            findings=all_findings,
            scan_root=str(root),
            scan_timestamp=Report.now(),
            detectors_run=detector_names,
            errors=errors,
        )


def default_detectors() -> list[Detector]:
    """Return the default v0.5 detector set.

    Imports are deferred so each detector module can be developed and tested
    independently without breaking the orchestrator.
    """
    detectors: list[Detector] = []

    # Lazy imports keep the orchestrator usable even if a detector module is missing
    # during development. Each detector module is implemented in detectors/.
    try:
        from .detectors.mcp_servers import McpServerDetector  # noqa: PLC0415
        detectors.append(McpServerDetector())
    except ImportError as e:
        log.debug("MCP detector unavailable: %s", e)

    try:
        from .detectors.llm_sdks import LlmSdkDetector  # noqa: PLC0415
        detectors.append(LlmSdkDetector())
    except ImportError as e:
        log.debug("LLM SDK detector unavailable: %s", e)

    try:
        from .detectors.agent_frameworks import AgentFrameworkDetector  # noqa: PLC0415
        detectors.append(AgentFrameworkDetector())
    except ImportError as e:
        log.debug("Agent framework detector unavailable: %s", e)

    try:
        from .detectors.env_keys import EnvKeyDetector  # noqa: PLC0415
        detectors.append(EnvKeyDetector())
    except ImportError as e:
        log.debug("Env key detector unavailable: %s", e)

    try:
        from .detectors.model_gateways import ModelGatewayDetector  # noqa: PLC0415
        detectors.append(ModelGatewayDetector())
    except ImportError as e:
        log.debug("Model gateway detector unavailable: %s", e)

    return detectors
