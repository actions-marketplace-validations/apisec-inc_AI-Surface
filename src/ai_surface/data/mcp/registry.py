"""Known-MCP registry lookup for the deep-dive audit.

Ported from mcp-audit (``mcp_audit/data/__init__.py``). Loads the bundled
``known_mcps.json`` and matches a discovered MCP (by package source and/or
name) against it, yielding trust signals: a ``trust_label``
(verified|community|unknown), a coarse ``trust_score`` (0-100) and a
``registry_match`` (known|unknown).

Fully offline. Registry integrity is checked against a known SHA-256; a
mismatch only warns (trust data may be stale) and never aborts a scan.
"""
from __future__ import annotations

import hashlib
import json
import logging
import warnings
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger(__name__)

_REGISTRY_PATH = Path(__file__).parent / "known_mcps.json"

# SHA-256 of the bundled known_mcps.json. Mirrors mcp-audit's REGISTRY_HASH so
# tampering with the trust list is detectable.
REGISTRY_HASH = "5a8e4584c42bbd98c2bc0d5604911274c39d99ddf925f5723221a3a1e4bd5dc5"

_registry: Optional[dict[str, Any]] = None


class RegistryTamperWarning(UserWarning):
    """Raised when the registry integrity check fails."""


def _verify_integrity(path: Path) -> bool:
    try:
        content = path.read_bytes()
    except OSError:
        return False
    return hashlib.sha256(content).hexdigest() == REGISTRY_HASH


def get_registry(skip_integrity_check: bool = False) -> dict[str, Any]:
    """Load and cache the bundled known-MCP registry.

    On a missing or unparseable registry, returns an empty ``{"mcps": []}``
    so the caller degrades to "unknown" rather than raising.
    """
    global _registry
    if _registry is not None:
        return _registry

    if not _REGISTRY_PATH.is_file():
        log.debug("known_mcps.json not found at %s; registry empty", _REGISTRY_PATH)
        _registry = {"mcps": []}
        return _registry

    if not skip_integrity_check and not _verify_integrity(_REGISTRY_PATH):
        warnings.warn(
            "MCP registry integrity check failed; trust data may be unreliable.",
            RegistryTamperWarning,
            stacklevel=2,
        )

    try:
        _registry = json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.debug("failed to load known_mcps.json: %s", exc)
        _registry = {"mcps": []}
    if "mcps" not in _registry:
        _registry["mcps"] = []
    return _registry


def _extract_domain(url: str) -> str:
    url = url.replace("https://", "").replace("http://", "")
    url = url.split("/")[0]
    return url.split(":")[0]


def lookup_mcp(source: str, name: Optional[str] = None) -> Optional[dict[str, Any]]:
    """Look up an MCP by package source, endpoint URL, or name.

    Priority: exact package match, endpoint/domain match, exact name match,
    then partial name match. Returns the registry entry dict or ``None``.
    """
    registry = get_registry()
    source_lower = (source or "").lower()
    name_lower = (name or "").lower()
    mcps = registry.get("mcps", [])

    # 1. Exact package match.
    for mcp in mcps:
        pkg = mcp.get("package", "")
        if pkg and pkg.lower() in source_lower:
            return mcp

    # 2. Endpoint / domain match (remote MCPs).
    for mcp in mcps:
        endpoint = mcp.get("endpoint")
        if not endpoint:
            continue
        endpoint_lower = endpoint.lower()
        if source_lower and (endpoint_lower in source_lower or source_lower in endpoint_lower):
            return mcp
        if source_lower and _extract_domain(endpoint_lower) == _extract_domain(source_lower):
            return mcp

    # 3. Exact name / id match.
    if name_lower:
        for mcp in mcps:
            if name_lower in (mcp.get("name", "").lower(), mcp.get("id", "").lower()):
                return mcp

    # 4. Partial name match (fallback).
    if name_lower:
        for mcp in mcps:
            mcp_name = mcp.get("name", "").lower()
            if mcp_name and (mcp_name in name_lower or name_lower in mcp_name):
                return mcp

    return None


# trust_label values map onto ai-surface's documented "verified|community|unknown".
_TYPE_TO_LABEL = {
    "official": "verified",
    "vendor": "verified",
    "community": "community",
}


def trust_signals(source: str, name: Optional[str] = None) -> dict[str, Any]:
    """Resolve registry trust signals for a discovered MCP.

    Returns a dict with:
      * ``registry_match``: "known" | "unknown"
      * ``trust_label``: "verified" | "community" | "unknown"
      * ``trust_score``: 0-100 or ``None`` when unknown
      * ``match``: the raw registry entry or ``None``
    """
    match = lookup_mcp(source, name)
    if not match:
        return {
            "registry_match": "unknown",
            "trust_label": "unknown",
            "trust_score": None,
            "match": None,
        }

    verified = bool(match.get("verified", False))
    mcp_type = (match.get("type") or "").lower()
    label = _TYPE_TO_LABEL.get(mcp_type, "community" if not verified else "verified")

    # Coarse score: verified+official is highest; community lower.
    if verified and label == "verified":
        score: Optional[float] = 90.0
    elif label == "verified":
        score = 80.0
    elif label == "community":
        score = 50.0
    else:
        score = None

    return {
        "registry_match": "known",
        "trust_label": label,
        "trust_score": score,
        "match": match,
    }


__all__ = ["get_registry", "lookup_mcp", "trust_signals", "REGISTRY_HASH", "RegistryTamperWarning"]
