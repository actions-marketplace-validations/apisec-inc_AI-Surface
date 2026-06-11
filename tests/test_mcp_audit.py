"""Tests for the MCP deep-dive audit detector."""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from ai_surface.data.mcp import registry
from ai_surface.detectors.mcp_audit import McpAuditDetector
from ai_surface.types import (
    SEVERITY_CRITICAL,
    Audit,
    Finding,
    Secret,
)
from ai_surface.types import (
    CATEGORY_MCP_SERVER as MCP,
)


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


# --- Protocol / discovery ---------------------------------------------------- #


def test_detector_protocol_attributes() -> None:
    d = McpAuditDetector()
    assert d.name == "mcp_audit"
    assert d.category == MCP


def test_discovery_config_and_source(tmp_path: Path) -> None:
    """Both config-declared and in-house source servers are discovered."""
    _write(
        tmp_path / ".mcp.json",
        {"mcpServers": {"weather-mcp": {"command": "npx", "args": ["weather-mcp"]}}},
    )
    src = tmp_path / "server.py"
    src.write_text(
        "from mcp.server import FastMCP\n"
        "mcp = FastMCP('orders')\n"
        "@mcp.tool()\n"
        "def lookup_order(): ...\n",
        encoding="utf-8",
    )
    findings = McpAuditDetector().detect(str(tmp_path))
    surfaces = {f.surface for f in findings}
    assert "MCP Server: weather-mcp" in surfaces
    assert any(s.startswith("MCP Server (in-house): ") for s in surfaces)
    for f in findings:
        assert f.category == MCP
        # Every finding carries an audit (deep-dive layer).
        assert isinstance(f.audit, Audit)
        # Funnel layer fills bridges, not us.
        assert f.bridges == []


# --- Secret detection -------------------------------------------------------- #


def test_env_secret_yields_critical_flag_and_secret(tmp_path: Path) -> None:
    """A live Stripe key in env -> critical risk flag + Secret (name only)."""
    _write(
        tmp_path / ".mcp.json",
        {
            "mcpServers": {
                "stripe-mcp": {
                    "command": "npx",
                    "args": ["stripe-mcp"],
                    "env": {"STRIPE_SECRET_KEY": "sk_live_" + "a" * 30},
                }
            }
        },
    )
    findings = McpAuditDetector().detect(str(tmp_path))
    assert len(findings) == 1
    f = findings[0]
    assert f.surface == "MCP Server: stripe-mcp"
    assert f.audit is not None

    flags = {rf.flag: rf for rf in f.audit.risk_flags}
    assert "secrets-detected" in flags
    assert flags["secrets-detected"].severity == SEVERITY_CRITICAL
    # The weaker generic flag is replaced when a concrete secret is found.
    assert "secrets-in-env" not in flags

    # Exactly one Secret, carrying NAME/TYPE only.
    assert len(f.audit.secrets) == 1
    secret = f.audit.secrets[0]
    assert secret.name == "STRIPE_SECRET_KEY"
    assert secret.secret_type == "stripe_live"
    assert secret.severity == SEVERITY_CRITICAL
    assert secret.confidence == "high"
    assert secret.location == ".mcp.json:env"


def test_no_secret_value_anywhere_in_finding(tmp_path: Path) -> None:
    """Privacy guarantee: the secret value never appears in the serialized finding."""
    value = "sk_live_" + "z" * 40
    _write(
        tmp_path / ".mcp.json",
        {"mcpServers": {"pay": {"command": "npx", "args": ["pay"], "env": {"STRIPE_SECRET_KEY": value}}}},
    )
    findings = McpAuditDetector().detect(str(tmp_path))
    blob = json.dumps([dataclasses.asdict(f) for f in findings])
    assert value not in blob
    # Not even a masked fragment of the random body should leak.
    assert "z" * 8 not in blob
    # The Secret dataclass has no value-bearing field.
    assert not any(
        "value" in field.name.lower() for field in dataclasses.fields(Secret)
    )


def test_direct_string_value_secret_detected(tmp_path: Path) -> None:
    """Secrets hardcoded as direct config values (not in env) are caught."""
    _write(
        tmp_path / "mcp_servers" / "gh.json",
        {"name": "gh-mcp", "command": "node", "args": ["gh.js"], "githubToken": "ghp_" + "b" * 36},
    )
    findings = McpAuditDetector().detect(str(tmp_path))
    f = next(f for f in findings if f.surface == "MCP Server: gh-mcp")
    names = {s.name for s in f.audit.secrets}
    assert "githubToken" in names
    assert any(rf.flag == "secrets-detected" for rf in f.audit.risk_flags)


# --- OWASP + severity rollup ------------------------------------------------- #


def test_owasp_mappings_populate(tmp_path: Path) -> None:
    _write(
        tmp_path / ".mcp.json",
        {
            "mcpServers": {
                "stripe-mcp": {
                    "command": "npx",
                    "args": ["stripe-mcp"],
                    "env": {"STRIPE_SECRET_KEY": "sk_live_" + "c" * 30},
                    "tools": ["create_charge", "refund"],
                }
            }
        },
    )
    f = McpAuditDetector().detect(str(tmp_path))[0]
    # secrets -> LLM02/LLM07; financial-action -> LLM06.
    assert "LLM02" in f.audit.owasp_mappings
    assert "LLM07" in f.audit.owasp_mappings
    assert "LLM06" in f.audit.owasp_mappings
    # Per-flag owasp lists are populated too.
    sd = next(rf for rf in f.audit.risk_flags if rf.flag == "secrets-detected")
    assert sd.owasp == ["LLM02", "LLM07"]


def test_severity_rolls_up_to_max(tmp_path: Path) -> None:
    """Finding severity = max across risk flags (critical secret > high financial)."""
    _write(
        tmp_path / ".mcp.json",
        {
            "mcpServers": {
                "stripe-mcp": {
                    "command": "npx",
                    "args": ["stripe-mcp"],
                    "env": {"STRIPE_SECRET_KEY": "sk_live_" + "d" * 30},
                    "tools": ["refund"],
                }
            }
        },
    )
    f = McpAuditDetector().detect(str(tmp_path))[0]
    severities = {rf.severity for rf in f.audit.risk_flags}
    assert SEVERITY_CRITICAL in severities
    assert "high" in severities  # financial-action
    assert f.severity == SEVERITY_CRITICAL


# --- Clean MCP --------------------------------------------------------------- #


def test_clean_mcp_has_no_risk_flags(tmp_path: Path) -> None:
    """A benign read-only MCP with no secrets/financial tools has no flags."""
    _write(
        tmp_path / ".mcp.json",
        {
            "mcpServers": {
                "notes": {
                    "command": "npx",
                    "args": ["@modelcontextprotocol/server-notes"],
                    "tools": ["read_note"],
                }
            }
        },
    )
    f = McpAuditDetector().detect(str(tmp_path))[0]
    assert f.audit.risk_flags == []
    assert f.audit.secrets == []
    assert f.severity is None


def test_placeholder_value_is_not_a_secret(tmp_path: Path) -> None:
    """Placeholder env values must not be flagged as secrets."""
    _write(
        tmp_path / ".mcp.json",
        {
            "mcpServers": {
                "svc": {
                    "command": "npx",
                    "args": ["@modelcontextprotocol/server-svc"],
                    "env": {"API_KEY": "your-api-key-here"},
                }
            }
        },
    )
    f = McpAuditDetector().detect(str(tmp_path))[0]
    assert f.audit.secrets == []
    # secrets-in-env may flag on the key NAME, but no secrets-detected.
    assert not any(rf.flag == "secrets-detected" for rf in f.audit.risk_flags)


# --- Registry / trust -------------------------------------------------------- #


def test_known_registry_match_sets_trust(tmp_path: Path) -> None:
    """A package in the known registry yields a verified/known trust signal."""
    # Use a verified official package from the bundled registry.
    reg = registry.get_registry(skip_integrity_check=True)
    verified = next(m for m in reg["mcps"] if m.get("verified"))
    _write(
        tmp_path / ".mcp.json",
        {"mcpServers": {"fs": {"command": "npx", "args": [verified["package"]]}}},
    )
    f = McpAuditDetector().detect(str(tmp_path))[0]
    assert f.audit.registry_match == "known"
    assert f.audit.trust_label == "verified"
    assert f.audit.trust_score is not None


def test_unknown_source_is_unverified(tmp_path: Path) -> None:
    _write(
        tmp_path / ".mcp.json",
        {"mcpServers": {"randomthing": {"command": "npx", "args": ["totally-unknown-pkg"]}}},
    )
    f = McpAuditDetector().detect(str(tmp_path))[0]
    assert f.audit.registry_match == "unknown"
    assert f.audit.trust_label == "unknown"
    assert any(rf.flag == "unverified-source" for rf in f.audit.risk_flags)


def test_returns_empty_on_clean_tree(tmp_path: Path) -> None:
    (tmp_path / "readme.md").write_text("hello", encoding="utf-8")
    assert McpAuditDetector().detect(str(tmp_path)) == []
