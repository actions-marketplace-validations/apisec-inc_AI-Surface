"""Tests for the MCP server detector."""
from __future__ import annotations

import json
from pathlib import Path

from ai_surface.detectors.mcp_servers import McpServerDetector
from ai_surface.types import CATEGORY_MCP_SERVER

FIXTURES = Path(__file__).parent / "fixtures" / "mcp"


# --- Config-file detection ---------------------------------------------------


def test_config_fixture_yields_two_findings() -> None:
    """The bundled fixture has one mcp.json declaring 2 servers."""
    findings = McpServerDetector().detect(str(FIXTURES / "with_config"))
    assert len(findings) == 2
    surfaces = {f.surface for f in findings}
    assert surfaces == {"MCP Server: github-mcp", "MCP Server: weather-mcp"}
    for f in findings:
        assert f.category == CATEGORY_MCP_SERVER
        assert f.evidence.files == ["mcp.json"]


def test_config_broad_permissions_flagged() -> None:
    findings = McpServerDetector().detect(str(FIXTURES / "with_config"))
    by_name = {f.surface: f for f in findings}
    gh = by_name["MCP Server: github-mcp"]
    assert "broad permissions" in gh.risk_indicators
    assert "admin" in gh.permissions
    assert "write" in gh.permissions

    weather = by_name["MCP Server: weather-mcp"]
    assert "broad permissions" not in weather.risk_indicators
    assert weather.permissions == ["read"]


def test_dot_mcp_json_at_root_is_detected(tmp_path: Path) -> None:
    """Detect ``.mcp.json`` at the repo root (the canonical name)."""
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "stripe-mcp": {"capabilities": ["delete", "write"]},
                }
            }
        ),
        encoding="utf-8",
    )
    findings = McpServerDetector().detect(str(tmp_path))
    assert len(findings) == 1
    assert findings[0].surface == "MCP Server: stripe-mcp"
    assert "broad permissions" in findings[0].risk_indicators


def test_config_under_config_dir(tmp_path: Path) -> None:
    """``config/mcp.json`` is recognised, but a deeply nested config is not."""
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "mcp.json").write_text(
        json.dumps({"mcpServers": {"alpha": {"capabilities": ["read"]}}}),
        encoding="utf-8",
    )
    # Decoy: nested mcp.json at random path is ignored.
    deep = tmp_path / "src" / "nested" / "vendor"
    deep.mkdir(parents=True)
    (deep / "mcp.json").write_text(
        json.dumps({"mcpServers": {"ignored": {}}}),
        encoding="utf-8",
    )

    findings = McpServerDetector().detect(str(tmp_path))
    assert len(findings) == 1
    assert findings[0].surface == "MCP Server: alpha"


def test_per_server_files_under_mcp_servers(tmp_path: Path) -> None:
    """Files under ``mcp_servers/`` should each become a finding."""
    d = tmp_path / "mcp_servers"
    d.mkdir()
    (d / "billing.json").write_text(
        json.dumps({"name": "billing-mcp", "tools": ["create_invoice", "refund_charge"]}),
        encoding="utf-8",
    )
    (d / "search.json").write_text(
        json.dumps({"name": "search-mcp", "capabilities": ["read"]}),
        encoding="utf-8",
    )
    findings = McpServerDetector().detect(str(tmp_path))
    surfaces = sorted(f.surface for f in findings)
    assert surfaces == ["MCP Server: billing-mcp", "MCP Server: search-mcp"]

    billing = next(f for f in findings if "billing" in f.surface)
    assert "financial action exposed" in billing.risk_indicators
    assert "refund_charge" in billing.permissions


def test_malformed_json_is_skipped(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text("{not valid json", encoding="utf-8")
    findings = McpServerDetector().detect(str(tmp_path))
    assert findings == []


def test_servers_array_shape(tmp_path: Path) -> None:
    (tmp_path / "mcp.json").write_text(
        json.dumps(
            {
                "servers": [
                    {"name": "a", "capabilities": ["read"]},
                    {"name": "b", "capabilities": ["admin"]},
                ]
            }
        ),
        encoding="utf-8",
    )
    findings = McpServerDetector().detect(str(tmp_path))
    surfaces = sorted(f.surface for f in findings)
    assert surfaces == ["MCP Server: a", "MCP Server: b"]


# --- Source-file detection ---------------------------------------------------


def test_python_in_house_server_detected() -> None:
    findings = McpServerDetector().detect(str(FIXTURES / "with_source"))
    assert len(findings) == 1
    f = findings[0]
    assert f.surface.startswith("MCP Server (in-house): ")
    assert f.surface.endswith("mcp_orders_server.py")
    assert f.category == CATEGORY_MCP_SERVER

    # Tool decorators populate permissions
    assert set(f.permissions) >= {"lookup_order", "refund_payment", "cancel_order"}

    # Risk indicators
    assert "in-house MCP server (custom code, audit recommended)" in f.risk_indicators
    assert "financial action exposed" in f.risk_indicators


def test_typescript_in_house_server_detected(tmp_path: Path) -> None:
    src = tmp_path / "server.ts"
    src.write_text(
        """
        import { Server } from "@modelcontextprotocol/sdk/server/index.js";
        const server = new Server({ name: "ts-mcp" }, { capabilities: {} });
        server.tool("list_users", async (req) => { return []; });
        server.tool("delete_user", async (req) => { return {}; });
        """.strip(),
        encoding="utf-8",
    )
    findings = McpServerDetector().detect(str(tmp_path))
    assert len(findings) == 1
    f = findings[0]
    assert "server.ts" in f.surface
    assert set(f.permissions) == {"list_users", "delete_user"}
    assert "in-house MCP server (custom code, audit recommended)" in f.risk_indicators


def test_negative_case_no_findings() -> None:
    findings = McpServerDetector().detect(str(FIXTURES / "empty"))
    assert findings == []


def test_python_file_without_mcp_token_is_skipped(tmp_path: Path) -> None:
    """A Python file that mentions Server() but isn't MCP shouldn't trip us."""
    (tmp_path / "http_server.py").write_text(
        "from http.server import HTTPServer\nServer = HTTPServer\n",
        encoding="utf-8",
    )
    findings = McpServerDetector().detect(str(tmp_path))
    assert findings == []


def test_detector_protocol_attributes() -> None:
    d = McpServerDetector()
    assert d.name == "mcp-servers"
    assert d.category == CATEGORY_MCP_SERVER
