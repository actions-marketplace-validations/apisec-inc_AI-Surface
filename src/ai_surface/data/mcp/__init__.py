"""MCP audit static data, ported from mcp-audit.

Four modules, all offline and deterministic:

* :mod:`secret_patterns` - regex/context patterns for credential detection
* :mod:`risk_definitions` - risk-flag severities + remediation guidance
* :mod:`owasp_llm` - OWASP LLM Top 10 (2025) mappings for MCP findings
* :mod:`registry` - lookup against the bundled known-MCP registry

The ai-surface ``mcp_audit`` detector consumes these to attach a populated
``Audit`` block to MCP discovery findings.
"""
