"""Secret detection patterns for MCP configurations.

Ported from mcp-audit (``mcp_audit/data/secret_patterns.py``) with one
deliberate privacy hardening: ``detect_secrets`` here NEVER returns the secret
value, nor a masked form of it. Only the variable NAME (``env_key``), the
classified ``type``, ``severity``, ``confidence`` and a static ``description``
leave this module. The matched value is used transiently for classification
and then discarded. This upholds ai-surface's privacy guarantee that no
secret value ever enters a report.

All content is static; no network access.
"""
from __future__ import annotations

import re
from typing import Any

# Common placeholders that aren't real secrets and must be skipped.
PLACEHOLDER_PATTERNS = [
    r"^xxx+$",
    r"^your[_-]?(api[_-]?key|token|secret|password).*$",
    r"^changeme$",
    r"^replace[_-]?me$",
    r"^todo$",
    r"^fixme$",
    r"^example$",
    r"^test$",
    r"^dummy$",
    r"^fake$",
    r"^\*+$",
    r"^<.*>$",  # <your-api-key>
    r"^\[.*\]$",  # [your-api-key]
    r"^\{.*\}$",  # {your-api-key}
    r"^sk_test_",  # Stripe test keys are lower risk
    r"^pk_test_",  # Stripe test public keys
]

# Secret detection patterns. ``severity`` values use ai-surface SEVERITY_*
# vocabulary (critical|high|medium|low). ``requires_context`` patterns only
# fire when the variable name contains one of ``context_keys``.
SECRET_PATTERNS: dict[str, dict[str, Any]] = {
    # AWS
    "aws_access_key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "description": "AWS Access Key ID",
        "severity": "critical",
    },
    "aws_secret_key": {
        "pattern": r"(?<![A-Za-z0-9/+=])[0-9a-zA-Z/+]{40}(?![A-Za-z0-9/+=])",
        "context_keys": ["AWS_SECRET", "SECRET_KEY", "SECRET_ACCESS"],
        "description": "AWS Secret Access Key",
        "severity": "critical",
        "requires_context": True,
    },
    # GitHub
    "github_pat": {
        "pattern": r"ghp_[0-9a-zA-Z]{36}",
        "description": "GitHub Personal Access Token",
        "severity": "critical",
    },
    "github_oauth": {
        "pattern": r"gho_[0-9a-zA-Z]{36}",
        "description": "GitHub OAuth Access Token",
        "severity": "critical",
    },
    "github_app": {
        "pattern": r"gh[us]_[0-9a-zA-Z]{36}",
        "description": "GitHub App Token",
        "severity": "critical",
    },
    # Stripe
    "stripe_live": {
        "pattern": r"sk_live_[0-9a-zA-Z]{24,}",
        "description": "Stripe Live Secret Key",
        "severity": "critical",
    },
    "stripe_restricted": {
        "pattern": r"rk_live_[0-9a-zA-Z]{24,}",
        "description": "Stripe Restricted API Key",
        "severity": "high",
    },
    # Slack
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9a-zA-Z-]{10,}",
        "description": "Slack Token",
        "severity": "high",
    },
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+",
        "description": "Slack Webhook URL",
        "severity": "medium",
    },
    # OpenAI
    "openai_project_key": {
        "pattern": r"sk-proj-[0-9a-zA-Z_-]{20,}",
        "description": "OpenAI Project API Key",
        "severity": "high",
    },
    "openai_key": {
        "pattern": r"sk-[0-9a-zA-Z]{20,}",
        "description": "OpenAI API Key",
        "severity": "high",
    },
    # Anthropic
    "anthropic_key": {
        "pattern": r"sk-ant-[0-9a-zA-Z-]{40,}",
        "description": "Anthropic API Key",
        "severity": "high",
    },
    # Google
    "google_api_key": {
        "pattern": r"AIza[0-9A-Za-z-_]{35}",
        "description": "Google API Key",
        "severity": "high",
    },
    "google_oauth": {
        "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        "description": "Google OAuth Client ID",
        "severity": "medium",
    },
    # Salesforce
    "salesforce_token": {
        "pattern": r"[0-9A-Za-z]{24,}",
        "context_keys": ["SF_ACCESS_TOKEN", "SALESFORCE_TOKEN", "SFDC_TOKEN", "SF_TOKEN"],
        "description": "Salesforce Access Token",
        "severity": "high",
        "requires_context": True,
    },
    # Database connection strings
    "postgres_conn": {
        "pattern": r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\w+",
        "description": "PostgreSQL Connection String with Credentials",
        "severity": "critical",
    },
    "mysql_conn": {
        "pattern": r"mysql://[^:]+:[^@]+@[^/]+/\w+",
        "description": "MySQL Connection String with Credentials",
        "severity": "critical",
    },
    "mongodb_conn": {
        "pattern": r"mongodb(?:\+srv)?://[^:]+:[^@]+@",
        "description": "MongoDB Connection String with Credentials",
        "severity": "critical",
    },
    "redis_conn": {
        "pattern": r"redis://[^:]+:[^@]+@",
        "description": "Redis Connection String with Credentials",
        "severity": "high",
    },
    # Private keys
    "private_key": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        "description": "Private Key",
        "severity": "critical",
    },
    # SendGrid
    "sendgrid_key": {
        "pattern": r"SG\.[0-9A-Za-z-_]{22}\.[0-9A-Za-z-_]{43}",
        "description": "SendGrid API Key",
        "severity": "high",
    },
    # Twilio
    "twilio_key": {
        "pattern": r"SK[0-9a-fA-F]{32}",
        "description": "Twilio API Key",
        "severity": "high",
    },
    # Mailchimp
    "mailchimp_key": {
        "pattern": r"[0-9a-f]{32}-us[0-9]{1,2}",
        "description": "Mailchimp API Key",
        "severity": "medium",
    },
    # Discord
    "discord_token": {
        "pattern": r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
        "description": "Discord Bot Token",
        "severity": "high",
    },
    "discord_webhook": {
        "pattern": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
        "description": "Discord Webhook URL",
        "severity": "medium",
    },
    # NPM
    "npm_token": {
        "pattern": r"npm_[A-Za-z0-9]{36}",
        "description": "NPM Access Token",
        "severity": "high",
    },
    # PyPI
    "pypi_token": {
        "pattern": r"pypi-[A-Za-z0-9_-]{50,}",
        "description": "PyPI API Token",
        "severity": "high",
    },
    # Heroku
    "heroku_key": {
        "pattern": (
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        ),
        "context_keys": ["HEROKU_API_KEY", "HEROKU_TOKEN"],
        "description": "Heroku API Key",
        "severity": "high",
        "requires_context": True,
    },
    # Generic patterns (lower confidence, need context)
    "generic_api_key": {
        "pattern": r"[0-9a-zA-Z]{32,}",
        "context_keys": ["API_KEY", "APIKEY", "API_SECRET", "SECRET_KEY", "ACCESS_KEY"],
        "description": "Potential API Key",
        "severity": "medium",
        "requires_context": True,
    },
    "generic_password": {
        "pattern": r".{8,}",
        "context_keys": ["PASSWORD", "PASSWD", "PWD", "DB_PASS", "DB_PASSWORD"],
        "description": "Password",
        "severity": "high",
        "requires_context": True,
    },
    "generic_token": {
        "pattern": r"[0-9a-zA-Z_-]{20,}",
        "context_keys": ["TOKEN", "AUTH_TOKEN", "ACCESS_TOKEN", "BEARER", "JWT"],
        "description": "Authentication Token",
        "severity": "high",
        "requires_context": True,
    },
}

_PLACEHOLDER_COMPILED = [re.compile(p, re.IGNORECASE) for p in PLACEHOLDER_PATTERNS]


def is_placeholder(value: str) -> bool:
    """Return True if ``value`` is a common placeholder, not a real secret."""
    value_lower = value.lower().strip()
    return any(p.match(value_lower) for p in _PLACEHOLDER_COMPILED)


def detect_secrets(
    env_dict: dict[str, Any],
    config_path: str | None = None,
    mcp_name: str | None = None,
) -> list[dict[str, Any]]:
    """Detect secrets in MCP environment variables.

    Privacy: the returned dicts contain the variable NAME (``env_key``) and a
    classification only. The secret value is never returned, masked or
    otherwise. Values are matched in memory and discarded.

    Args:
        env_dict: variable name -> value mapping from an MCP config.
        config_path: optional source path, echoed back for location display.
        mcp_name: optional MCP server name, echoed back for context.

    Returns:
        A list of metadata dicts, one per detected secret.
    """
    secrets: list[dict[str, Any]] = []

    if not env_dict or not isinstance(env_dict, dict):
        return secrets

    for key, value in env_dict.items():
        if not isinstance(value, str):
            continue
        # Skip empty or very short values.
        if len(value) < 8:
            continue
        # Skip placeholders.
        if is_placeholder(value):
            continue
        # Skip environment-variable references (e.g. "$FOO", "${FOO}").
        if value.startswith("$") or value.startswith("${"):
            continue

        for secret_type, config in SECRET_PATTERNS.items():
            pattern = config["pattern"]
            context_keys = config.get("context_keys", [])
            requires_context = config.get("requires_context", False)

            try:
                match = re.search(pattern, value)
            except re.error:
                continue
            if not match:
                continue

            # For generic/contextual patterns, require key context.
            if requires_context:
                key_upper = key.upper()
                if not any(ctx.upper() in key_upper for ctx in context_keys):
                    continue

            confidence = "high"
            if requires_context:
                confidence = "medium"
            if secret_type.startswith("generic_"):
                confidence = "medium"

            secrets.append(
                {
                    "type": secret_type,
                    "description": config["description"],
                    "severity": config["severity"],
                    "env_key": key,
                    "confidence": confidence,
                    "config_path": config_path,
                    "mcp_name": mcp_name,
                }
            )
            # Don't double-count the same value against multiple patterns.
            break

    return secrets


__all__ = ["SECRET_PATTERNS", "PLACEHOLDER_PATTERNS", "is_placeholder", "detect_secrets"]
