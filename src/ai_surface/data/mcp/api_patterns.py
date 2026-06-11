"""
API endpoint detection patterns for MCP configurations.

This module contains patterns for detecting and categorizing
API endpoints that MCPs are configured to access.
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class DetectedAPI:
    """Represents a detected API endpoint"""
    url: str
    category: str  # database, rest_api, websocket, sse, saas, cloud
    description: str
    source: str    # env_var, config_field, args
    source_key: str  # The specific key (e.g., "POSTGRES_URL")
    mcp_name: str
    masked_url: str  # URL with credentials masked

    def to_dict(self) -> dict:
        return {
            "url": self.masked_url,  # Always use masked in output
            "category": self.category,
            "description": self.description,
            "source": self.source,
            "source_key": self.source_key,
            "mcp_name": self.mcp_name,
        }


# URL patterns for specific services (checked first for accurate categorization)
SERVICE_PATTERNS = {
    # Databases
    "postgresql": {
        "pattern": r"postgres(?:ql)?://[^\s\"']+",
        "category": "database",
        "description": "PostgreSQL Database",
    },
    "mysql": {
        "pattern": r"mysql://[^\s\"']+",
        "category": "database",
        "description": "MySQL Database",
    },
    "mongodb": {
        "pattern": r"mongodb(?:\+srv)?://[^\s\"']+",
        "category": "database",
        "description": "MongoDB Database",
    },
    "redis": {
        "pattern": r"redis://[^\s\"']+",
        "category": "database",
        "description": "Redis Cache",
    },
    "sqlite": {
        "pattern": r"sqlite:(?://)?[^\s\"']+",
        "category": "database",
        "description": "SQLite Database",
    },
    # WebSocket
    "websocket": {
        "pattern": r"wss?://[^\s\"']+",
        "category": "websocket",
        "description": "WebSocket Connection",
    },
    # Known SaaS endpoints
    "slack_api": {
        "pattern": r"https?://(?:api\.)?slack\.com[^\s\"']*",
        "category": "saas",
        "description": "Slack API",
    },
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/[^\s\"']+",
        "category": "saas",
        "description": "Slack Webhook",
    },
    "github_api": {
        "pattern": r"https?://(?:api\.)?github\.com[^\s\"']*",
        "category": "saas",
        "description": "GitHub API",
    },
    "github_mcp": {
        "pattern": r"https?://mcp\.github\.com[^\s\"']*",
        "category": "sse",
        "description": "GitHub MCP (SSE)",
    },
    "linear_api": {
        "pattern": r"https?://(?:api\.)?linear\.app[^\s\"']*",
        "category": "saas",
        "description": "Linear API",
    },
    "linear_mcp": {
        "pattern": r"https?://mcp\.linear\.app[^\s\"']*",
        "category": "sse",
        "description": "Linear MCP (SSE)",
    },
    "asana_mcp": {
        "pattern": r"https?://mcp\.asana\.com[^\s\"']*",
        "category": "sse",
        "description": "Asana MCP (SSE)",
    },
    "discord_api": {
        "pattern": r"https?://(?:discord\.com|discordapp\.com)/api[^\s\"']*",
        "category": "saas",
        "description": "Discord API",
    },
    "discord_webhook": {
        "pattern": r"https?://(?:discord\.com|discordapp\.com)/api/webhooks[^\s\"']+",
        "category": "saas",
        "description": "Discord Webhook",
    },
    "openai_api": {
        "pattern": r"https?://api\.openai\.com[^\s\"']*",
        "category": "saas",
        "description": "OpenAI API",
    },
    "anthropic_api": {
        "pattern": r"https?://api\.anthropic\.com[^\s\"']*",
        "category": "saas",
        "description": "Anthropic API",
    },
    # Cloud providers
    "aws_s3": {
        "pattern": r"https?://[^/]*\.s3\.amazonaws\.com[^\s\"']*",
        "category": "cloud",
        "description": "AWS S3",
    },
    "aws_api": {
        "pattern": r"https?://[^/]*\.amazonaws\.com[^\s\"']*",
        "category": "cloud",
        "description": "AWS API",
    },
    "gcp_api": {
        "pattern": r"https?://[^/]*\.googleapis\.com[^\s\"']*",
        "category": "cloud",
        "description": "Google Cloud API",
    },
    "azure_api": {
        "pattern": r"https?://[^/]*\.azure\.com[^\s\"']*",
        "category": "cloud",
        "description": "Azure API",
    },
    # Generic SSE (must contain /sse path)
    "sse_endpoint": {
        "pattern": r"https?://[^\s\"']+/sse[^\s\"']*",
        "category": "sse",
        "description": "SSE Endpoint",
    },
}

# Fallback pattern for generic HTTP/HTTPS URLs
GENERIC_HTTP_PATTERN = r"https?://[^\s\"']+"

# Environment variable key patterns that likely contain URLs
ENV_KEY_PATTERNS = [
    "_URL",
    "_ENDPOINT",
    "_HOST",
    "_API",
    "_URI",
    "_SERVER",
    "_BASE",
    "_WEBHOOK",
    "_CONNECTION",
]

# Config field names that typically contain URLs
CONFIG_URL_FIELDS = [
    "url",
    "serverUrl",
    "endpoint",
    "baseUrl",
    "uri",
    "host",
    "server",
    "apiUrl",
    "apiEndpoint",
    "webhookUrl",
    "connectionString",
]


def mask_url_credentials(url: str) -> str:
    """
    Mask credentials in a URL for safe display.
    postgresql://user:password@host -> postgresql://****:****@host
    """
    # Pattern to match credentials in URL
    cred_pattern = r"(://[^:]+:)([^@]+)(@)"
    masked = re.sub(cred_pattern, r"\1****\3", url)

    # Also mask user part if present
    user_pattern = r"(://)([^:@]+)(:)"
    masked = re.sub(user_pattern, r"\1****\3", masked)

    return masked


def classify_url(url: str) -> tuple[str, str]:
    """
    Classify a URL and return (category, description).
    Checks specific service patterns first, then falls back to generic.
    """
    url_lower = url.lower()

    # Check specific service patterns first
    for _service_name, config in SERVICE_PATTERNS.items():
        if re.search(config["pattern"], url, re.IGNORECASE):
            return config["category"], config["description"]

    # Generic HTTP/HTTPS
    if url_lower.startswith("http://") or url_lower.startswith("https://"):
        return "rest_api", "HTTP API Endpoint"

    return "unknown", "Unknown Endpoint"


def detect_apis(
    raw_config: dict,
    args: list,
    mcp_name: str,
    env: Optional[dict] = None
) -> list[DetectedAPI]:
    """
    Detect API endpoints from MCP configuration.

    Args:
        raw_config: The raw MCP configuration dict
        args: Command arguments list
        mcp_name: Name of the MCP
        env: Environment variables dict (if separate from raw_config)

    Returns:
        List of DetectedAPI objects
    """
    apis = []
    seen_urls = set()  # Avoid duplicates

    # Get env from raw_config if not provided separately
    if env is None:
        env = raw_config.get("env", {}) if raw_config else {}

    # 1. Check environment variables
    if env and isinstance(env, dict):
        for key, value in env.items():
            if not isinstance(value, str) or len(value) < 8:
                continue

            # Skip env var references
            if value.startswith("$") or value.startswith("${"):
                continue

            # Check if key suggests it's a URL
            key_upper = key.upper()
            any(pattern in key_upper for pattern in ENV_KEY_PATTERNS)

            # Try to find URLs in the value
            urls_found = _extract_urls(value)

            for url in urls_found:
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                category, description = classify_url(url)
                apis.append(DetectedAPI(
                    url=url,
                    category=category,
                    description=description,
                    source="env_var",
                    source_key=key,
                    mcp_name=mcp_name,
                    masked_url=mask_url_credentials(url),
                ))

    # 2. Check config fields for URL-like values
    if raw_config and isinstance(raw_config, dict):
        for field in CONFIG_URL_FIELDS:
            value = raw_config.get(field)
            if not value or not isinstance(value, str):
                continue

            urls_found = _extract_urls(value)
            for url in urls_found:
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                category, description = classify_url(url)
                apis.append(DetectedAPI(
                    url=url,
                    category=category,
                    description=description,
                    source="config_field",
                    source_key=field,
                    mcp_name=mcp_name,
                    masked_url=mask_url_credentials(url),
                ))

    # 3. Check command args for URLs
    if args and isinstance(args, list):
        for i, arg in enumerate(args):
            if not isinstance(arg, str) or len(arg) < 8:
                continue

            urls_found = _extract_urls(arg)
            for url in urls_found:
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                category, description = classify_url(url)
                apis.append(DetectedAPI(
                    url=url,
                    category=category,
                    description=description,
                    source="args",
                    source_key=f"args[{i}]",
                    mcp_name=mcp_name,
                    masked_url=mask_url_credentials(url),
                ))

    return apis


def _extract_urls(text: str) -> list[str]:
    """Extract all URLs from a text string."""
    urls = []

    # Check specific patterns first
    for _service_name, config in SERVICE_PATTERNS.items():
        matches = re.findall(config["pattern"], text, re.IGNORECASE)
        urls.extend(matches)

    # Then check generic HTTP/HTTPS
    http_matches = re.findall(GENERIC_HTTP_PATTERN, text, re.IGNORECASE)
    for url in http_matches:
        if url not in urls:
            urls.append(url)

    return urls


# Category display names and icons
CATEGORY_INFO = {
    "database": {"name": "Database", "icon": "🗄️"},
    "rest_api": {"name": "REST API", "icon": "🌐"},
    "websocket": {"name": "WebSocket", "icon": "🔌"},
    "sse": {"name": "SSE", "icon": "📡"},
    "saas": {"name": "SaaS", "icon": "☁️"},
    "cloud": {"name": "Cloud", "icon": "🏢"},
    "unknown": {"name": "Other", "icon": "❓"},
}


def get_category_display(category: str) -> tuple[str, str]:
    """Get display name and icon for a category."""
    info = CATEGORY_INFO.get(category, CATEGORY_INFO["unknown"])
    return info["name"], info["icon"]
