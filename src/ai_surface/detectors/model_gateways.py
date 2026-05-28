"""Model gateway detector.

Gateways are the proxy/routing layers that sit in front of LLM providers.
Detected from configuration files (``litellm`` proxy ``config.yaml``,
``portkey-config.json``) and from source-level imports / URL references
(``portkey_ai``, ``helicone.ai``, ``gateway.ai.cloudflare.com``,
``openrouter.ai/api``).

Self-hosted runtimes and managed AI cloud resources (K8s, Helm, Terraform,
Dockerfiles, compose) are a separate concern handled by the ``ai_infra``
detector under ``CATEGORY_AI_INFRA``.

Each detected gateway produces exactly one :class:`Finding`, aggregated
across however many files reference it.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from ..types import CATEGORY_MODEL_GATEWAY, Evidence, Finding
from ..utils.specs import (
    SNIPPET_MAX,
    first_line_containing,
    first_match_line,
    head_snippet,
    parse_yaml_lenient,
)
from ..utils.walk import read_text_safe, relative_to_root, walk_files

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Gateway: source-level patterns
# ---------------------------------------------------------------------------

_PORTKEY_PATTERNS = (
    re.compile(r"\bfrom\s+portkey_ai\b"),
    re.compile(r"\bimport\s+portkey_ai\b"),
    re.compile(r"""['"]portkey-ai['"]"""),
    re.compile(r"\bPORTKEY_API_KEY\b"),
)
_HELICONE_PATTERNS = (
    re.compile(r"helicone(?:-proxy)?\.ai"),
    re.compile(r"\bHELICONE_API_KEY\b"),
    re.compile(r"""['"]Helicone-[A-Za-z0-9-]+['"]"""),
)
_CLOUDFLARE_PATTERNS = (
    re.compile(r"gateway\.ai\.cloudflare\.com"),
    # Cloudflare Workers AI binding in wrangler config (TOML/JSON).
    # The body length is bounded to defend against catastrophic backtracking
    # on adversarial input containing many `[ai]` headers and no `binding=`.
    re.compile(r"""\[ai\][^\[]{0,4096}?binding\s*=\s*['"][^'"]+['"]""", re.DOTALL),
    re.compile(r"""['"]ai['"]\s*:\s*\{\s*['"]binding['"]"""),
)
_OPENROUTER_PATTERNS = (
    re.compile(r"openrouter\.ai/api"),
    re.compile(r"\bOPENROUTER_API_KEY\b"),
)
_LITELLM_PROXY_SOURCE_PATTERNS = (
    re.compile(r"\bfrom\s+litellm\.proxy\b"),
    re.compile(r"\blitellm_proxy\b"),
)

_SOURCE_EXTENSIONS = (
    ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".toml", ".json",
)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class ModelGatewayDetector:
    """Detect production model gateways (proxy / routing layers)."""

    name = "model_gateways"
    category = CATEGORY_MODEL_GATEWAY

    def detect(self, root_path: str) -> list[Finding]:
        findings: list[Finding] = []

        # Per-gateway accumulators so each gateway is one Finding even if it
        # appears in multiple files.
        gateway_acc: dict[str, dict[str, Any]] = {}

        # Pass 1: YAML / JSON config (litellm proxy, portkey config).
        for path in walk_files(root_path, extensions=[".yaml", ".yml", ".json"]):
            text = read_text_safe(path)
            if not text:
                continue
            rel = relative_to_root(path, root_path)

            litellm_models = _parse_litellm_proxy(text, path)
            if litellm_models is not None:
                _accumulate_gateway(
                    gateway_acc,
                    key="LiteLLM",
                    rel=rel,
                    snippet=first_line_containing(text, "model_list"),
                    extra_models=litellm_models,
                )

            if path.name in {"portkey-config.json", "portkey.json"}:
                _accumulate_gateway(
                    gateway_acc,
                    key="Portkey",
                    rel=rel,
                    snippet=head_snippet(text),
                )

        # Pass 2: source files for gateway imports / URL refs and litellm proxy.
        for path in walk_files(root_path, extensions=list(_SOURCE_EXTENSIONS)):
            text = read_text_safe(path)
            if not text:
                continue
            rel = relative_to_root(path, root_path)

            if any(p.search(text) for p in _PORTKEY_PATTERNS):
                _accumulate_gateway(
                    gateway_acc,
                    key="Portkey",
                    rel=rel,
                    snippet=first_match_line(_PORTKEY_PATTERNS, text),
                )
            if any(p.search(text) for p in _HELICONE_PATTERNS):
                _accumulate_gateway(
                    gateway_acc,
                    key="Helicone",
                    rel=rel,
                    snippet=first_match_line(_HELICONE_PATTERNS, text),
                )
            if any(p.search(text) for p in _CLOUDFLARE_PATTERNS):
                _accumulate_gateway(
                    gateway_acc,
                    key="Cloudflare AI Gateway",
                    rel=rel,
                    snippet=first_match_line(_CLOUDFLARE_PATTERNS, text),
                )
            if any(p.search(text) for p in _OPENROUTER_PATTERNS):
                _accumulate_gateway(
                    gateway_acc,
                    key="OpenRouter",
                    rel=rel,
                    snippet=first_match_line(_OPENROUTER_PATTERNS, text),
                )
            if any(p.search(text) for p in _LITELLM_PROXY_SOURCE_PATTERNS):
                _accumulate_gateway(
                    gateway_acc,
                    key="LiteLLM",
                    rel=rel,
                    snippet=first_match_line(_LITELLM_PROXY_SOURCE_PATTERNS, text),
                )

        for gw_key, acc in gateway_acc.items():
            findings.append(_finding_from_gateway(gw_key, acc))

        return findings


# ---------------------------------------------------------------------------
# Gateway accumulators
# ---------------------------------------------------------------------------


def _accumulate_gateway(
    acc: dict[str, dict[str, Any]],
    *,
    key: str,
    rel: str,
    snippet: str,
    extra_models: list[str] | None = None,
) -> None:
    bucket = acc.setdefault(key, {"files": [], "snippet": "", "models": []})
    if rel not in bucket["files"]:
        bucket["files"].append(rel)
    if not bucket["snippet"] and snippet:
        bucket["snippet"] = snippet[:SNIPPET_MAX]
    if extra_models:
        for m in extra_models:
            if m not in bucket["models"]:
                bucket["models"].append(m)


def _finding_from_gateway(key: str, acc: dict[str, Any]) -> Finding:
    files = sorted(set(acc["files"]))
    metadata: dict[str, Any] = {"gateway": key}
    permissions: list[str] = []
    if key == "LiteLLM" and acc.get("models"):
        metadata["models_routed"] = list(acc["models"])
        permissions = list(acc["models"])
    return Finding(
        surface=f"Model Gateway: {key}",
        category=CATEGORY_MODEL_GATEWAY,
        evidence=Evidence(
            files=files,
            snippet=acc.get("snippet", "")[:SNIPPET_MAX],
            metadata=metadata,
        ),
        permissions=permissions,
        risk_indicators=[
            "multi-model routing layer (production traffic flows through this)"
        ],
    )


# ---------------------------------------------------------------------------
# LiteLLM proxy config parsing
# ---------------------------------------------------------------------------


def _parse_litellm_proxy(text: str, path: Path) -> list[str] | None:
    """Return the list of model names if the YAML looks like a LiteLLM proxy config.

    Only YAML files (``*.yaml`` / ``*.yml``) are considered, and only when the
    file references both ``model_list`` and either ``litellm_params`` or
    ``litellm_settings``. Returns an empty list (truthy ``is not None``) if
    the config is recognised but no model names were extracted.
    """
    if path.suffix.lower() not in {".yaml", ".yml"}:
        return None
    if "model_list" not in text:
        return None
    if "litellm_params" not in text and "litellm_settings" not in text:
        return None

    parsed = parse_yaml_lenient(text)
    models: list[str] = []
    if isinstance(parsed, dict):
        ml = parsed.get("model_list")
        if isinstance(ml, list):
            for entry in ml:
                if isinstance(entry, dict):
                    name = entry.get("model_name") or entry.get("name")
                    if isinstance(name, (str, int)) and str(name).strip():
                        models.append(str(name))
    if not models:
        # Fallback: regex pull `- model_name: NAME` entries.
        for m in re.finditer(
            r"^\s*-?\s*model_name\s*:\s*['\"]?([^'\"\n#]+)", text, re.MULTILINE
        ):
            cand = m.group(1).strip()
            if cand and cand not in models:
                models.append(cand)
    return models


__all__ = ["ModelGatewayDetector"]
