"""Model gateway and AI infrastructure detector.

Two related but distinct surface families:

1. **Model gateways** (``CATEGORY_MODEL_GATEWAY``) — proxies/routers that sit
   in front of LLM providers. Detected from configuration files
   (``litellm`` proxy ``config.yaml``, ``portkey-config.json``) and from
   source-level imports / URL references (``portkey_ai``, ``helicone.ai``,
   ``gateway.ai.cloudflare.com``, ``openrouter.ai/api``).

2. **AI infrastructure** (``CATEGORY_AI_INFRA``) — self-hosted AI runtimes
   declared in deployment specs: K8s ``Deployment`` / ``StatefulSet``
   manifests, Helm ``values.yaml`` images, and Terraform resources for
   Bedrock provisioned throughput, custom Bedrock models, SageMaker LLM
   endpoints, and Vertex AI endpoints.

Each detected surface produces exactly one :class:`Finding`. PyYAML is used
when available; a tiny fallback parser handles synthetic test fixtures.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from ..types import CATEGORY_AI_INFRA, CATEGORY_MODEL_GATEWAY, Evidence, Finding
from ..utils.walk import read_text_safe, relative_to_root, walk_files

log = logging.getLogger(__name__)


_SNIPPET_MAX = 200

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
    re.compile(r"""\[ai\][^\[]*?binding\s*=\s*['"][^'"]+['"]""", re.DOTALL),
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
# AI Infra: image and resource patterns
# ---------------------------------------------------------------------------

# Image substrings that signify a self-hosted AI runtime.
# Each tuple: (substring, short_name).
_AI_IMAGE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("ollama/ollama", "ollama"),
    ("vllm/vllm-openai", "vllm-openai"),
    ("huggingface/text-generation-inference", "text-generation-inference"),
    ("lmsys/fastchat", "fastchat"),
    ("langchain/", "langchain"),
    ("crewai/", "crewai"),
    ("xinference", "xinference"),
)

# Terraform AI resources we care about.
_TF_RESOURCE_RE = re.compile(
    r"""resource\s+"(?P<type>[a-zA-Z0-9_]+)"\s+"(?P<name>[a-zA-Z0-9_-]+)"\s*\{(?P<body>[^}]*)\}""",
    re.DOTALL,
)
_TF_AI_RESOURCE_TYPES = {
    "aws_bedrock_provisioned_model_throughput": (
        "Bedrock provisioned throughput",
        "high-cost AI infrastructure (billing exposure)",
    ),
    "aws_bedrock_custom_model": (
        "Bedrock custom model",
        "high-cost AI infrastructure (billing exposure)",
    ),
    "aws_sagemaker_endpoint": (
        "SageMaker endpoint",
        "high-cost AI infrastructure (billing exposure)",
    ),
    "google_vertex_ai_endpoint": (
        "Vertex AI endpoint",
        "high-cost AI infrastructure (billing exposure)",
    ),
}

# Bedrock-style model id: provider.modelname-... (e.g. anthropic.claude-3-5-sonnet)
_BEDROCK_MODEL_ID_RE = re.compile(
    r"""(?:anthropic|amazon|meta|mistral|cohere|ai21|stability)\.[a-zA-Z0-9._:-]+"""
)
# A SageMaker endpoint is interesting only when the model name looks LLM-shaped.
_LLM_HINT_RE = re.compile(
    r"""(claude|llama|mistral|mixtral|gpt|gemini|cohere|command|titan|nova|falcon|qwen|phi|deepseek)""",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class ModelGatewayDetector:
    """Detect production model gateways and self-hosted AI infrastructure."""

    name = "model_gateways"
    # Reported category varies per finding; class-level attr is informational.
    category = CATEGORY_MODEL_GATEWAY

    def detect(self, root_path: str) -> list[Finding]:
        findings: list[Finding] = []

        # Per-gateway accumulators so each gateway is one Finding even if it
        # appears in multiple files.
        gateway_acc: dict[str, dict[str, Any]] = {}

        # Pass 1: YAML / JSON config (litellm, portkey, helm values, k8s manifests)
        for path in walk_files(
            root_path,
            extensions=[".yaml", ".yml", ".json"],
        ):
            text = read_text_safe(path)
            if not text:
                continue
            rel = relative_to_root(path, root_path)

            # LiteLLM proxy config: model_list with litellm_params/litellm_settings.
            litellm_models = _parse_litellm_proxy(text, path)
            if litellm_models is not None:
                _accumulate_gateway(
                    gateway_acc,
                    key="LiteLLM",
                    rel=rel,
                    snippet=_first_line_containing(text, "model_list"),
                    extra_models=litellm_models,
                )

            # Portkey config: filenames portkey-config.json / portkey.json.
            if path.name in {"portkey-config.json", "portkey.json"}:
                _accumulate_gateway(
                    gateway_acc,
                    key="Portkey",
                    rel=rel,
                    snippet=_head_snippet(text),
                )

            # K8s manifests: emit one finding per AI workload.
            if path.suffix.lower() in {".yaml", ".yml"}:
                for k8s_finding in _detect_k8s_ai_workloads(text, rel):
                    findings.append(k8s_finding)

                # Helm values.yaml: image references for AI runtimes.
                if path.name == "values.yaml":
                    for helm_finding in _detect_helm_values_ai(text, rel):
                        findings.append(helm_finding)

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
                    snippet=_first_match_line(_PORTKEY_PATTERNS, text),
                )
            if any(p.search(text) for p in _HELICONE_PATTERNS):
                _accumulate_gateway(
                    gateway_acc,
                    key="Helicone",
                    rel=rel,
                    snippet=_first_match_line(_HELICONE_PATTERNS, text),
                )
            if any(p.search(text) for p in _CLOUDFLARE_PATTERNS):
                _accumulate_gateway(
                    gateway_acc,
                    key="Cloudflare AI Gateway",
                    rel=rel,
                    snippet=_first_match_line(_CLOUDFLARE_PATTERNS, text),
                )
            if any(p.search(text) for p in _OPENROUTER_PATTERNS):
                _accumulate_gateway(
                    gateway_acc,
                    key="OpenRouter",
                    rel=rel,
                    snippet=_first_match_line(_OPENROUTER_PATTERNS, text),
                )
            if any(p.search(text) for p in _LITELLM_PROXY_SOURCE_PATTERNS):
                _accumulate_gateway(
                    gateway_acc,
                    key="LiteLLM",
                    rel=rel,
                    snippet=_first_match_line(_LITELLM_PROXY_SOURCE_PATTERNS, text),
                )

        # Pass 3: Terraform.
        for path in walk_files(root_path, extensions=[".tf", ".tfvars"]):
            text = read_text_safe(path)
            if not text:
                continue
            rel = relative_to_root(path, root_path)
            for tf_finding in _detect_terraform_ai(text, rel):
                findings.append(tf_finding)

        # Materialise gateway findings.
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
    bucket = acc.setdefault(
        key, {"files": [], "snippet": "", "models": []}
    )
    if rel not in bucket["files"]:
        bucket["files"].append(rel)
    if not bucket["snippet"] and snippet:
        bucket["snippet"] = snippet[:_SNIPPET_MAX]
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
            snippet=acc.get("snippet", "")[:_SNIPPET_MAX],
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

    parsed = _parse_yaml_lenient(text)
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
        for m in re.finditer(r"^\s*-?\s*model_name\s*:\s*['\"]?([^'\"\n#]+)", text, re.MULTILINE):
            cand = m.group(1).strip()
            if cand and cand not in models:
                models.append(cand)
    return models


# ---------------------------------------------------------------------------
# K8s manifest parsing
# ---------------------------------------------------------------------------


def _detect_k8s_ai_workloads(text: str, rel: str) -> list[Finding]:
    """Find K8s Deployment / StatefulSet docs that run an AI runtime image."""
    out: list[Finding] = []
    for doc in _split_yaml_documents(text):
        kind = _yaml_top_value(doc, "kind")
        if kind not in {"Deployment", "StatefulSet"}:
            continue
        # Find every container image in this doc.
        for image in _find_yaml_image_values(doc):
            short = _match_ai_image(image)
            if short is None:
                continue
            namespace = _yaml_nested_value(doc, ["metadata", "namespace"]) or "default"
            replicas = _yaml_nested_value(doc, ["spec", "replicas"])
            workload_name = _yaml_nested_value(doc, ["metadata", "name"]) or short
            metadata: dict[str, Any] = {
                "image": image,
                "namespace": namespace,
                "kind": kind,
                "workload_name": workload_name,
                "runtime": short,
            }
            if replicas:
                metadata["replicas"] = replicas
            snippet = _first_line_containing(doc, image)
            out.append(
                Finding(
                    surface=f"K8s AI Workload: {short} (in {rel})",
                    category=CATEGORY_AI_INFRA,
                    evidence=Evidence(
                        files=[rel],
                        snippet=snippet[:_SNIPPET_MAX],
                        metadata=metadata,
                    ),
                    permissions=[],
                    risk_indicators=[
                        "self-hosted LLM runtime (operational responsibility on the team)"
                    ],
                )
            )
    return out


def _detect_helm_values_ai(text: str, rel: str) -> list[Finding]:
    """Find AI runtime image references in a Helm ``values.yaml`` file.

    Helm values files are not K8s manifests; they declare the inputs that
    templates render into manifests. We surface them so users are aware of
    the chart configuration even when no rendered manifest is checked in.
    """
    out: list[Finding] = []
    seen: set[str] = set()
    # Look for `image: <value>` and `repository: <value>` style lines.
    for m in re.finditer(
        r"^\s*(?:image|repository)\s*:\s*['\"]?([^'\"#\n]+)", text, re.MULTILINE,
    ):
        candidate = m.group(1).strip()
        short = _match_ai_image(candidate)
        if short is None or short in seen:
            continue
        seen.add(short)
        out.append(
            Finding(
                surface=f"AI Workload (Helm): {short} (in {rel})",
                category=CATEGORY_AI_INFRA,
                evidence=Evidence(
                    files=[rel],
                    snippet=_first_line_containing(text, candidate)[:_SNIPPET_MAX],
                    metadata={"image": candidate, "runtime": short, "source": "helm-values"},
                ),
                permissions=[],
                risk_indicators=[
                    "self-hosted LLM runtime (operational responsibility on the team)"
                ],
            )
        )
    return out


def _match_ai_image(image: str) -> str | None:
    img_l = image.lower()
    for substr, short in _AI_IMAGE_PATTERNS:
        if substr in img_l:
            return short
    return None


# ---------------------------------------------------------------------------
# Terraform parsing
# ---------------------------------------------------------------------------


def _detect_terraform_ai(text: str, rel: str) -> list[Finding]:
    """Surface AI-related Terraform resources from a single ``.tf`` file."""
    out: list[Finding] = []
    for m in _TF_RESOURCE_RE.finditer(text):
        rtype = m.group("type")
        rname = m.group("name")
        body = m.group("body")
        if rtype not in _TF_AI_RESOURCE_TYPES:
            continue
        label, risk = _TF_AI_RESOURCE_TYPES[rtype]

        model_id = _extract_terraform_model_id(rtype, body)

        # SageMaker endpoints are common for non-LLM workloads. Only surface
        # them if the body or name hints at an LLM.
        if rtype == "aws_sagemaker_endpoint" and not (
            _LLM_HINT_RE.search(body)
            or _LLM_HINT_RE.search(rname)
        ):
            continue

        surface = f"{label}: {model_id}" if model_id else f"{label}: {rname}"

        snippet = _first_line_containing(text, f'"{rtype}"')
        out.append(
            Finding(
                surface=surface,
                category=CATEGORY_AI_INFRA,
                evidence=Evidence(
                    files=[rel],
                    snippet=snippet[:_SNIPPET_MAX],
                    metadata={
                        "resource_type": rtype,
                        "resource_name": rname,
                        "model_id": model_id or "",
                    },
                ),
                permissions=[],
                risk_indicators=[risk],
            )
        )
    return out


def _extract_terraform_model_id(rtype: str, body: str) -> str:
    """Pull a model identifier from a TF resource body (best effort)."""
    # Most precise: model_arn = "...claude-3-5-sonnet..."
    for key in ("model_arn", "model_id", "base_model_identifier", "model_name"):
        m = re.search(
            rf"""\b{key}\s*=\s*['"]([^'"]+)['"]""", body,
        )
        if not m:
            continue
        value = m.group(1)
        bedrock = _BEDROCK_MODEL_ID_RE.search(value)
        if bedrock:
            return bedrock.group(0)
        # Otherwise strip an ARN prefix down to its last segment.
        if value.startswith("arn:"):
            tail = value.rsplit("/", 1)[-1]
            return tail or value
        return value
    return ""


# ---------------------------------------------------------------------------
# YAML helpers (PyYAML-first with regex fallback)
# ---------------------------------------------------------------------------


def _parse_yaml_lenient(text: str) -> Any:
    try:  # pragma: no cover - depends on environment
        import yaml  # type: ignore

        return yaml.safe_load(text)
    except ImportError:
        return None
    except Exception as exc:  # pragma: no cover - defensive
        log.debug("PyYAML failed to parse: %s", exc)
        return None


def _split_yaml_documents(text: str) -> list[str]:
    """Split a YAML stream on ``---`` document markers (zero-aware)."""
    if "\n---" not in text and not text.lstrip().startswith("---"):
        return [text]
    parts: list[str] = []
    buf: list[str] = []
    for line in text.splitlines():
        if line.strip() == "---":
            if buf:
                parts.append("\n".join(buf))
                buf = []
            continue
        buf.append(line)
    if buf:
        parts.append("\n".join(buf))
    return parts or [text]


def _yaml_top_value(doc: str, key: str) -> str | None:
    """Extract a top-level scalar value (no indentation) from a YAML doc."""
    m = re.search(
        rf"^{re.escape(key)}\s*:\s*['\"]?([^'\"\n#]+?)['\"]?\s*$",
        doc,
        re.MULTILINE,
    )
    if not m:
        return None
    return m.group(1).strip() or None


def _yaml_nested_value(doc: str, path: list[str]) -> str | None:
    """Best-effort nested scalar lookup by indentation depth.

    Walks the YAML line by line tracking the current key path via indentation;
    returns the scalar value at ``path`` if the path matches. Good enough for
    fixtures and well-formed manifests, not a full YAML parser.
    """
    if not path:
        return None
    stack: list[tuple[int, str]] = []  # (indent, key)
    for raw in doc.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if line.startswith("- "):
            line = line[2:].strip()
            if not line:
                continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        # Pop deeper / equal-level frames before we descend.
        while stack and stack[-1][0] >= indent:
            stack.pop()
        stack.append((indent, key))
        current_path = [k for _, k in stack]
        if current_path == path and value:
            return value
    return None


def _find_yaml_image_values(doc: str) -> list[str]:
    """Return every ``image: <value>`` value in the YAML document text."""
    out: list[str] = []
    for m in re.finditer(
        r"""^\s*image\s*:\s*['"]?([^'"#\n]+)""", doc, re.MULTILINE,
    ):
        candidate = m.group(1).strip()
        if candidate:
            out.append(candidate)
    return out


# ---------------------------------------------------------------------------
# Snippet helpers
# ---------------------------------------------------------------------------


def _first_line_containing(text: str, needle: str) -> str:
    if not needle:
        return _head_snippet(text)
    idx = text.find(needle)
    if idx == -1:
        return _head_snippet(text)
    line_start = text.rfind("\n", 0, idx) + 1
    line_end = text.find("\n", idx)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()


def _first_match_line(patterns: tuple[re.Pattern, ...], text: str) -> str:
    for p in patterns:
        m = p.search(text)
        if not m:
            continue
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.end())
        if line_end == -1:
            line_end = len(text)
        return text[line_start:line_end].strip()
    return _head_snippet(text)


def _head_snippet(text: str) -> str:
    head = text[:_SNIPPET_MAX]
    return head.replace("\n", " ").strip()


__all__ = ["ModelGatewayDetector"]
