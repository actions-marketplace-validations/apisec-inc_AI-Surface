"""AI infrastructure detector.

Surfaces self-hosted AI runtimes and managed AI cloud resources declared in
deployment specs and infrastructure-as-code. This is the breadth-side
"where is AI compute provisioned" category, distinct from ``model_gateways``
(which covers proxy/routing layers in front of providers).

Sources scanned:

* **Kubernetes manifests** (``*.yaml`` / ``*.yml``) whose ``kind`` runs an AI
  runtime image: ``Deployment``, ``StatefulSet``, ``DaemonSet``, ``Pod``,
  ``Job``, ``CronJob``, ``ReplicaSet``, Argo ``Rollout``.
* **Helm** ``values.yaml`` image / repository references.
* **docker-compose** (``docker-compose*.yml``, ``compose*.yml``) service images.
* **Dockerfiles** (``Dockerfile``, ``*.Dockerfile``, ``Containerfile``) whose
  ``FROM`` base image or serve command is an AI runtime.
* **Terraform** (``*.tf`` / ``*.tfvars``) resources for managed AI compute:
  Bedrock provisioned throughput / custom models, SageMaker LLM endpoints,
  Vertex AI endpoints.

Each detected surface produces exactly one :class:`Finding`.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..types import CATEGORY_AI_INFRA, Evidence, Finding
from ..utils.specs import (
    SNIPPET_MAX,
    extract_hcl_body,
    find_yaml_image_values,
    first_line_containing,
    split_yaml_documents,
    yaml_nested_value,
    yaml_top_value,
)
from ..utils.walk import read_text_safe, relative_to_root, walk_files

_RISK_SELF_HOSTED = "self-hosted LLM runtime (operational responsibility on the team)"
_RISK_HIGH_COST = "high-cost AI infrastructure (billing exposure)"


# ---------------------------------------------------------------------------
# AI runtime image catalogue
# ---------------------------------------------------------------------------
#
# Each tuple: (lowercased substring to look for in an image ref, short name).
# Substrings are chosen to be distinctive enough to avoid matching unrelated
# images. Order matters only for which short name wins on overlap.

_AI_IMAGE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("ollama/ollama", "ollama"),
    ("vllm/vllm-openai", "vllm"),
    ("vllm/vllm", "vllm"),
    ("huggingface/text-generation-inference", "text-generation-inference"),
    ("huggingface/text-embeddings-inference", "text-embeddings-inference"),
    ("text-embeddings-inference", "text-embeddings-inference"),
    ("lmsysorg/sglang", "sglang"),
    ("lmsys/fastchat", "fastchat"),
    ("nvcr.io/nvidia/tritonserver", "triton-inference-server"),
    ("tritonserver", "triton-inference-server"),
    ("nvcr.io/nim", "nvidia-nim"),
    ("localai/localai", "localai"),
    ("go-skynet/local-ai", "localai"),
    ("ghcr.io/ggerganov/llama.cpp", "llama.cpp"),
    ("ggml-org/llama.cpp", "llama.cpp"),
    ("predibase/lorax", "lorax"),
    ("alpindale/aphrodite-engine", "aphrodite"),
    ("michaelf34/infinity", "infinity"),
    ("bentoml/openllm", "openllm"),
    ("ray-project/ray-llm", "ray-llm"),
    ("xinference", "xinference"),
    ("langchain/", "langchain"),
    ("crewai/", "crewai"),
)

# Serve commands that, when present in a Dockerfile CMD/ENTRYPOINT/RUN, signal
# the image is built to serve an AI runtime even if the base image is generic.
# The separator class ``['"]?[,\s]+['"]?`` tolerates both the shell form
# (``vllm serve``) and the JSON-array exec form (``["vllm", "serve"]``).
_DOCKERFILE_SERVE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"""\bvllm['"]?[,\s]+['"]?serve\b"""), "vllm"),
    (re.compile(r"\bvllm\.entrypoints\b"), "vllm"),
    (re.compile(r"""\bollama['"]?[,\s]+['"]?serve\b"""), "ollama"),
    (re.compile(r"\btext-generation-launcher\b"), "text-generation-inference"),
    (re.compile(r"\btritonserver\b"), "triton-inference-server"),
    (re.compile(r"\bsglang\.launch_server\b"), "sglang"),
    (re.compile(r"""\bopenllm['"]?[,\s]+['"]?(?:start|serve)\b"""), "openllm"),
    (re.compile(r"\blocalai\b"), "localai"),
)

_DOCKERFILE_FROM_RE = re.compile(r"^\s*FROM\s+(\S+)", re.IGNORECASE | re.MULTILINE)

_K8S_WORKLOAD_KINDS = frozenset(
    {
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "Pod",
        "Job",
        "CronJob",
        "ReplicaSet",
        "Rollout",  # Argo Rollouts
    }
)

# ---------------------------------------------------------------------------
# Terraform AI resources
# ---------------------------------------------------------------------------

_TF_RESOURCE_RE = re.compile(
    r"""resource\s+"(?P<type>[a-zA-Z0-9_]+)"\s+"(?P<name>[a-zA-Z0-9_-]+)"\s*\{""",
)
_TF_AI_RESOURCE_TYPES = {
    "aws_bedrock_provisioned_model_throughput": (
        "Bedrock provisioned throughput",
        _RISK_HIGH_COST,
    ),
    "aws_bedrock_custom_model": ("Bedrock custom model", _RISK_HIGH_COST),
    "aws_sagemaker_endpoint": ("SageMaker endpoint", _RISK_HIGH_COST),
    "google_vertex_ai_endpoint": ("Vertex AI endpoint", _RISK_HIGH_COST),
}

_BEDROCK_MODEL_ID_RE = re.compile(
    r"""(?:anthropic|amazon|meta|mistral|cohere|ai21|stability)\.[a-zA-Z0-9._:-]+"""
)
_LLM_HINT_RE = re.compile(
    r"""(claude|llama|mistral|mixtral|gpt|gemini|cohere|command|titan|nova|falcon|qwen|phi|deepseek)""",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class AiInfraDetector:
    """Detect self-hosted AI runtimes and managed AI cloud resources."""

    name = "ai_infra"
    category = CATEGORY_AI_INFRA

    def detect(self, root_path: str) -> list[Finding]:
        findings: list[Finding] = []

        # Pass 1: YAML manifests (k8s), Helm values, docker-compose.
        for path in walk_files(root_path, extensions=[".yaml", ".yml"]):
            text = read_text_safe(path)
            if not text:
                continue
            rel = relative_to_root(path, root_path)

            findings.extend(_detect_k8s_ai_workloads(text, rel))

            if path.name == "values.yaml":
                findings.extend(_detect_helm_values_ai(text, rel))

            if _is_compose_file(path):
                findings.extend(_detect_compose_ai(text, rel))

        # Pass 2: Terraform.
        for path in walk_files(root_path, extensions=[".tf", ".tfvars"]):
            text = read_text_safe(path)
            if not text:
                continue
            rel = relative_to_root(path, root_path)
            findings.extend(_detect_terraform_ai(text, rel))

        # Pass 3: Dockerfiles (no standard extension; filter by name).
        for path in walk_files(root_path):
            if not _is_dockerfile(path):
                continue
            text = read_text_safe(path)
            if not text:
                continue
            rel = relative_to_root(path, root_path)
            findings.extend(_detect_dockerfile_ai(text, rel))

        return findings


def _match_ai_image(image: str) -> str | None:
    img_l = image.lower()
    for substr, short in _AI_IMAGE_PATTERNS:
        if substr in img_l:
            return short
    return None


# ---------------------------------------------------------------------------
# Kubernetes
# ---------------------------------------------------------------------------


def _detect_k8s_ai_workloads(text: str, rel: str) -> list[Finding]:
    """Find K8s workload docs that run an AI runtime image."""
    out: list[Finding] = []
    for doc in split_yaml_documents(text):
        kind = yaml_top_value(doc, "kind")
        if kind not in _K8S_WORKLOAD_KINDS:
            continue
        for image in find_yaml_image_values(doc):
            short = _match_ai_image(image)
            if short is None:
                continue
            namespace = yaml_nested_value(doc, ["metadata", "namespace"]) or "default"
            replicas = yaml_nested_value(doc, ["spec", "replicas"])
            workload_name = yaml_nested_value(doc, ["metadata", "name"]) or short
            metadata: dict[str, Any] = {
                "image": image,
                "namespace": namespace,
                "kind": kind,
                "workload_name": workload_name,
                "runtime": short,
            }
            if replicas:
                metadata["replicas"] = replicas
            snippet = first_line_containing(doc, image)
            out.append(
                Finding(
                    surface=f"K8s AI Workload: {short} (in {rel})",
                    category=CATEGORY_AI_INFRA,
                    evidence=Evidence(
                        files=[rel],
                        snippet=snippet[:SNIPPET_MAX],
                        metadata=metadata,
                    ),
                    permissions=[],
                    risk_indicators=[_RISK_SELF_HOSTED],
                )
            )
    return out


def _detect_helm_values_ai(text: str, rel: str) -> list[Finding]:
    """Find AI runtime image references in a Helm ``values.yaml`` file."""
    out: list[Finding] = []
    seen: set[str] = set()
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
                    snippet=first_line_containing(text, candidate)[:SNIPPET_MAX],
                    metadata={"image": candidate, "runtime": short, "source": "helm-values"},
                ),
                permissions=[],
                risk_indicators=[_RISK_SELF_HOSTED],
            )
        )
    return out


# ---------------------------------------------------------------------------
# docker-compose
# ---------------------------------------------------------------------------


def _is_compose_file(path: Path) -> bool:
    name = path.name.lower()
    if name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
        return True
    # docker-compose.prod.yml, compose.override.yaml, etc.
    return bool(
        (name.startswith("docker-compose.") or name.startswith("compose."))
        and name.endswith((".yml", ".yaml"))
    )


def _detect_compose_ai(text: str, rel: str) -> list[Finding]:
    """Find AI runtime images referenced as compose service images."""
    out: list[Finding] = []
    seen: set[str] = set()
    for image in find_yaml_image_values(text):
        short = _match_ai_image(image)
        if short is None or short in seen:
            continue
        seen.add(short)
        out.append(
            Finding(
                surface=f"AI Workload (compose): {short} (in {rel})",
                category=CATEGORY_AI_INFRA,
                evidence=Evidence(
                    files=[rel],
                    snippet=first_line_containing(text, image)[:SNIPPET_MAX],
                    metadata={"image": image, "runtime": short, "source": "docker-compose"},
                ),
                permissions=[],
                risk_indicators=[_RISK_SELF_HOSTED],
            )
        )
    return out


# ---------------------------------------------------------------------------
# Dockerfiles
# ---------------------------------------------------------------------------


def _is_dockerfile(path: Path) -> bool:
    name = path.name
    if name in {"Dockerfile", "Containerfile"}:
        return True
    # api.Dockerfile, gpu.dockerfile, Dockerfile.prod
    lower = name.lower()
    return bool(lower.endswith(".dockerfile") or lower.startswith("dockerfile."))


def _detect_dockerfile_ai(text: str, rel: str) -> list[Finding]:
    """Surface a Dockerfile that builds an AI runtime image.

    Matches on the ``FROM`` base image first, then falls back to serve
    commands (``vllm serve``, ``ollama serve``, ``text-generation-launcher``,
    etc.) so an image built ``FROM python`` that runs a server is still caught.
    One finding per Dockerfile.
    """
    runtime: str | None = None
    matched_image = ""
    for fm in _DOCKERFILE_FROM_RE.finditer(text):
        image = fm.group(1)
        short = _match_ai_image(image)
        if short is not None:
            runtime = short
            matched_image = image
            break

    if runtime is None:
        for rx, short in _DOCKERFILE_SERVE_PATTERNS:
            if rx.search(text):
                runtime = short
                break

    if runtime is None:
        return []

    snippet = (
        first_line_containing(text, matched_image)
        if matched_image
        else first_line_containing(text, "FROM")
    )
    metadata: dict[str, Any] = {"runtime": runtime, "source": "dockerfile"}
    if matched_image:
        metadata["base_image"] = matched_image
    return [
        Finding(
            surface=f"AI Workload (Dockerfile): {runtime} (in {rel})",
            category=CATEGORY_AI_INFRA,
            evidence=Evidence(
                files=[rel],
                snippet=snippet[:SNIPPET_MAX],
                metadata=metadata,
            ),
            permissions=[],
            risk_indicators=[_RISK_SELF_HOSTED],
        )
    ]


# ---------------------------------------------------------------------------
# Terraform
# ---------------------------------------------------------------------------


def _detect_terraform_ai(text: str, rel: str) -> list[Finding]:
    """Surface AI-related Terraform resources from a single ``.tf`` file."""
    out: list[Finding] = []
    for m in _TF_RESOURCE_RE.finditer(text):
        rtype = m.group("type")
        rname = m.group("name")
        if rtype not in _TF_AI_RESOURCE_TYPES:
            continue
        # m.end() - 1 points at the opening `{` captured by the regex.
        body = extract_hcl_body(text, m.end() - 1)
        label, risk = _TF_AI_RESOURCE_TYPES[rtype]

        model_id = _extract_terraform_model_id(body)

        # SageMaker endpoints are common for non-LLM workloads. Only surface
        # them if the body or name hints at an LLM.
        if rtype == "aws_sagemaker_endpoint" and not (
            _LLM_HINT_RE.search(body) or _LLM_HINT_RE.search(rname)
        ):
            continue

        surface = f"{label}: {model_id}" if model_id else f"{label}: {rname}"
        snippet = first_line_containing(text, f'"{rtype}"')
        out.append(
            Finding(
                surface=surface,
                category=CATEGORY_AI_INFRA,
                evidence=Evidence(
                    files=[rel],
                    snippet=snippet[:SNIPPET_MAX],
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


def _extract_terraform_model_id(body: str) -> str:
    """Pull a model identifier from a TF resource body (best effort)."""
    for key in ("model_arn", "model_id", "base_model_identifier", "model_name"):
        m = re.search(rf"""\b{key}\s*=\s*['"]([^'"]+)['"]""", body)
        if not m:
            continue
        value = m.group(1)
        bedrock = _BEDROCK_MODEL_ID_RE.search(value)
        if bedrock:
            return bedrock.group(0)
        if value.startswith("arn:"):
            tail = value.rsplit("/", 1)[-1]
            return tail or value
        return value
    return ""


__all__ = ["AiInfraDetector"]
