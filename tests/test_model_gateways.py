"""Tests for the model gateway / AI infrastructure detector."""
from __future__ import annotations

from pathlib import Path

from ai_surface.detectors.model_gateways import ModelGatewayDetector
from ai_surface.types import CATEGORY_AI_INFRA, CATEGORY_MODEL_GATEWAY

FIXTURES = Path(__file__).parent / "fixtures" / "gateways"


# --- Per-fixture cases -------------------------------------------------------


def test_litellm_proxy_config() -> None:
    findings = ModelGatewayDetector().detect(str(FIXTURES / "litellm_proxy"))
    assert len(findings) == 1
    f = findings[0]
    assert "LiteLLM" in f.surface
    assert f.category == CATEGORY_MODEL_GATEWAY
    routed = f.evidence.metadata.get("models_routed")
    assert routed is not None
    assert set(routed) == {"gpt-4o", "claude-3-5-sonnet", "llama-3-70b"}
    # The gateway should also surface those models as the routable namespace.
    assert set(f.permissions) == {"gpt-4o", "claude-3-5-sonnet", "llama-3-70b"}
    assert any(
        "multi-model routing layer" in r for r in f.risk_indicators
    )


def test_portkey_python_source() -> None:
    findings = ModelGatewayDetector().detect(str(FIXTURES / "portkey_python"))
    assert len(findings) == 1
    f = findings[0]
    assert "Portkey" in f.surface
    assert f.category == CATEGORY_MODEL_GATEWAY


def test_k8s_ollama_deployment() -> None:
    findings = ModelGatewayDetector().detect(str(FIXTURES / "k8s_ollama"))
    assert len(findings) == 1
    f = findings[0]
    assert f.category == CATEGORY_AI_INFRA
    assert "ollama" in f.surface
    assert f.evidence.metadata.get("image", "").startswith("ollama/ollama")
    assert f.evidence.metadata.get("namespace") == "ai"
    assert any(
        "self-hosted LLM runtime" in r for r in f.risk_indicators
    )


def test_terraform_bedrock_provisioned_throughput() -> None:
    findings = ModelGatewayDetector().detect(str(FIXTURES / "terraform_bedrock"))
    assert len(findings) == 1
    f = findings[0]
    assert f.category == CATEGORY_AI_INFRA
    assert "claude-3-5-sonnet" in f.surface
    assert any(
        "high-cost AI infrastructure" in r for r in f.risk_indicators
    )


def test_clean_directory_no_findings() -> None:
    findings = ModelGatewayDetector().detect(str(FIXTURES / "clean"))
    assert findings == []


def test_combined_directory_yields_four_findings() -> None:
    """Running on the parent ``gateways/`` dir should yield 4 findings:
    LiteLLM, Portkey, K8s ollama, Bedrock throughput."""
    findings = ModelGatewayDetector().detect(str(FIXTURES))
    assert len(findings) == 4

    by_category: dict = {}
    for f in findings:
        by_category.setdefault(f.category, []).append(f)
    assert len(by_category[CATEGORY_MODEL_GATEWAY]) == 2
    assert len(by_category[CATEGORY_AI_INFRA]) == 2


# --- Detector protocol -------------------------------------------------------


def test_detector_protocol_attributes() -> None:
    d = ModelGatewayDetector()
    assert d.name == "model_gateways"
    # Class-level category is informational; findings carry their own category.
    assert d.category == CATEGORY_MODEL_GATEWAY


# --- Targeted coverage for additional gateways and edge cases ----------------


def test_helicone_url_in_source(tmp_path: Path) -> None:
    src = tmp_path / "client.ts"
    src.write_text(
        """
        import OpenAI from "openai";
        const client = new OpenAI({
          baseURL: "https://oai.helicone.ai/v1",
          defaultHeaders: { "Helicone-Auth": `Bearer ${process.env.HELICONE_API_KEY}` },
        });
        """.strip(),
        encoding="utf-8",
    )
    findings = ModelGatewayDetector().detect(str(tmp_path))
    assert len(findings) == 1
    assert "Helicone" in findings[0].surface


def test_cloudflare_ai_gateway_url(tmp_path: Path) -> None:
    src = tmp_path / "worker.js"
    src.write_text(
        'const url = "https://gateway.ai.cloudflare.com/v1/abc/openai-proxy/openai/chat/completions";\n',
        encoding="utf-8",
    )
    findings = ModelGatewayDetector().detect(str(tmp_path))
    assert len(findings) == 1
    assert "Cloudflare" in findings[0].surface


def test_openrouter_url(tmp_path: Path) -> None:
    src = tmp_path / "router.py"
    src.write_text(
        'BASE_URL = "https://openrouter.ai/api/v1"\nimport os\nos.environ["OPENROUTER_API_KEY"]\n',
        encoding="utf-8",
    )
    findings = ModelGatewayDetector().detect(str(tmp_path))
    assert len(findings) == 1
    assert "OpenRouter" in findings[0].surface


def test_litellm_proxy_python_import(tmp_path: Path) -> None:
    src = tmp_path / "proxy_app.py"
    src.write_text(
        "from litellm.proxy import proxy_server\nproxy_server.app.run()\n",
        encoding="utf-8",
    )
    findings = ModelGatewayDetector().detect(str(tmp_path))
    assert len(findings) == 1
    assert "LiteLLM" in findings[0].surface


def test_gateway_aggregates_across_files(tmp_path: Path) -> None:
    """Two source files referencing Portkey should produce ONE finding, not two."""
    (tmp_path / "a.py").write_text("from portkey_ai import Portkey\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("PORTKEY_API_KEY = 'redacted'\n", encoding="utf-8")
    findings = ModelGatewayDetector().detect(str(tmp_path))
    assert len(findings) == 1
    assert sorted(findings[0].evidence.files) == ["a.py", "b.py"]


def test_terraform_sagemaker_skipped_when_not_llm(tmp_path: Path) -> None:
    """A SageMaker endpoint with no LLM hints should be ignored."""
    (tmp_path / "main.tf").write_text(
        'resource "aws_sagemaker_endpoint" "tabular" {\n'
        '  name = "tabular-xgboost"\n'
        '  endpoint_config_name = "xgb-config"\n'
        "}\n",
        encoding="utf-8",
    )
    findings = ModelGatewayDetector().detect(str(tmp_path))
    assert findings == []


def test_terraform_sagemaker_llm_endpoint(tmp_path: Path) -> None:
    """A SageMaker endpoint hosting an LLM-shaped model should surface."""
    (tmp_path / "main.tf").write_text(
        'resource "aws_sagemaker_endpoint" "llama_inference" {\n'
        '  name = "llama-3-70b-endpoint"\n'
        '  endpoint_config_name = "llama-config"\n'
        "}\n",
        encoding="utf-8",
    )
    findings = ModelGatewayDetector().detect(str(tmp_path))
    assert len(findings) == 1
    assert "SageMaker" in findings[0].surface


def test_helm_values_yaml_with_vllm(tmp_path: Path) -> None:
    (tmp_path / "values.yaml").write_text(
        "image:\n  repository: vllm/vllm-openai\n  tag: latest\nreplicaCount: 1\n",
        encoding="utf-8",
    )
    findings = ModelGatewayDetector().detect(str(tmp_path))
    assert len(findings) == 1
    f = findings[0]
    assert f.category == CATEGORY_AI_INFRA
    assert "vllm-openai" in f.surface


def test_non_ai_k8s_deployment_ignored(tmp_path: Path) -> None:
    (tmp_path / "deploy.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n  name: nginx\n  namespace: web\n"
        "spec:\n  template:\n    spec:\n      containers:\n        - name: nginx\n          image: nginx:1.25\n",
        encoding="utf-8",
    )
    findings = ModelGatewayDetector().detect(str(tmp_path))
    assert findings == []
