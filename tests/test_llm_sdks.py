"""Tests for the LLM SDK detector."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import pytest

from ai_surface.detectors.llm_sdks import LlmSdkDetector
from ai_surface.types import CATEGORY_LLM_SDK, Finding


FIXTURES = Path(__file__).parent / "fixtures" / "llm_sdks"


def _by_surface(findings: List[Finding]) -> Dict[str, Finding]:
    return {f.surface: f for f in findings}


# ---------------------------------------------------------------------------
# Fixture-directory tests
# ---------------------------------------------------------------------------


def test_detects_anthropic_python_with_dataflow_risk() -> None:
    findings = LlmSdkDetector().detect(str(FIXTURES / "anthropic_py"))
    by_surface = _by_surface(findings)

    assert "Anthropic SDK" in by_surface
    finding = by_surface["Anthropic SDK"]
    assert finding.category == CATEGORY_LLM_SDK
    assert finding.evidence.files == ["agent.py"]
    assert "claude-sonnet-4-6" in finding.evidence.metadata["models_used"]
    assert finding.evidence.metadata["call_site_count"] == 1
    assert "non-literal data flows into LLM call" in finding.risk_indicators
    # Snippet should be the import line, capped at 200 chars.
    assert "anthropic" in finding.evidence.snippet.lower()
    assert len(finding.evidence.snippet) <= 200


def test_detects_openai_python_without_dataflow_risk() -> None:
    findings = LlmSdkDetector().detect(str(FIXTURES / "openai_py"))
    by_surface = _by_surface(findings)

    assert "OpenAI SDK" in by_surface
    finding = by_surface["OpenAI SDK"]
    assert finding.evidence.files == ["summarize.py"]
    assert "gpt-4-turbo" in finding.evidence.metadata["models_used"]
    # Hardcoded prompts only — no flow risk.
    assert finding.risk_indicators == []


def test_detects_anthropic_typescript() -> None:
    findings = LlmSdkDetector().detect(str(FIXTURES / "anthropic_ts"))
    by_surface = _by_surface(findings)

    assert "Anthropic SDK" in by_surface
    finding = by_surface["Anthropic SDK"]
    assert finding.evidence.files == ["client.ts"]
    assert "claude-haiku-4-5" in finding.evidence.metadata["models_used"]
    # `content: prompt` (no quotes around prompt) is a non-literal flow.
    assert "non-literal data flows into LLM call" in finding.risk_indicators


def test_clean_repo_yields_no_findings() -> None:
    findings = LlmSdkDetector().detect(str(FIXTURES / "clean"))
    assert findings == []


def test_full_fixture_root_aggregates_across_subdirs() -> None:
    findings = LlmSdkDetector().detect(str(FIXTURES))
    by_surface = _by_surface(findings)

    # Two distinct SDKs should surface from the combined fixture tree.
    assert {"Anthropic SDK", "OpenAI SDK"}.issubset(set(by_surface.keys()))

    anthropic = by_surface["Anthropic SDK"]
    # Both Python and TS files surface under one Anthropic finding.
    assert sorted(anthropic.evidence.files) == sorted(
        ["anthropic_py/agent.py", "anthropic_ts/client.ts"]
    )
    assert anthropic.evidence.metadata["call_site_count"] == 2

    openai = by_surface["OpenAI SDK"]
    assert openai.evidence.files == ["openai_py/summarize.py"]


# ---------------------------------------------------------------------------
# Inline tmp_path tests for edge cases
# ---------------------------------------------------------------------------


def test_bedrock_python_boto3_client(tmp_path: Path) -> None:
    src = tmp_path / "bedrock.py"
    src.write_text(
        'import boto3\n'
        'client = boto3.client("bedrock-runtime")\n'
        'resp = client.invoke_model(modelId="anthropic.claude-3-5-sonnet-20240620-v1:0", body=b"{}")\n',
        encoding="utf-8",
    )
    findings = LlmSdkDetector().detect(str(tmp_path))
    by_surface = _by_surface(findings)
    assert "AWS Bedrock" in by_surface
    models = by_surface["AWS Bedrock"].evidence.metadata["models_used"]
    assert any("claude-3-5-sonnet" in m for m in models)


def test_azure_openai_does_not_double_count_as_openai(tmp_path: Path) -> None:
    src = tmp_path / "azure.py"
    src.write_text(
        'from openai import AzureOpenAI\n'
        'client = AzureOpenAI(api_version="2024-02-01")\n',
        encoding="utf-8",
    )
    findings = LlmSdkDetector().detect(str(tmp_path))
    surfaces = {f.surface for f in findings}
    assert "Azure OpenAI" in surfaces
    assert "OpenAI SDK" not in surfaces


def test_litellm_python(tmp_path: Path) -> None:
    src = tmp_path / "proxy.py"
    src.write_text(
        "from litellm import completion\n"
        'resp = completion(model="gpt-4-turbo", messages=[{"role":"user","content":"hi"}])\n',
        encoding="utf-8",
    )
    findings = LlmSdkDetector().detect(str(tmp_path))
    surfaces = {f.surface for f in findings}
    assert "LiteLLM" in surfaces


def test_groq_typescript(tmp_path: Path) -> None:
    src = tmp_path / "g.ts"
    src.write_text(
        'import Groq from "groq-sdk";\n'
        'const c = new Groq();\n',
        encoding="utf-8",
    )
    findings = LlmSdkDetector().detect(str(tmp_path))
    surfaces = {f.surface for f in findings}
    assert "Groq" in surfaces


def test_detector_protocol_fields() -> None:
    d = LlmSdkDetector()
    assert d.name == "llm_sdks"
    assert d.category == CATEGORY_LLM_SDK


def test_orchestrator_wires_llm_detector() -> None:
    """The default detector list should include LlmSdkDetector."""
    from ai_surface.orchestrator import default_detectors

    detectors = default_detectors()
    assert any(isinstance(d, LlmSdkDetector) for d in detectors)


# ---------------------------------------------------------------------------
# Empty-input & robustness
# ---------------------------------------------------------------------------


def test_detect_returns_empty_for_empty_dir(tmp_path: Path) -> None:
    assert LlmSdkDetector().detect(str(tmp_path)) == []


def test_detect_ignores_unrelated_extensions(tmp_path: Path) -> None:
    # A .md file mentioning anthropic should not produce a finding.
    (tmp_path / "README.md").write_text(
        "We use the anthropic SDK and import openai.", encoding="utf-8"
    )
    assert LlmSdkDetector().detect(str(tmp_path)) == []
