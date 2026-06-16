"""Tests for the AI provider env-key detector."""
from __future__ import annotations

from pathlib import Path

from ai_surface.detectors.env_keys import EnvKeyDetector
from ai_surface.reporters.json_reporter import render_json
from ai_surface.reporters.markdown_reporter import render_markdown
from ai_surface.types import CATEGORY_ENV_KEY, Finding, Report

FIXTURES = Path(__file__).parent / "fixtures" / "env_keys"

# Fake values planted in the fixtures. None of these may appear in any
# field of the rendered Finding.
FAKE_VALUES = (
    "sk-test-12345",
    "sk-ant-test-67890",
    "gsk-test-abcdef",
    "fake-azure-key-aaaaaaaa",
    "ls-test-zzzzzzzz",
    "sk-foo",
)


def _build_report(findings: list[Finding]) -> Report:
    return Report(
        findings=findings,
        scan_root=str(FIXTURES),
        scan_timestamp="2026-05-03T00:00:00+00:00",
        detectors_run=["env_keys"],
    )


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------


def test_detects_ai_keys_in_with_keys_fixture() -> None:
    findings = EnvKeyDetector().detect(str(FIXTURES / "with_keys"))
    assert len(findings) == 1, "detector must aggregate into a single finding"

    finding = findings[0]
    assert finding.surface == "AI Provider API Keys"
    assert finding.category == CATEGORY_ENV_KEY
    assert finding.permissions == []

    key_names = finding.evidence.metadata["key_names"]
    providers = finding.evidence.metadata["providers"]

    # All planted AI keys are present.
    expected_keys = {
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GROQ_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "LANGSMITH_API_KEY",
    }
    assert expected_keys.issubset(set(key_names))

    # Non-AI vars are NOT present.
    assert "DATABASE_URL" not in key_names
    assert "REDIS_URL" not in key_names
    # Non-credential config is NOT listed as a key (an endpoint URL / org id is
    # configuration, not a secret).
    assert "AZURE_OPENAI_ENDPOINT" not in key_names

    # Sorted lists.
    assert key_names == sorted(key_names)
    assert providers == sorted(providers)

    # Provider list contains expected labels.
    assert {"OpenAI", "Anthropic", "Groq", "Azure OpenAI", "LangSmith"}.issubset(
        set(providers)
    )

    # Both env files contributed.
    assert ".env" in finding.evidence.files
    assert ".env.production" in finding.evidence.files


def test_clean_fixture_yields_no_findings() -> None:
    findings = EnvKeyDetector().detect(str(FIXTURES / "clean"))
    assert findings == []


def test_export_prefix_is_handled() -> None:
    findings = EnvKeyDetector().detect(str(FIXTURES / "with_export"))
    assert len(findings) == 1
    finding = findings[0]
    assert "OPENAI_API_KEY" in finding.evidence.metadata["key_names"]
    assert "OpenAI" in finding.evidence.metadata["providers"]
    assert finding.evidence.files == [".envrc"]


# ---------------------------------------------------------------------------
# Risk indicators
# ---------------------------------------------------------------------------


def test_multiple_provider_risk_indicator_when_three_or_more() -> None:
    findings = EnvKeyDetector().detect(str(FIXTURES / "with_keys"))
    finding = findings[0]
    assert "multiple AI provider keys present" in finding.risk_indicators


def test_observability_risk_indicator_when_langsmith_present() -> None:
    findings = EnvKeyDetector().detect(str(FIXTURES / "with_keys"))
    finding = findings[0]
    assert (
        "observability/tracing key present (production telemetry to third party)"
        in finding.risk_indicators
    )


def test_no_multiple_providers_indicator_when_only_one_provider(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-only\n", encoding="utf-8")
    findings = EnvKeyDetector().detect(str(tmp_path))
    assert len(findings) == 1
    assert "multiple AI provider keys present" not in findings[0].risk_indicators


def test_no_observability_indicator_when_langchain_absent(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "OPENAI_API_KEY=sk-x\nANTHROPIC_API_KEY=sk-y\n", encoding="utf-8"
    )
    findings = EnvKeyDetector().detect(str(tmp_path))
    assert findings
    risks = findings[0].risk_indicators
    assert not any("observability" in r for r in risks)


def test_langchain_alone_triggers_observability_risk(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("LANGCHAIN_API_KEY=ls-x\n", encoding="utf-8")
    findings = EnvKeyDetector().detect(str(tmp_path))
    assert findings
    assert any(
        "observability/tracing key present" in r for r in findings[0].risk_indicators
    )


# ---------------------------------------------------------------------------
# Safety: no values may appear anywhere in the Finding output
# ---------------------------------------------------------------------------


def test_snippet_is_redacted_and_value_free() -> None:
    findings = EnvKeyDetector().detect(str(FIXTURES / "with_keys"))
    finding = findings[0]
    snippet = finding.evidence.snippet

    # The snippet must be a synthetic redacted form, never the source line.
    assert "<redacted>" in snippet
    assert len(snippet) <= 150

    for value in FAKE_VALUES:
        assert value not in snippet, f"snippet leaked value: {value}"


def test_no_value_leaks_into_rendered_outputs() -> None:
    findings = EnvKeyDetector().detect(str(FIXTURES / "with_keys"))
    report = _build_report(findings)

    json_text = render_json(report)
    md_text = render_markdown(report)

    for value in FAKE_VALUES:
        assert value not in json_text, f"json output leaked value: {value}"
        assert value not in md_text, f"markdown output leaked value: {value}"


def test_no_value_leaks_for_export_fixture() -> None:
    findings = EnvKeyDetector().detect(str(FIXTURES / "with_export"))
    report = _build_report(findings)
    json_text = render_json(report)
    md_text = render_markdown(report)
    assert "sk-foo" not in json_text
    assert "sk-foo" not in md_text


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


def test_comment_lines_are_ignored(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "# OPENAI_API_KEY=sk-commented-out\n"
        "    # ANTHROPIC_API_KEY=also-commented\n"
        "DATABASE_URL=postgres://x\n",
        encoding="utf-8",
    )
    assert EnvKeyDetector().detect(str(tmp_path)) == []


def test_only_env_shaped_files_are_scanned(tmp_path: Path) -> None:
    # A .py file containing OPENAI_API_KEY=... should not be picked up.
    (tmp_path / "config.py").write_text(
        'OPENAI_API_KEY = "sk-should-not-be-detected"\n', encoding="utf-8"
    )
    findings = EnvKeyDetector().detect(str(tmp_path))
    assert findings == []


def test_dotenv_glob_variants_are_recognised(tmp_path: Path) -> None:
    (tmp_path / ".env.local").write_text("OPENAI_API_KEY=sk-local\n", encoding="utf-8")
    (tmp_path / "staging.env").write_text(
        "GROQ_API_KEY=gsk-staging\n", encoding="utf-8"
    )
    (tmp_path / ".env.example").write_text(
        "ANTHROPIC_API_KEY=replace-me\n", encoding="utf-8"
    )

    findings = EnvKeyDetector().detect(str(tmp_path))
    assert len(findings) == 1
    keys = findings[0].evidence.metadata["key_names"]
    assert {"OPENAI_API_KEY", "GROQ_API_KEY", "ANTHROPIC_API_KEY"}.issubset(set(keys))


def test_substring_keys_do_not_match(tmp_path: Path) -> None:
    # MY_OPENAI_API_KEY is custom; we don't want false positives.
    (tmp_path / ".env").write_text(
        "MY_OPENAI_API_KEY=should-not-match\n"
        "PREFIX_ANTHROPIC_API_KEY=should-not-match\n",
        encoding="utf-8",
    )
    assert EnvKeyDetector().detect(str(tmp_path)) == []


def test_aggregates_across_multiple_files(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("OPENAI_API_KEY=a\n", encoding="utf-8")
    (tmp_path / ".env.production").write_text(
        "ANTHROPIC_API_KEY=b\n", encoding="utf-8"
    )
    (tmp_path / "deploy.env").write_text("GROQ_API_KEY=c\n", encoding="utf-8")

    findings = EnvKeyDetector().detect(str(tmp_path))
    assert len(findings) == 1
    finding = findings[0]
    assert sorted(finding.evidence.files) == [".env", ".env.production", "deploy.env"]
    assert {"OpenAI", "Anthropic", "Groq"}.issubset(
        set(finding.evidence.metadata["providers"])
    )


def test_detect_returns_empty_for_empty_dir(tmp_path: Path) -> None:
    assert EnvKeyDetector().detect(str(tmp_path)) == []


# ---------------------------------------------------------------------------
# Protocol / wiring
# ---------------------------------------------------------------------------


def test_detector_protocol_fields() -> None:
    d = EnvKeyDetector()
    assert d.name == "env_keys"
    assert d.category == CATEGORY_ENV_KEY


def test_orchestrator_wires_env_key_detector() -> None:
    from ai_surface.orchestrator import default_detectors

    detectors = default_detectors()
    assert any(isinstance(d, EnvKeyDetector) for d in detectors)
