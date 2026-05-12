"""Tests for the agent framework detector."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

from ai_surface.detectors.agent_frameworks import AgentFrameworkDetector
from ai_surface.types import CATEGORY_AGENT_FRAMEWORK, Finding


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "agents"


def _by_surface(findings: Iterable[Finding]) -> dict:
    return {f.surface: f for f in findings}


def _findings_for(*fixtures: str, tmp_path: Path) -> List[Finding]:
    """Copy a subset of fixture files into tmp_path and run the detector."""
    for fname in fixtures:
        src = FIXTURE_ROOT / fname
        dst = tmp_path / fname
        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return AgentFrameworkDetector().detect(str(tmp_path))


# ---------------------------------------------------------------------------
# Empty / clean inputs
# ---------------------------------------------------------------------------


def test_empty_directory_returns_no_findings(tmp_path: Path) -> None:
    assert AgentFrameworkDetector().detect(str(tmp_path)) == []


def test_clean_python_returns_no_findings(tmp_path: Path) -> None:
    findings = _findings_for("clean.py", tmp_path=tmp_path)
    assert findings == []


# ---------------------------------------------------------------------------
# LangChain
# ---------------------------------------------------------------------------


def test_langchain_agent_finding(tmp_path: Path) -> None:
    findings = _findings_for("langchain_refund.py", tmp_path=tmp_path)
    # Expect exactly one agent-level finding (no framework-only fallback because
    # the only file is covered by the agent definition).
    assert len(findings) == 1
    f = findings[0]
    assert f.category == CATEGORY_AGENT_FRAMEWORK
    assert "LangChain Agent" in f.surface
    assert "refund_agent" in f.surface
    assert "langchain_refund.py" in f.surface

    # Tool extraction
    assert "query_db" in f.permissions
    assert "refund_payment" in f.permissions
    assert f.evidence.metadata["framework"] == "langchain"
    assert f.evidence.metadata["agent_name"] == "refund_agent"
    assert f.evidence.metadata["tool_count"] == 2

    # Risk indicators
    assert "financial action exposed" in f.risk_indicators
    assert "high blast-radius combination" in f.risk_indicators


# ---------------------------------------------------------------------------
# CrewAI
# ---------------------------------------------------------------------------


def test_crewai_agent_finding(tmp_path: Path) -> None:
    findings = _findings_for("crewai_research.py", tmp_path=tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert "CrewAI Agent" in f.surface
    assert "researcher" in f.surface
    assert "search_tool" in f.permissions
    assert "send_email_tool" in f.permissions
    # send_email_tool ends with "_tool" but the substring match for messaging
    # should NOT trigger because we match exact tool names. We only flag
    # high-blast-radius via read+write token co-occurrence: search (read) +
    # send_email_tool contains "send" (write).
    assert "high blast-radius combination" in f.risk_indicators
    assert f.evidence.metadata["framework"] == "crewai"
    assert f.evidence.metadata["agent_name"] == "researcher"


# ---------------------------------------------------------------------------
# Anthropic-shape tools
# ---------------------------------------------------------------------------


def test_anthropic_tools_finding(tmp_path: Path) -> None:
    findings = _findings_for("anthropic_tools.py", tmp_path=tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert "Claude Tools" in f.surface
    assert "call_admin_agent" in f.surface
    assert "delete_record" in f.permissions
    assert "fetch_user" in f.permissions
    assert "destructive action exposed" in f.risk_indicators
    # delete + fetch -> read + destructive -> high blast radius
    assert "high blast-radius combination" in f.risk_indicators


# ---------------------------------------------------------------------------
# AWS Strands
# ---------------------------------------------------------------------------


def test_strands_agent_finding(tmp_path: Path) -> None:
    findings = _findings_for("strands_param_hydration.py", tmp_path=tmp_path)
    # One named Strands agent + the @tool decorators don't produce separate findings.
    assert len(findings) == 1
    f = findings[0]
    assert f.category == CATEGORY_AGENT_FRAMEWORK
    assert "AWS Strands Agent" in f.surface
    assert "param_resolver" in f.surface
    assert "strands_param_hydration.py" in f.surface
    # The constructor uses bare-identifier references — the detector should
    # fall back to @tool-decorated functions.
    assert "lookup_endpoint" in f.permissions
    assert "execute_endpoint" in f.permissions
    assert "resolve_auth" in f.permissions
    assert f.evidence.metadata["framework"] == "strands"
    assert f.evidence.metadata["agent_name"] == "param_resolver"


def test_strands_framework_only_fallback(tmp_path: Path) -> None:
    """A file that imports strands but defines no Agent yields a framework-only finding."""
    (tmp_path / "uses_strands.py").write_text(
        "from strands.models import BedrockModel\n\n"
        "def make_model():\n"
        '    return BedrockModel(model_id="us.anthropic.claude-sonnet-4-20250514-v1:0")\n',
        encoding="utf-8",
    )
    findings = AgentFrameworkDetector().detect(str(tmp_path))
    assert len(findings) == 1
    f = findings[0]
    assert f.surface.startswith("AWS Strands (used in 1 file")
    assert f.evidence.metadata["framework"] == "strands"


# ---------------------------------------------------------------------------
# Mixed & framework-only fallbacks
# ---------------------------------------------------------------------------


def test_all_fixtures_together(tmp_path: Path) -> None:
    findings = _findings_for(
        "langchain_refund.py",
        "crewai_research.py",
        "anthropic_tools.py",
        "clean.py",
        tmp_path=tmp_path,
    )
    surfaces = {f.surface for f in findings}
    # 3 agent/tools findings, no clean-file noise
    assert len(findings) == 3
    assert any("LangChain Agent: refund_agent" in s for s in surfaces)
    assert any("CrewAI Agent: researcher" in s for s in surfaces)
    assert any("Claude Tools: call_admin_agent" in s for s in surfaces)


def test_framework_only_fallback(tmp_path: Path) -> None:
    """A file that imports langchain but defines no agent yields a framework-only finding."""
    (tmp_path / "uses_langchain.py").write_text(
        "from langchain.schema import Document\n\n"
        "def make_doc(text: str) -> Document:\n"
        "    return Document(page_content=text)\n",
        encoding="utf-8",
    )
    findings = AgentFrameworkDetector().detect(str(tmp_path))
    assert len(findings) == 1
    f = findings[0]
    assert f.surface.startswith("LangChain (used in 1 file")
    assert f.permissions == []
    assert f.risk_indicators == []
    assert f.evidence.metadata["framework"] == "langchain"
    assert f.evidence.metadata["file_count"] == 1


def test_detector_name_and_category() -> None:
    d = AgentFrameworkDetector()
    assert d.name == "agent_frameworks"
    assert d.category == CATEGORY_AGENT_FRAMEWORK


# ---------------------------------------------------------------------------
# Risk classifier edge cases
# ---------------------------------------------------------------------------


def test_destructive_only_no_read_no_blast_radius(tmp_path: Path) -> None:
    """Destructive tool without any read tool should NOT be high blast-radius."""
    (tmp_path / "purge.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "from langchain.tools import Tool\n\n"
        'tools = [Tool(name="purge_logs", func=None)]\n'
        "purge_agent = AgentExecutor(tools=tools, agent=None)\n",
        encoding="utf-8",
    )
    findings = AgentFrameworkDetector().detect(str(tmp_path))
    assert len(findings) == 1
    f = findings[0]
    assert "destructive action exposed" in f.risk_indicators
    assert "high blast-radius combination" not in f.risk_indicators


def test_messaging_tool_indicator(tmp_path: Path) -> None:
    (tmp_path / "msg.py").write_text(
        'tools = [{"name": "send_slack"}, {"name": "send_email"}]\n'
        "def notify(): return tools\n",
        encoding="utf-8",
    )
    findings = AgentFrameworkDetector().detect(str(tmp_path))
    assert len(findings) == 1
    assert "messaging action exposed" in findings[0].risk_indicators
