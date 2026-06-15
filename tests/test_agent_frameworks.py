"""Tests for the agent framework detector."""
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from ai_surface.detectors.agent_frameworks import AgentFrameworkDetector
from ai_surface.types import CATEGORY_AGENT_FRAMEWORK, Finding

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "agents"


def _by_surface(findings: Iterable[Finding]) -> dict:
    return {f.surface: f for f in findings}


def _findings_for(*fixtures: str, tmp_path: Path) -> list[Finding]:
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


# ---------------------------------------------------------------------------
# tools=<variable> resolution to an in-file list literal
# ---------------------------------------------------------------------------


def test_tools_kwarg_resolves_distant_list_var(tmp_path: Path) -> None:
    """tools=<var> resolves to an in-file list literal even when the assignment
    is far from the constructor (beyond the nearest-block window)."""
    filler = "\n".join(f"x{i} = {i}" for i in range(40))
    (tmp_path / "agent.py").write_text(
        "from strands import Agent\n"
        "AGENT_TOOLS = [refund_payment, get_customer]\n"
        f"{filler}\n"
        "agent = Agent(model=m, tools=AGENT_TOOLS)\n",
        encoding="utf-8",
    )
    findings = AgentFrameworkDetector().detect(str(tmp_path))
    agents = [f for f in findings if "Agent:" in f.surface and f.permissions]
    assert len(agents) == 1
    f = agents[0]
    assert "refund_payment" in f.permissions
    assert "get_customer" in f.permissions
    assert "financial action exposed" in f.risk_indicators


def test_tools_var_flows_to_audit_and_oversight(tmp_path: Path) -> None:
    """A tools=<var> agent now reaches the deep-dive audit AND the oversight
    pass end to end (the gap dogfooding surfaced)."""
    from ai_surface.audits import enrich_audits
    from ai_surface.oversight import enrich_oversight

    (tmp_path / "agent.py").write_text(
        "from strands import Agent\n"
        "TOOLS = [refund_payment, get_customer, delete_account]\n"
        "agent = Agent(model=m, tools=TOOLS)\n",
        encoding="utf-8",
    )
    findings = AgentFrameworkDetector().detect(str(tmp_path))
    enrich_audits(findings)
    enrich_oversight(findings)  # snippet only -> no approval gate -> should flag

    agents = [f for f in findings if "Agent:" in f.surface and f.permissions]
    assert agents
    f = agents[0]
    assert f.audit is not None
    flags = {rf.flag for rf in f.audit.risk_flags}
    assert "financial-action" in flags
    assert "destructive-action" in flags
    assert "no-human-oversight" in flags
    assert f.severity == "high"


def test_tools_var_factory_call_not_resolved(tmp_path: Path) -> None:
    """A tools list built by a function call is NOT falsely resolved (honest:
    needs dataflow). The agent is still inventoried, just without tools."""
    (tmp_path / "agent.py").write_text(
        "from strands import Agent\n"
        "tools, budget, capture = make_tools()\n"
        "agent = Agent(model=m, tools=tools)\n",
        encoding="utf-8",
    )
    findings = AgentFrameworkDetector().detect(str(tmp_path))
    agents = [f for f in findings if "Agent:" in f.surface]
    assert len(agents) == 1
    assert agents[0].permissions == []


# ---------------------------------------------------------------------------
# JavaScript / TypeScript agent detection (v0.6)
# ---------------------------------------------------------------------------


def _js_findings(name: str, content: str, tmp_path: Path) -> list[Finding]:
    (tmp_path / name).write_text(content, encoding="utf-8")
    return AgentFrameworkDetector().detect(str(tmp_path))


def test_js_langchain_agentexecutor_tools_var(tmp_path: Path) -> None:
    findings = _js_findings("agent.ts",
        'import { AgentExecutor } from "langchain/agents";\n'
        'const tools = [searchTool, refundTool];\n'
        'const executor = new AgentExecutor({ agent, tools, maxIterations: 5 });\n',
        tmp_path)
    agents = [f for f in findings if "Agent:" in f.surface]
    assert len(agents) == 1
    f = agents[0]
    assert "LangChain Agent: executor" in f.surface
    assert "refundTool" in f.permissions and "searchTool" in f.permissions
    assert f.evidence.metadata["language"] == "javascript/typescript"
    assert "financial action exposed" in f.risk_indicators


def test_js_langgraph_react_agent(tmp_path: Path) -> None:
    findings = _js_findings("graph.ts",
        'import { createReactAgent } from "@langchain/langgraph/prebuilt";\n'
        'const agent = createReactAgent({ llm, tools: [lookupTool, deleteTool] });\n',
        tmp_path)
    agents = [f for f in findings if "Agent:" in f.surface]
    assert len(agents) == 1
    assert agents[0].evidence.metadata["framework"] == "langgraph"
    assert "deleteTool" in agents[0].permissions


def test_js_vercel_ai_tools_object_keys(tmp_path: Path) -> None:
    findings = _js_findings("vercel.ts",
        'import { generateText, tool } from "ai";\n'
        'async function run() {\n'
        '  return generateText({\n'
        '    model: openai("gpt-4o"),\n'
        '    tools: {\n'
        '      refundPayment: tool({ description: "refund" }),\n'
        '      getCustomer: tool({ description: "lookup" }),\n'
        '    },\n'
        '  });\n'
        '}\n',
        tmp_path)
    agents = [f for f in findings if "Agent:" in f.surface]
    assert len(agents) == 1
    f = agents[0]
    assert f.evidence.metadata["framework"] == "vercel_ai"
    assert "refundPayment" in f.permissions and "getCustomer" in f.permissions
    assert "financial action exposed" in f.risk_indicators


def test_js_mastra_agent(tmp_path: Path) -> None:
    findings = _js_findings("mastra.ts",
        'import { Agent } from "@mastra/core/agent";\n'
        'const support = new Agent({ name: "support", tools: [getOrder, sendEmail] });\n',
        tmp_path)
    agents = [f for f in findings if "Agent:" in f.surface]
    assert len(agents) == 1
    assert agents[0].evidence.metadata["framework"] == "mastra"
    assert "getOrder" in agents[0].permissions


def test_js_framework_only_fallback(tmp_path: Path) -> None:
    findings = _js_findings("chain.ts",
        'import { ChatOpenAI } from "@langchain/openai";\n'
        'const model = new ChatOpenAI({});\n',
        tmp_path)
    assert len(findings) == 1
    assert findings[0].surface.startswith("LangChain (used in 1 file")
    assert findings[0].evidence.metadata["framework"] == "langchain"


def test_js_no_framework_no_findings(tmp_path: Path) -> None:
    findings = _js_findings("util.ts", 'export function add(a, b) { return a + b; }\n', tmp_path)
    assert findings == []


def test_js_ai_package_not_matched_by_openai(tmp_path: Path) -> None:
    # `from "openai"` must NOT trigger the Vercel "ai" package match.
    findings = _js_findings("oai.ts",
        'import OpenAI from "openai";\nconst c = new OpenAI();\n', tmp_path)
    assert findings == []


def test_js_agent_flows_to_audit_and_oversight(tmp_path: Path) -> None:
    from ai_surface.audits import enrich_audits
    from ai_surface.oversight import enrich_oversight

    findings = _js_findings("agent.ts",
        'import { Agent } from "@mastra/core/agent";\n'
        'const TOOLS = [refundPayment, deleteAccount, getCustomer];\n'
        'const billing = new Agent({ name: "billing", tools: TOOLS });\n',
        tmp_path)
    enrich_audits(findings)
    enrich_oversight(findings)
    agents = [f for f in findings if "Agent:" in f.surface and f.permissions]
    assert agents
    flags = {rf.flag for rf in agents[0].audit.risk_flags}
    assert "financial-action" in flags
    assert "destructive-action" in flags
    assert "no-human-oversight" in flags
