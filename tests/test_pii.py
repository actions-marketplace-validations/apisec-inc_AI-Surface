"""Tests for the PII-into-prompt audit pass."""
from __future__ import annotations

from ai_surface.pii import enrich_pii, has_pii_prompt
from ai_surface.types import (
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_LLM_SDK,
    Evidence,
    Finding,
)


def test_has_pii_prompt() -> None:
    yes = 'SUPPORT_TEMPLATE = "You are a helpful assistant. Email: {customer_email}"'
    assert has_pii_prompt(yes)
    # PII placeholder but not a prompt context -> not flagged
    assert not has_pii_prompt('html = "<p>{customer_email}</p>"')
    # prompt context but no PII -> not flagged
    assert not has_pii_prompt('PROMPT = "You are a helpful assistant."')


def test_flags_agent_in_pii_prompt_file(tmp_path) -> None:
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        'SYSTEM_TEMPLATE = "You are support. Address: {customer_address}, email {customer_email}"\n'
        "support = AgentExecutor(agent=None, tools=[])\n",
        encoding="utf-8",
    )
    f = Finding(surface="LangChain Agent: support", category=CATEGORY_AGENT_FRAMEWORK,
                evidence=Evidence(files=["agent.py"]))
    enrich_pii([f], str(tmp_path))
    assert f.audit and any(rf.flag == "pii-to-llm" for rf in f.audit.risk_flags)
    assert f.severity == "medium"


def test_flags_agent_that_imports_pii_prompts_module(tmp_path) -> None:
    (tmp_path / "prompts.py").write_text(
        "from langchain_core.prompts import ChatPromptTemplate\n"
        'SUPPORT_SYSTEM_TEMPLATE = "You are support. Email: {customer_email}"\n',
        encoding="utf-8",
    )
    (tmp_path / "support_agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "from app.ai.prompts import SUPPORT_SYSTEM_TEMPLATE\n"
        "support = AgentExecutor(agent=None, tools=[])\n",
        encoding="utf-8",
    )
    f = Finding(surface="LangChain Agent: support", category=CATEGORY_AGENT_FRAMEWORK,
                evidence=Evidence(files=["support_agent.py"]))
    enrich_pii([f], str(tmp_path))
    assert f.audit and any(rf.flag == "pii-to-llm" for rf in f.audit.risk_flags)


def test_no_pii_no_flag(tmp_path) -> None:
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        'PROMPT = "You are a helpful shopping assistant."\n'
        "a = AgentExecutor(agent=None, tools=[])\n",
        encoding="utf-8",
    )
    f = Finding(surface="LangChain Agent: a", category=CATEGORY_AGENT_FRAMEWORK,
                evidence=Evidence(files=["agent.py"]))
    enrich_pii([f], str(tmp_path))
    assert not (f.audit and any(rf.flag == "pii-to-llm" for rf in f.audit.risk_flags))


def test_does_not_flag_non_agent(tmp_path) -> None:
    (tmp_path / "agent.py").write_text(
        'TEMPLATE = "You are support. Email: {customer_email}"\n', encoding="utf-8")
    llm = Finding(surface="OpenAI SDK", category=CATEGORY_LLM_SDK, evidence=Evidence(files=["agent.py"]))
    enrich_pii([llm], str(tmp_path))
    assert llm.audit is None


def test_no_scan_root_is_noop() -> None:
    f = Finding(surface="LangChain Agent: x", category=CATEGORY_AGENT_FRAMEWORK, evidence=Evidence())
    enrich_pii([f], None)
    assert f.audit is None
