"""Synthetic LangChain agent fixture: refund agent with read+financial tools."""
from langchain.agents import AgentExecutor
from langchain.tools import Tool


def _query_db(_q: str) -> str:
    return "rows"


def _refund_payment(_id: str) -> str:
    return "ok"


tools = [
    Tool(name="query_db", func=_query_db, description="read customer rows"),
    Tool(name="refund_payment", func=_refund_payment, description="refund a charge"),
]

refund_agent = AgentExecutor(tools=tools, agent=None, verbose=True)
