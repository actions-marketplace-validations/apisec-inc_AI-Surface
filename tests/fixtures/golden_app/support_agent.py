from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.tools import tool
from prompts import PROMPT  # links the PII prompt module


@tool
def process_refund(order_id: str, amount: float) -> str:
    """Refund an order."""
    return "ok"


@tool
def send_email(to: str, body: str) -> str:
    """Email the customer."""
    return "ok"


@tool
def lookup_order(order_id: str) -> str:
    """Look up an order."""
    return "ok"


tools = [process_refund, send_email, lookup_order]
support_agent = AgentExecutor(agent=create_tool_calling_agent(None, tools, PROMPT), tools=tools)
