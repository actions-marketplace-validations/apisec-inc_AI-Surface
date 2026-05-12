"""A LangChain customer support agent with refund and lookup tools.

Demonstrates:
- LangChain agent framework detection
- Tool inventory extraction
- Risk indicators: `financial action exposed`, `high blast-radius combination`
"""
from __future__ import annotations

from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import Tool
from langchain.chat_models import ChatOpenAI


def lookup_order(order_id: str) -> dict:
    """Find an order by ID. Read-only."""
    # ... database read ...
    return {"order_id": order_id, "amount": 100.0}


def refund_payment(order_id: str, amount: float) -> dict:
    """Issue a refund. Reversible only by another refund."""
    # ... payment provider write ...
    return {"refund_id": f"r_{order_id}", "amount": amount}


def cancel_subscription(subscription_id: str) -> dict:
    """Cancel an active subscription. Irreversible same-period."""
    # ... subscriptions API ...
    return {"subscription_id": subscription_id, "status": "cancelled"}


tools = [
    Tool(name="lookup_order", func=lookup_order, description="Look up an order by ID"),
    Tool(name="refund_payment", func=refund_payment, description="Issue a refund"),
    Tool(name="cancel_subscription", func=cancel_subscription, description="Cancel a subscription"),
]


llm = ChatOpenAI(model="gpt-4-turbo")
support_agent = create_react_agent(llm=llm, tools=tools, prompt="...")
agent_executor = AgentExecutor(agent=support_agent, tools=tools)
