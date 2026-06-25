"""Fixture: OpenAI Agents SDK (Python). Not real app code."""
from agents import Agent, Runner, function_tool


@function_tool
def refund_payment(order_id: str) -> str:
    """Refund a customer's payment."""
    return "refunded"


@function_tool
def lookup_order(order_id: str) -> str:
    """Look up an order by id."""
    return "order"


support_agent = Agent(
    name="Support",
    instructions="Help customers with refunds.",
    tools=[refund_payment, lookup_order],
)


def main() -> None:
    Runner.run_sync(support_agent, "refund my order")
