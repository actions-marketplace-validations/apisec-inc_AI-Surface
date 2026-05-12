"""AWS Strands SDK workflow for ticket triage.

Demonstrates:
- AWS Strands agent detection
- @tool decorator pattern
- Bedrock model via Strands wrapper
- Bedrock cross-region inference profile (us.anthropic.claude-...)
"""
from __future__ import annotations

from strands import Agent, tool
from strands.models import BedrockModel


@tool
def fetch_customer_profile(customer_id: str) -> dict:
    """Look up customer profile from CRM."""
    return {"id": customer_id, "tier": "gold"}


@tool
def search_knowledge_base(query: str) -> list:
    """Search internal documentation."""
    return [{"title": "How to refund", "url": "..."}]


@tool
def escalate_to_human(ticket_id: str, reason: str) -> dict:
    """Escalate a ticket to a human agent."""
    return {"ticket_id": ticket_id, "escalated": True}


def build_triage_agent():
    """Construct the ticket triage agent."""
    model = BedrockModel(
        model_id="us.anthropic.claude-sonnet-4-20250514-v1:0",
        region_name="us-east-1",
        temperature=0.2,
    )
    triage_agent = Agent(
        model=model,
        tools=[fetch_customer_profile, search_knowledge_base, escalate_to_human],
    )
    return triage_agent
