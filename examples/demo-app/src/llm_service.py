"""Direct LLM SDK calls. Two providers, one of them with a data-flow risk.

Demonstrates:
- OpenAI and Anthropic SDK detection
- Multiple model references extracted
- Risk indicator: `non-literal data flows into LLM call`
"""
from __future__ import annotations

import os
from anthropic import Anthropic
from openai import OpenAI


anthropic_client = Anthropic()
openai_client = OpenAI()


def summarize_ticket(ticket_body: str) -> str:
    """Summarize a support ticket. Note: user content flows directly into the prompt."""
    # Non-literal data flow: ticket_body is a runtime variable that flows into messages.
    # ai-surface flags this as `non-literal data flows into LLM call`.
    response = anthropic_client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=512,
        messages=[
            {"role": "user", "content": ticket_body},
        ],
    )
    return response.content[0].text


def classify_ticket(ticket_body: str) -> str:
    """Classify a ticket using GPT-4. Also has non-literal data flow."""
    response = openai_client.chat.completions.create(
        model="gpt-4-turbo",
        messages=[
            {"role": "system", "content": "Classify this support ticket."},
            {"role": "user", "content": ticket_body},
        ],
    )
    return response.choices[0].message.content
