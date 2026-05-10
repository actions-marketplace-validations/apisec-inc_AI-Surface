"""Synthetic fixture: Anthropic SDK with non-literal user input."""
from anthropic import Anthropic


def chat(user_input: str) -> str:
    client = Anthropic()
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        messages=[
            {"role": "user", "content": user_input},
        ],
    )
    return response.content[0].text
