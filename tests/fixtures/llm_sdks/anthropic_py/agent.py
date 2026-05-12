"""Synthetic fixture: Anthropic SDK with non-literal user input."""
from anthropic import Anthropic


def chat(user_input: str) -> str:
    client = Anthropic()
    response = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=1024,
        messages=[
            {"role": "user", "content": user_input},
        ],
    )
    return response.content[0].text
