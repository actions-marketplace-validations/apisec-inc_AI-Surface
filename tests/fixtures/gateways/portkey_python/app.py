"""Sample app file using the Portkey gateway SDK."""
from portkey_ai import Portkey

client = Portkey(api_key="redacted")


def chat(prompt: str) -> str:
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content
