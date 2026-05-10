"""Synthetic fixture: OpenAI SDK with hardcoded prompt only."""
import openai


def summarize() -> str:
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4-turbo",
        messages=[
            {"role": "system", "content": "You are a concise assistant."},
            {"role": "user", "content": "Summarize the Iliad in two sentences."},
        ],
    )
    return response.choices[0].message.content
