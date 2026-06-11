"""Combined e2e fixture: exercises multiple ai-surface detectors at once."""
from anthropic import Anthropic
from fastapi import FastAPI

app = FastAPI()
_client = Anthropic()


@app.post("/v1/charge")
def charge(amount: int) -> dict:
    _client.messages.create(model="claude-opus-4-8", messages=[])
    return {"ok": True}
