"""Synthetic AWS Strands SDK fixture modeled on real param-hydration agent code.

Strands is AWS's open-source agent framework. Agents are constructed with
`Agent(model=..., tools=...)`, tools are decorated with `@tool`, and the
Bedrock LLM is wrapped by `BedrockModel`.
"""
from strands import Agent, tool
from strands.models import BedrockModel


@tool
def lookup_endpoint(spec_id: str) -> dict:
    """Return a single endpoint spec."""
    return {"path": "/api/charges", "method": "POST"}


@tool
def execute_endpoint(endpoint: dict, payload: dict) -> dict:
    """Send a real request against the endpoint."""
    return {"status": 200}


@tool
def resolve_auth(spec_id: str) -> dict:
    """Look up auth credentials for the endpoint's tenant."""
    return {"token": "..."}


def build_agent():
    model = BedrockModel(
        model_id="us.anthropic.claude-sonnet-4-20250514-v1:0",
        region_name="us-east-1",
        temperature=0.3,
    )
    param_resolver = Agent(
        model=model,
        tools=[lookup_endpoint, execute_endpoint, resolve_auth],
    )
    return param_resolver
