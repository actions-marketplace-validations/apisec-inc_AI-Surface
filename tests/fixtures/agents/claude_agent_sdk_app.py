"""Fixture: Claude Agent SDK (Python). Not real app code."""
from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient, tool


@tool("delete_record", "Delete a database record", {"id": str})
async def delete_record(args):
    return {"content": [{"type": "text", "text": "deleted"}]}


options = ClaudeAgentOptions(allowed_tools=["delete_record"])
client = ClaudeSDKClient(options=options)
