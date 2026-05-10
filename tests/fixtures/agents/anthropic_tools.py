"""Synthetic Anthropic-shape tools fixture: destructive admin tools."""


def call_admin_agent():
    tools = [
        {"name": "delete_record", "description": "remove a row by id"},
        {"name": "fetch_user", "description": "read a user record"},
    ]
    # Pretend we'd pass these to anthropic.messages.create(tools=tools, ...)
    return tools
