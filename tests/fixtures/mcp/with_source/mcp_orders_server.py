"""Synthetic in-house MCP server fixture used by McpServerDetector tests.

Do NOT actually run this file; the dependencies are stubbed for fixture
purposes only.
"""
from __future__ import annotations

from mcp.server import Server  # type: ignore[import-not-found]

server = Server("orders-mcp")


@server.tool()
def lookup_order(order_id: str) -> dict:
    """Return basic order metadata."""
    return {"id": order_id}


@server.tool()
async def refund_payment(order_id: str, amount: float) -> dict:
    """Refund the given amount for an order."""
    return {"refunded": True}


@server.tool()
def cancel_order(order_id: str) -> dict:
    """Cancel an order."""
    return {"cancelled": True}


if __name__ == "__main__":
    server.run()
