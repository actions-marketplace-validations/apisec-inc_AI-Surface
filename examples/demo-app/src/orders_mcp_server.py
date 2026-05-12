"""In-house MCP server exposing order management tools.

Demonstrates:
- MCP server detection (in-house, source-resident)
- Tool catalog extraction from @mcp.tool decorators
- Risk indicators: `in-house MCP server`, `financial action exposed`,
  `destructive action exposed`, `database write exposed`
"""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP


mcp = FastMCP("orders-mcp")


@mcp.tool()
def lookup_order(order_id: str) -> dict:
    """Look up an order by ID."""
    return {"order_id": order_id}


@mcp.tool()
def refund_payment(order_id: str, amount: float) -> dict:
    """Issue a refund against an order."""
    return {"refund_id": "r_123"}


@mcp.tool()
def cancel_order(order_id: str) -> dict:
    """Cancel an order. Irreversible after fulfillment."""
    return {"cancelled": True}


@mcp.tool()
def delete_customer(customer_id: str) -> dict:
    """Hard-delete a customer record. GDPR compliance path."""
    return {"deleted": True}


@mcp.tool()
def update_record(record_id: str, fields: dict) -> dict:
    """Update fields on a record."""
    return {"updated": True}


if __name__ == "__main__":
    mcp.run()
