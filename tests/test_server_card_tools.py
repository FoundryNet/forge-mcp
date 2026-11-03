"""The server card's tools[] is hand-written, so it can drift from the real surface.

It did: #17 added four alert tools, the card's computed count said 36 and its
list still named 32. This pins the list to `mcp.list_tools()`.
"""
from __future__ import annotations

import mcp_server
from mcp_client import app_client


async def test_server_card_lists_exactly_the_registered_tools():
    real = {t.name for t in await mcp_server.mcp.list_tools()}
    async with app_client() as client:
        r = await client.get("/.well-known/mcp/server-card.json")
    assert r.status_code == 200
    card = [t["name"] for t in r.json()["tools"]]
    assert len(card) == len(set(card)), "duplicate names on the server card"
    assert set(card) == real, (
        f"missing from card: {sorted(real - set(card))}; "
        f"not a real tool: {sorted(set(card) - real)}")
