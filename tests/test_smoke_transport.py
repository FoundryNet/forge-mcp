"""Does the harness actually reach the gate? Everything else depends on it."""
from __future__ import annotations

import pytest

from identities import TENANT_A_KEY
from mcp_client import session

pytestmark = pytest.mark.asyncio


async def test_initialize_and_list_tools():
    async with session(TENANT_A_KEY) as s:
        tools = await s.list_tools()
        names = {t["name"] for t in tools}
        assert len(names) == 32, f"expected 32 tools, got {len(names)}: {sorted(names)}"


async def test_a_tool_call_reaches_upstream(upstream):
    async with session(TENANT_A_KEY) as s:
        out = await s.call("get_coverage", {})
        assert out["ok"], out
    assert len(upstream.requests) == 1
    assert upstream.last.url.path == "/v1/coverage"
