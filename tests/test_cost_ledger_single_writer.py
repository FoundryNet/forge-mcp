"""One writer for `forge_api_usage`, and it is forge-prod.

Found by independent review of the tenancy change, 2026-10-08.

The proxy used to write the cost-ledger row because it authenticated as itself:
forge-prod skipped its own write for a call carrying a PROVEN
`X-Forge-Origin: mcp`, and this server did it instead, under the real caller's
key id. Both halves of that arrangement are gone. The proxy presents the
caller's key, so `_trusted_origin_label` cannot honour the origin claim (a
customer key carries no `metadata.trusted_origin`), forge-prod's skip condition
`_origin != "mcp"` becomes TRUE, and forge-prod logs the row itself.

Two writers into one table with the same `api_key_id` means
`GET /v1/usage/summary` sums every MCP call twice — and at two different
prices, because forge-prod zeroes an abstained call and the proxy did not.
forge-prod's own comment names that outcome: "the ledger and the meter
disagreeing is how a customer comes to be invoiced one number and shown
another."

These tests assert the proxy writes nothing, and that the reason is still true
of forge-prod's source rather than remembered.
"""
from __future__ import annotations

import asyncio
import pathlib
import re

import pytest

import forge_prod_gate
import gating
from identities import SANDBOX_KEY, TENANT_A_KEY
from mcp_client import app_client, session
from toolargs import ARGS

# asyncio_mode = auto in pytest.ini marks the async tests; an explicit module
# mark also lands on the sync ones and emits a warning per test.


async def test_no_tool_call_writes_a_cost_ledger_row(fake_db):
    """n = 32 tools. Not one `forge_api_usage` insert from this process."""
    async with session(TENANT_A_KEY) as s:
        for name in sorted(gating.ALL_TOOLS):
            out = await s.call(name, ARGS[name])
            assert out["ok"], f"{name}: {out.get('error')}"
    # Give any fire-and-forget task a chance to land before asserting absence.
    await asyncio.sleep(0.05)
    rows = [t for t, _ in fake_db.inserts if t == "forge_api_usage"]
    assert not rows, (
        f"the proxy wrote {len(rows)} forge_api_usage row(s); forge-prod writes "
        f"them now, so these are duplicates")


async def test_no_a2a_task_writes_a_cost_ledger_row(fake_db):
    async with app_client() as client:
        for skill, params in (("normalize_telemetry", {"data": {"x": 1}}),
                              ("agent_trust", {})):
            r = await client.post("/a2a/tasks",
                                  headers={"Authorization": f"Bearer {TENANT_A_KEY}",
                                           "Content-Type": "application/json"},
                                  json={"skill_id": skill, "params": params})
            assert r.status_code == 200, r.text[:200]
    await asyncio.sleep(0.05)
    rows = [t for t, _ in fake_db.inserts if t == "forge_api_usage"]
    assert not rows, f"/a2a/tasks wrote {len(rows)} forge_api_usage row(s)"


async def test_log_usage_is_inert_even_if_called(fake_db):
    """Reintroduction variant: the function is kept as a no-op, so an older call
    site cannot resurrect the second writer without the no-op being removed
    first — which this test makes a deliberate act."""
    await gating.log_usage("keyid-aaaa", "predict", 0.10)
    await gating.log_usage(None, "predict", 0.10)
    rows = [t for t, _ in fake_db.inserts if t == "forge_api_usage"]
    assert not rows, "log_usage wrote a row"


def test_the_monthly_cap_counter_is_a_different_table():
    """The cap is NOT the ledger. Removing the ledger write must not remove the
    per-tier cap, which lives in `forge_mcp_usage` via the atomic RPC."""
    import inspect

    src = inspect.getsource(gating.check_and_increment)
    assert "increment_mcp_usage" in src
    assert "forge_api_usage" not in src


async def test_the_cap_fires_exactly_once_per_call(fake_db):
    """Measured, not assumed — the A2A route is a second entry point into the
    same gate and an extra increment there would silently halve a tenant's
    allowance."""
    async with session(TENANT_A_KEY) as s:
        await s.call("get_coverage", {})
    assert len([1 for n, _ in fake_db.rpcs if n == "increment_mcp_usage"]) == 1

    fake_db.rpcs.clear()
    async with app_client() as client:
        r = await client.post("/a2a/tasks",
                              headers={"Authorization": f"Bearer {TENANT_A_KEY}",
                                       "Content-Type": "application/json"},
                              json={"skill_id": "agent_trust", "params": {}})
        assert r.status_code == 200, r.text[:200]
    assert len([1 for n, _ in fake_db.rpcs if n == "increment_mcp_usage"]) == 1

    fake_db.rpcs.clear()
    async with app_client() as client:
        r = await client.get("/a2a/agents",
                             headers={"Authorization": f"Bearer {TENANT_A_KEY}"})
        assert r.status_code == 200
    assert len([1 for n, _ in fake_db.rpcs if n == "increment_mcp_usage"]) == 1


async def test_a_refused_call_does_not_spend_the_allowance(fake_db):
    """A 402 is not a call. Spending a free tenant's allowance on refusals means
    100 refusals exhaust the month."""
    async with session(SANDBOX_KEY) as s:
        for _ in range(3):
            out = await s.call("machine_intelligence", ARGS["machine_intelligence"])
            assert not out["ok"]
    assert not [1 for n, _ in fake_db.rpcs if n == "increment_mcp_usage"], (
        "a payment-required refusal incremented the monthly counter")


# ── The reason, re-read from forge-prod rather than remembered ───────────────

PROD_SRC = forge_prod_gate.api_path()


@pytest.mark.skipif(PROD_SRC is None, reason="forge-prod/api.py not on this machine")
def test_forge_prod_still_writes_the_row_for_a_customer_key_call():
    """The whole argument for removing our write is that forge-prod does it. If
    forge-prod's guard ever changes shape, this test says so instead of leaving
    the ledger with no writer at all."""
    text = pathlib.Path(PROD_SRC).read_text()

    # 1. The origin claim is only honoured for a key whose metadata matches,
    #    so a customer-key call cannot prove origin 'mcp'.
    assert re.search(r"return claimed if trusted and trusted == claimed else None", text), (
        "forge-prod's _trusted_origin_label no longer binds the origin claim to "
        "the key row; re-check whether a customer-key call can now claim 'mcp' "
        "and suppress forge-prod's ledger write")

    # 2. The ledger write is guarded on origin != 'mcp', which is TRUE for us.
    assert re.search(r'_origin\s*!=\s*"mcp"', text), (
        "forge-prod's cost-ledger guard is no longer `_origin != \"mcp\"`; "
        "re-derive whether it writes the row for a customer-key MCP call")

    # 3. It writes into the same table this proxy used to.
    assert '"forge_api_usage"' in text or "forge_api_usage" in text
