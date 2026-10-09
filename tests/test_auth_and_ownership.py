"""Auth matrix and ownership: the gate's decision must come only from the key.

Two properties, both the kind that fail quietly:

  1. Every refusal has the right shape and the right reason. `402` means
     billing and `403` on a guardrail write means human-only BY DESIGN — a
     "fix" that turns either into the other is a regression, not an
     improvement, so both are pinned.
  2. Nothing a caller SENDS can change what the gate decides. Not an argument,
     not a header, not a tool name's casing. The decision is a function of the
     `forge_api_keys` row and nothing else.

Plus the trap this codebase has already been bitten by: a gate that reads a
column missing from its select list sees `None` and silently never fires. Every
test here checks the path that must KEEP working alongside the one it blocks.
"""
from __future__ import annotations

import pytest

import gating
from identities import (
    METERED_NOCARD,
    SANDBOX_KEY,
    TENANT_A_KEY,
    TENANT_A_KEY_ID,
    TENANT_B_KEY,
)
from mcp_client import MCPSession, app_client, session
from toolargs import ARGS

# asyncio_mode = auto in pytest.ini marks the async tests; an explicit module
# mark also lands on the sync ones and emits a warning per test.


# ── The refusal matrix ───────────────────────────────────────────────────────

async def test_unknown_tool_is_never_routed_to_the_paywall():
    """A typo must read as 'unknown tool', not 'pay us'. Existence is checked
    BEFORE entitlement, for every tier, including the free one."""
    for token in (TENANT_A_KEY, SANDBOX_KEY, METERED_NOCARD):
        async with session(token) as s:
            for bogus in ("predict_future", "PREDICT", "normalize", "settle",
                          "attest_machine_action", "verify_on_chain", ""):
                out = await s.call(bogus, {})
                assert not out["ok"], f"{bogus!r} was callable"
                assert out["error"]["error"] in ("unknown_tool", "invalid_params"), (
                    f"{bogus!r} on {token[:14]}… → {out['error']}")


async def test_sandbox_key_is_refused_every_paid_tool_and_allowed_every_free_one(upstream):
    """Both halves, counted. n = 32."""
    paid = sorted(gating.ALL_TOOLS - gating.FREE_TOOLS)
    free = sorted(gating.FREE_TOOLS)
    async with session(SANDBOX_KEY) as s:
        for name in paid:
            upstream.reset()
            out = await s.call(name, ARGS[name])
            assert not out["ok"], f"sandbox key ran paid tool {name}"
            assert out["error"]["error"] == "payment_method_required", out["error"]
            assert upstream.forge_requests == [], f"{name} reached the kernel"
        for name in free:
            upstream.reset()
            out = await s.call(name, ARGS[name])
            assert out["ok"], f"sandbox key refused FREE tool {name}: {out.get('error')}"
    assert len(paid) + len(free) == 32


async def test_metered_key_with_no_card_gets_only_the_truly_free_set(upstream):
    """A metered key with no payment method is narrower than the free tier, and
    must be refused everything else with the billing error — the REST 402."""
    truly_free = sorted(gating.TRULY_FREE_TOOLS)
    async with session(METERED_NOCARD) as s:
        for name in truly_free:
            upstream.reset()
            out = await s.call(name, ARGS[name])
            assert out["ok"], f"{name} refused for a metered key: {out.get('error')}"
        for name in sorted(gating.ALL_TOOLS - gating.TRULY_FREE_TOOLS):
            upstream.reset()
            out = await s.call(name, ARGS[name])
            assert not out["ok"], f"metered-no-card key ran {name}"
            assert out["error"]["error"] == "payment_method_required", out["error"]
            assert upstream.forge_requests == []


async def test_a_402_body_lists_tools_the_caller_can_actually_call():
    """The refusal that is supposed to unblock someone must not walk them into a
    second refusal. The lists are DERIVED from the frozensets the gate enforces,
    so they follow a tool that moves between tiers."""
    async with session(SANDBOX_KEY) as s:
        out = await s.call("machine_intelligence", ARGS["machine_intelligence"])
    err = out["error"]
    assert set(err["free_tools"]) == set(gating.FREE_TOOLS)
    assert set(err["sandbox_tools"]) == set(gating.FREE_TOOLS)
    # And every name it offers really is callable.
    async with session(SANDBOX_KEY) as s:
        for name in err["free_tools"]:
            assert (await s.call(name, ARGS[name]))["ok"], (
                f"the 402 body offered {name}, which is then refused")


async def test_a_402_body_for_a_metered_key_offers_the_metered_free_set():
    async with session(METERED_NOCARD) as s:
        out = await s.call("predict", ARGS["predict"])
        err = out["error"]
        assert set(err["free_tools"]) == set(gating.TRULY_FREE_TOOLS)
        for name in err["free_tools"]:
            assert (await s.call(name, ARGS[name]))["ok"], (
                f"the 402 body offered {name}, which is then refused")


async def test_the_monthly_cap_is_enforced_and_is_per_tenant(upstream, fake_db,
                                                             monkeypatch):
    """A cap that leaked across tenants would let one tenant exhaust another."""
    monkeypatch.setattr(gating, "FREE_CAP", 3)
    async with session(SANDBOX_KEY) as s:
        oks = [(await s.call("get_coverage", {}))["ok"] for _ in range(5)]
    assert oks[:3] == [True, True, True], oks
    assert oks[3:] == [False, False], oks

    # A different tenant's allowance is untouched.
    async with session(TENANT_A_KEY) as s:
        assert (await s.call("get_coverage", {}))["ok"]


async def test_the_cap_counter_is_keyed_on_the_tenant_not_the_proxy(fake_db):
    """If the counter were keyed on the shared proxy identity, every tenant
    would share one allowance — and the first busy tenant would rate-limit
    everybody."""
    async with session(TENANT_A_KEY) as s:
        await s.call("get_coverage", {})
    async with session(TENANT_B_KEY) as s:
        await s.call("get_coverage", {})
    users = {p["p_user_id"] for n, p in fake_db.rpcs if n == "increment_mcp_usage"}
    assert len(users) == 2, f"the cap counter saw {len(users)} distinct subject(s): {users}"


# ── Nothing the caller sends changes the decision ────────────────────────────

async def test_no_tool_argument_can_change_the_tier_decision(upstream):
    """Allowlist, never denylist; no caller-supplied parameter weakens a check."""
    sneaky = [
        {"tier": "pro"}, {"plan": "production"}, {"free_tier": False},
        {"entitlement": "pro"}, {"user_id": "someone-else"},
        {"key_id": TENANT_A_KEY_ID}, {"_entitlement": "pro"},
        {"permissions": None},
    ]
    async with session(SANDBOX_KEY) as s:
        for extra in sneaky:
            upstream.reset()
            args = dict(ARGS["machine_intelligence"])
            args.update(extra)
            out = await s.call("machine_intelligence", args)
            assert not out["ok"], f"arguments {extra} widened the tier"
            assert upstream.forge_requests == []


async def test_no_request_header_can_change_the_tier_decision(upstream):
    """Same property on the transport. The shared proxy key's privileges are
    claimed by metadata on a key row, never by a header."""
    forged = [
        {"X-Forge-Origin": "mcp"},
        {"X-Forge-Caller-Key-Id": TENANT_A_KEY_ID},
        {"X-Forge-Tier": "pro"},
        {"X-Forge-Plan": "production"},
        {"X-Forge-Billing-Exempt": "true"},
        {"X-Forge-Trusted-Origin": "mcp"},
    ]
    async with app_client() as client:
        for extra in forged:
            s = MCPSession(client, SANDBOX_KEY)
            base = s._headers
            s._headers = lambda e=None, _b=base, _x=extra: {**_b(e), **_x}  # type: ignore
            await s.initialize()
            upstream.reset()
            out = await s.call("fleet_health", ARGS["fleet_health"])
            assert not out["ok"], f"headers {extra} widened the tier"
            assert upstream.forge_requests == []


async def test_tool_name_casing_and_whitespace_do_not_bypass_the_allowlist(upstream):
    """Membership is exact-match on a frozenset. A normaliser added later that
    stripped or lowercased would be a bypass, so the variants are pinned as
    unknown rather than as refused-but-recognised."""
    async with session(SANDBOX_KEY) as s:
        for variant in ("Fleet_Health", "FLEET_HEALTH", " fleet_health",
                        "fleet_health ", "fleet_health\n", "fleet%5Fhealth"):
            upstream.reset()
            out = await s.call(variant, {})
            assert not out["ok"], f"{variant!r} was callable"
            assert out["error"]["error"] in ("unknown_tool", "invalid_params")
            assert upstream.forge_requests == []


# ── Ownership: the caller's ids go upstream verbatim, under their own key ────

async def test_caller_supplied_ids_are_passed_through_unchanged(upstream):
    """Ownership is enforced by forge-prod against the authenticated key. The
    proxy's job is to not interfere: it must neither default an id nor rewrite
    one, because either would decide ownership here, without the data to do it.
    """
    probes = [
        ("list_automations", {"machine_id": "m-other-tenant"}, "m-other-tenant"),
        ("query_machine_history", {"mint_id": "MINT-someone-else"}, "MINT-someone-else"),
        ("delete_automation", {"trigger_id": "t-not-mine"}, "t-not-mine"),
        ("energy_consumption", {"machine_id": "m-not-mine"}, "m-not-mine"),
    ]
    async with session(TENANT_A_KEY) as s:
        for tool, args, needle in probes:
            upstream.reset()
            out = await s.call(tool, args)
            assert out["ok"], f"{tool}: {out.get('error')}"
            req = upstream.forge_requests[-1]
            whole = str(req.url) + (req.content or b"").decode("utf-8", "replace")
            assert needle in whole, f"{tool} did not forward {needle!r}: {whole[:200]}"
            # ...and it went up under the CALLER's key, which is what makes
            # forge-prod's ownership check mean anything.
            assert req.headers.get("authorization") == f"Bearer {TENANT_A_KEY}"


async def test_the_proxy_adds_no_identity_of_its_own_to_a_body(upstream):
    """A request body that carried a user_id or key chosen by the proxy would be
    a second, weaker ownership claim travelling beside the real one."""
    async with session(TENANT_A_KEY) as s:
        for name in sorted(gating.ALL_TOOLS):
            upstream.reset()
            await s.call(name, ARGS[name])
            for body in upstream.bodies:
                if not isinstance(body, dict):
                    continue
                for forbidden in ("user_id", "api_key", "key_id", "tenant_id",
                                  "authorization", "tier", "plan"):
                    assert forbidden not in body, (
                        f"{name} sent {forbidden!r} in its upstream body: {body}")


# ── The column trap ──────────────────────────────────────────────────────────

def test_the_key_lookup_selects_every_column_the_gate_reads():
    """A gate reading a `forge_api_keys` column that is missing from the select
    list sees `None` and silently never fires — that is how a billing allow-list
    once 402'd the MCP proxy. Asserted against the source of the SELECT itself.
    """
    import inspect
    import re

    src = inspect.getsource(gating.validate_key)
    m = re.search(r'\.select\(\s*((?:"[^"]*"\s*)+)\)', src, re.S)
    assert m, "could not find the select list in validate_key"
    selected = {c.strip() for c in "".join(
        re.findall(r'"([^"]*)"', m.group(1))).split(",") if c.strip()}

    # Every column read by the row -> tier / entitlement path.
    needed = {"id", "user_id", "status", "free_tier", "is_demo", "plan",
              "stripe_customer_id", "rotation_grace_until", "expires_at"}
    missing = needed - selected
    assert not missing, (
        f"the gate reads {sorted(missing)} but validate_key does not select them; "
        f"they would read as None and the checks that use them would never fire")

    # And the row-reading functions must not reach for anything beyond it.
    for fn in (gating._tier_for_row, gating._entitlement):
        for col in re.findall(r'row\.get\("([^"]+)"\)', inspect.getsource(fn)):
            assert col in selected, f"{fn.__name__} reads unselected column {col!r}"


def test_a_revoked_status_is_not_merely_absent_from_the_allowlist():
    """Liveness is an allowlist of statuses, so a status nobody anticipated is
    dead rather than alive."""
    import inspect

    src = inspect.getsource(gating.validate_key)
    assert '.in_("status", ["active", "rotating"])' in src, (
        "key liveness is no longer an allowlist of statuses")
