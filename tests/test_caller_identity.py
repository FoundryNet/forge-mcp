"""Caller-identity propagation to forge-prod (X-Forge-Caller-Key-Id).

forge-mcp proxies every tool call to forge-prod under ONE shared
FOUNDRYNET_API_KEY, so forge-prod metered that key's owner — a
billing_exempt, cardless key — and every paid MCP tool collected $0.00.
forge-prod's fix/metering-spec branch accepts `X-Forge-Caller-Key-Id` and
meters that subject instead. These tests cover this repo's half: putting the
real caller's `forge_api_keys.id` on that header, per request, without
cross-attributing concurrent callers and without leaking a secret.

Run: python3 -m pytest tests/ -v   (from the repo root)
"""
from __future__ import annotations

import asyncio
import contextvars
import types

import pytest

import gating
import mcp_server

HEADER = "X-Forge-Caller-Key-Id"

# The shared proxy key this server authenticates to forge-prod with. It is a
# SECRET and must never appear on the caller-identity header.
PROXY_KEY = "fnet_live_sharedproxysecret_abcdef0123456789"

# Two different customers' keys. `key_id` is forge_api_keys.id — the ROW ID
# that gating.log_usage() is already keyed on — NOT the key itself.
CALLER_A_KEY = "forge_prod_customer_a_secret_zzzzzzzzzzzz"
CALLER_A_ROW = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
CALLER_B_KEY = "forge_prod_customer_b_secret_yyyyyyyyyyyy"
CALLER_B_ROW = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"

_KEYS = {
    CALLER_A_KEY: CALLER_A_ROW,
    CALLER_B_KEY: CALLER_B_ROW,
}

# Lets the stubbed get_http_headers() present a DIFFERENT bearer token to each
# concurrently-running gate. asyncio.gather wraps each coroutine in a Task and
# every Task gets its own copy of the context, so a set() inside one task is
# invisible to its sibling — the same property the production fix relies on.
_inbound_token: contextvars.ContextVar[str] = contextvars.ContextVar(
    "test_inbound_token", default="")


def _fake_mw_context(tool_name: str):
    """Minimal stand-in for fastmcp's MiddlewareContext.

    GatingMiddleware reads `.message.name` and `.fastmcp_context`, and then
    assigns `ctx.state` (note: fastmcp's real Context has NO `state`
    attribute — its API is get_state/set_state — so that dict is an ad-hoc
    attribute bag the middleware creates itself). SimpleNamespace reproduces
    it exactly.
    """
    return types.SimpleNamespace(
        message=types.SimpleNamespace(name=tool_name),
        fastmcp_context=types.SimpleNamespace(),
    )


def _gated_tool_name() -> str:
    """Any real tool except fire_sandbox, which takes a different counter path."""
    return sorted(gating.ALL_TOOLS - {"fire_sandbox"})[0]


@pytest.fixture
def middleware(monkeypatch):
    """A real GatingMiddleware with Supabase/Stripe/ledger stubbed out."""
    monkeypatch.setattr(mcp_server, "FOUNDRYNET_API_KEY", PROXY_KEY)

    monkeypatch.setattr(
        gating, "get_http_headers",
        lambda include=None: {"authorization": f"Bearer {_inbound_token.get()}"})

    def _resolve(token):
        row = _KEYS.get(token)
        if row is None:
            return None
        return {
            "user_id": f"user-of-{row}",
            "tier": "pro",
            "key_id": row,
            "plan": "",
            "stripe_customer_id": None,
        }

    monkeypatch.setattr(gating, "resolve_bearer", _resolve)
    monkeypatch.setattr(gating, "_entitlement", lambda info: "pro")
    monkeypatch.setattr(gating, "check_and_increment",
                        lambda user_id, tier: (True, 1, 10_000))

    async def _no_ledger(*a, **k):
        return None

    monkeypatch.setattr(gating, "log_usage", _no_ledger)
    return gating.GatingMiddleware()


# ── POSITIVE CONTROL ─────────────────────────────────────────────────────────
# This must pass BEFORE and AFTER the change: adding a header must not disturb
# the four headers forge-prod already depends on. X-Forge-Origin in particular
# is the key-bound trusted_origin proof that gates the new header upstream;
# break it and every proxied call loses its origin, not just its metering.

def test_existing_headers_unchanged(monkeypatch):
    monkeypatch.setattr(mcp_server, "FOUNDRYNET_API_KEY", PROXY_KEY)
    h = mcp_server._headers()
    assert h["Authorization"] == f"Bearer {PROXY_KEY}"
    assert h["Content-Type"] == "application/json"
    assert h["User-Agent"] == "FoundryNet-MCP/1.0"
    assert h["X-Forge-Origin"] == "mcp"


def test_headers_outside_any_tool_call_is_present_and_empty(monkeypatch):
    """No identified caller -> header SENT, empty. Never omitted, never None.

    forge-mcp also serves non-MCP HTTP routes (the A2A endpoints), where
    fastmcp's get_context() raises RuntimeError; _headers() must not crash
    there. And forge-prod fails CLOSED on an empty caller id
    (`meter_unattributed ... reason=mcp_caller_unidentified`), which is the
    intended outcome — omitting the header would be indistinguishable from an
    older proxy build that cannot identify callers at all.
    """
    monkeypatch.setattr(mcp_server, "FOUNDRYNET_API_KEY", PROXY_KEY)
    h = mcp_server._headers()
    assert HEADER in h, f"{HEADER} must be sent even when the caller is unknown"
    assert h[HEADER] == "", f"expected empty string, got {h[HEADER]!r}"
    assert h[HEADER] is not None  # httpx rejects None header values outright


def test_accessor_returns_empty_string_not_none():
    assert gating.current_caller_key_id() == ""


# ── THE FIX ──────────────────────────────────────────────────────────────────

def test_upstream_call_carries_the_callers_row_id(middleware):
    """A gated tool call puts the caller's forge_api_keys.id on the header."""
    seen = {}

    async def call_next(ctx):
        seen.update(mcp_server._headers())
        return "ok"

    async def drive():
        _inbound_token.set(CALLER_A_KEY)
        return await middleware.on_call_tool(
            _fake_mw_context(_gated_tool_name()), call_next)

    assert asyncio.run(drive()) == "ok"
    assert seen[HEADER] == CALLER_A_ROW


def test_header_is_the_row_id_never_a_secret(middleware):
    """The value is the ROW ID. Not the key, not its prefix, not its hash.

    This header crosses the wire on every upstream call; a secret on it would
    be a brand-new leak surface, and forge-prod does not need one — it already
    owns forge_api_keys and resolves the row id itself.
    """
    seen = {}

    async def call_next(ctx):
        seen.update(mcp_server._headers())
        return "ok"

    async def drive():
        _inbound_token.set(CALLER_A_KEY)
        await middleware.on_call_tool(
            _fake_mw_context(_gated_tool_name()), call_next)

    asyncio.run(drive())
    value = seen[HEADER]

    assert value == CALLER_A_ROW
    # the caller's own key, in whole or in part
    assert CALLER_A_KEY not in value
    assert "forge_prod_" not in value
    assert gating._hash_api_key(CALLER_A_KEY) not in value
    # and the shared proxy key it is proxied under
    assert PROXY_KEY not in value
    assert "fnet_" not in value
    # nothing key-shaped at all
    assert not value.startswith(gating.ACCEPTED_KEY_PREFIXES)


def test_ctx_state_carries_mcp_key_id(middleware):
    """The gate also stashes the row id on ctx.state alongside mcp_user_id."""
    ctx = _fake_mw_context(_gated_tool_name())

    async def call_next(_):
        return "ok"

    async def drive():
        _inbound_token.set(CALLER_B_KEY)
        await middleware.on_call_tool(ctx, call_next)

    asyncio.run(drive())
    assert ctx.fastmcp_context.state["mcp_key_id"] == CALLER_B_ROW
    # siblings still set
    assert ctx.fastmcp_context.state["mcp_user_id"] == f"user-of-{CALLER_B_ROW}"
    assert ctx.fastmcp_context.state["mcp_tier"] == "pro"


# ── WHY A ContextVar ─────────────────────────────────────────────────────────

def test_concurrent_callers_do_not_cross_attribute(middleware):
    """Two tool calls in flight at once must each see only their OWN caller id.

    This is the whole reason for a ContextVar. The id is set in the gate and
    read later, at the upstream request — with a module-level global or an
    attribute on any shared object, caller B's gate would overwrite caller A's
    id in that window and forge-prod would bill B's usage to A (or vice versa).

    The two events below make that window deterministic rather than lucky:
    neither call reads _headers() until BOTH gates have run.
    """
    a_in_flight = asyncio.Event()
    b_in_flight = asyncio.Event()
    seen: dict[str, str] = {}

    async def _call(token, label, mine, theirs):
        _inbound_token.set(token)

        async def call_next(ctx):
            mine.set()
            await asyncio.wait_for(theirs.wait(), timeout=5)
            # Both gates have now set their caller id. A shared mutable slot
            # would hold whichever ran last; a ContextVar holds ours.
            seen[label] = mcp_server._headers()[HEADER]
            return "ok"

        return await middleware.on_call_tool(
            _fake_mw_context(_gated_tool_name()), call_next)

    async def drive():
        return await asyncio.gather(
            _call(CALLER_A_KEY, "a", a_in_flight, b_in_flight),
            _call(CALLER_B_KEY, "b", b_in_flight, a_in_flight),
        )

    assert asyncio.run(drive()) == ["ok", "ok"]
    assert seen["a"] == CALLER_A_ROW
    assert seen["b"] == CALLER_B_ROW
    assert seen["a"] != seen["b"]


def test_caller_id_does_not_survive_the_call(middleware):
    """Reset in `finally`: a stale id must not leak into a later unattributed
    call, which would silently bill the previous caller."""
    async def call_next(ctx):
        assert gating.current_caller_key_id() == CALLER_A_ROW
        return "ok"

    async def drive():
        _inbound_token.set(CALLER_A_KEY)
        await middleware.on_call_tool(
            _fake_mw_context(_gated_tool_name()), call_next)
        return gating.current_caller_key_id()

    assert asyncio.run(drive()) == ""


def test_caller_id_reset_even_when_the_tool_raises(middleware):
    async def call_next(ctx):
        raise RuntimeError("tool blew up")

    async def drive():
        _inbound_token.set(CALLER_A_KEY)
        with pytest.raises(RuntimeError):
            await middleware.on_call_tool(
                _fake_mw_context(_gated_tool_name()), call_next)
        return gating.current_caller_key_id()

    assert asyncio.run(drive()) == ""
