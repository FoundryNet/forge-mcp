"""The whole 32-tool surface, swept — tenancy and the reintroduction variants.

The nine tools in `test_tenancy_isolation.py` are the ones whose leak is easiest
to describe. They are not the whole surface. This file calls EVERY tool and
asserts the same property for each, so a tool added later inherits the check
instead of quietly not having one.
"""
from __future__ import annotations

import asyncio
import inspect
import pathlib
import re

import pytest

import gating
import mcp_server
from identities import (
    SERVER_SHARED_KEY,  # noqa: F401 — used by the leak assertions
    TENANT_A_KEY,
    TENANT_A_KEY_ID,
    TENANT_B_KEY,
    TENANT_B_KEY_ID,
)
from mcp_client import session
from toolargs import ARGS

# asyncio_mode = auto in pytest.ini marks the async tests; an explicit module
# mark also lands on the sync ones and emits a warning per test.


async def _registry_names():
    return sorted(t.name for t in await mcp_server.mcp.list_tools())


async def test_every_tool_has_sweep_arguments():
    """The sweep below is only a measurement if it covers everything."""
    names = await _registry_names()
    missing = [n for n in names if n not in ARGS]
    extra = [n for n in ARGS if n not in names]
    assert not missing, f"tools with no sweep arguments: {missing}"
    assert not extra, f"sweep arguments for tools that do not exist: {extra}"
    assert len(names) == 32, f"tool count changed: {len(names)}"


# ── The sweep: n = 32 ────────────────────────────────────────────────────────

async def test_every_tool_presents_the_callers_identity_upstream(upstream):
    """For every tool, for two different tenants: the upstream request must
    carry THAT tenant's key and name THAT tenant. n = 32 tools x 2 tenants."""
    names = await _registry_names()
    checked = 0
    no_upstream = []
    for token, key_id in ((TENANT_A_KEY, TENANT_A_KEY_ID),
                          (TENANT_B_KEY, TENANT_B_KEY_ID)):
        async with session(token) as s:
            for name in names:
                upstream.reset()
                out = await s.call(name, ARGS[name])
                assert out["ok"], f"{name} refused for a pro tenant: {out.get('error')}"
                reqs = upstream.forge_requests
                if not reqs:
                    no_upstream.append(name)
                    continue
                for req in reqs:
                    auth = req.headers.get("authorization", "")
                    bearer = auth[7:].strip() if auth.lower().startswith("bearer ") else auth
                    assert bearer == token, (
                        f"{name}: upstream bearer was {bearer!r}, not this caller's key")
                    assert req.headers.get("x-forge-caller-key-id") == key_id, (
                        f"{name}: upstream caller id was "
                        f"{req.headers.get('x-forge-caller-key-id')!r}, expected {key_id!r}")
                    checked += 1
    assert checked >= 64, f"only {checked} upstream requests inspected"
    assert not no_upstream, f"tools that made no upstream call at all: {no_upstream}"


# ── Reintroduction variants ──────────────────────────────────────────────────

async def test_the_shared_server_key_never_appears_upstream(upstream):
    """Reintroduction variant 1: the leak came back as a FALLBACK.

    The most likely way this defect returns is not someone deleting the fix; it
    is `caller.upstream_key or FOUNDRYNET_API_KEY`, which looks defensive and
    restores the exposure for every caller whose context is missing. No tool
    call by any tenant may ever present the shared key.
    """
    names = await _registry_names()
    async with session(TENANT_A_KEY) as s:
        for name in names:
            await s.call(name, ARGS[name])
    leaked = [r.url.path for r in upstream.requests
              if SERVER_SHARED_KEY in r.headers.get("authorization", "")]
    assert not leaked, f"the shared proxy key reached forge-prod on: {leaked}"


def test_upstream_hop_refuses_when_no_caller_is_bound():
    """Reintroduction variant 2: `_headers()` must have NO default identity.

    Called with nothing bound — the state a new, ungated code path starts in —
    it must raise rather than return a usable header set.
    """
    assert gating.current_caller() is None
    with pytest.raises(gating.TenantContextUnavailable) as ei:
        mcp_server._headers()
    assert ei.value.reason == "no_caller_bound"


def test_upstream_hop_refuses_a_caller_it_cannot_name():
    """Reintroduction variant 3: a caller with no key_id is not a tenant.

    `forge_api_keys.permissions = NULL` means FULL ACCESS in forge-prod's
    `_require_perm`, and an empty-string id reads as "no filter" in more than
    one query builder. An unnameable caller must refuse, not widen.
    """
    reset = gating.bind_caller({"key_id": "", "user_id": "u", "via": "key"}, TENANT_A_KEY)
    try:
        with pytest.raises(gating.TenantContextUnavailable) as ei:
            mcp_server._headers()
        assert ei.value.reason == "caller_unidentified"
    finally:
        gating.release_caller(reset)


def test_oauth_token_callers_are_refused_not_run_as_the_proxy():
    """Reintroduction variant 4: an OAuth JWT carries a key id but not a key.

    The tempting shortcut is to fall back to the shared key for JWT callers,
    "since we know who they are". We know who they are and cannot prove it to
    forge-prod, so the call must refuse. (Owner decision P-12.)
    """
    reset = gating.bind_caller(
        {"key_id": TENANT_A_KEY_ID, "user_id": "u", "via": "jwt"}, "a.b.c")
    try:
        with pytest.raises(gating.TenantContextUnavailable) as ei:
            mcp_server._headers()
        assert ei.value.reason == "oauth_token_cannot_be_scoped"
        assert SERVER_SHARED_KEY not in ei.value.detail
    finally:
        gating.release_caller(reset)


def test_no_upstream_header_builder_reads_the_shared_key():
    """Reintroduction variant 5: static. The shared key must not be readable
    from the header builder at all, so the fallback cannot be written by
    accident. `FOUNDRYNET_API_KEY` may appear only where it is CONFIGURED or
    REPORTED, never where a request is built."""
    src = inspect.getsource(mcp_server._headers)
    body = src.split('"""')[-1]      # everything after the docstring
    assert "FOUNDRYNET_API_KEY" not in body, (
        "_headers() references the shared server key again")

    # And nowhere in the file may it be put ON a request. Matching on the two
    # things that turn a value into a credential — `Authorization` and `Bearer`
    # — rather than on an allow-list of lines, which is the shape that goes
    # stale the first time someone reflows a comment.
    text = pathlib.Path(mcp_server.__file__).read_text()
    offending = [(i + 1, ln.strip()) for i, ln in enumerate(text.splitlines())
                 if "FOUNDRYNET_API_KEY" in ln
                 and ("Authorization" in ln or "Bearer" in ln)]
    assert not offending, (
        f"the shared server key is being put on a request again: {offending}")


async def test_an_oauth_caller_gets_a_PARSEABLE_refusal_over_the_wire(upstream):
    """Review gap: the refusal was only ever asserted by calling `_headers()`
    directly, so nobody noticed the over-the-wire shape was prose.

    fastmcp turns any exception raised INSIDE `call_next` into
    `ToolError(f"Error calling tool {name!r}: {e}")` one layer below the
    middleware, so a refusal raised at the upstream hop reached the client as a
    sentence — unparseable by the agent it is meant to redirect — and logged an
    ERROR traceback for a routine refusal on every call. The gate now refuses
    before `call_next`. n = 32 tools.
    """
    import gating as g
    from mcp_client import MCPSession, app_client

    if not g.oauth_enabled():
        pytest.skip("OAuth signing not configured in this harness")
    minted = g.issue_access_token("harness", TENANT_A_KEY)
    assert minted and minted.get("access_token")

    names = await _registry_names()
    async with app_client() as client:
        s = MCPSession(client, minted["access_token"])
        await s.initialize()
        for name in names:
            upstream.reset()
            out = await s.call(name, ARGS[name])
            assert not out["ok"], f"{name} ran under an OAuth token"
            assert out["error"].get("error") == "tenant_context_unavailable", (
                f"{name} refused unparseably: {out['error']}")
            assert out["error"].get("reason") == "oauth_token_cannot_be_scoped", out["error"]
            assert SERVER_SHARED_KEY not in (out.get("text") or "")
            assert upstream.forge_requests == [], f"{name} reached the kernel"


async def test_an_oauth_caller_is_refused_before_spending_anything(fake_db):
    """And the refusal costs them nothing. It used to be raised at the upstream
    hop, i.e. after the cap counter had already spent a call — and after
    `fire_sandbox` had spent one of its TEN LIFETIME fires and really posted to
    the sandbox endpoint."""
    import gating as g
    from mcp_client import MCPSession, app_client

    if not g.oauth_enabled():
        pytest.skip("OAuth signing not configured in this harness")
    minted = g.issue_access_token("harness", TENANT_A_KEY)
    async with app_client() as client:
        s = MCPSession(client, minted["access_token"])
        await s.initialize()
        for _ in range(5):
            assert not (await s.call("get_coverage", {}))["ok"]
        assert not (await s.call("fire_sandbox", ARGS["fire_sandbox"]))["ok"]
    assert not [1 for n, _ in fake_db.rpcs if n == "increment_mcp_usage"], (
        "a refused OAuth call incremented a counter")


def test_the_raw_key_is_not_in_the_caller_identity_repr():
    """A frozen dataclass's generated repr would print the live customer
    credential. Nothing prints it today; that is one error reporter away from
    being untrue."""
    import gating as g

    c = g.CallerIdentity(key_id=TENANT_A_KEY_ID, user_id="u", entitlement="pro",
                         via="key", upstream_key=TENANT_A_KEY)
    for rendered in (repr(c), str(c), f"{c}", "{}".format(c)):
        assert TENANT_A_KEY not in rendered, f"the key appears in {rendered!r}"
    assert c.upstream_key == TENANT_A_KEY, "the field itself must still work"


def test_an_unnamed_auth_method_does_not_inherit_key_passthrough():
    """`bind_caller` used to default an unknown `via` to "key", which would have
    forwarded whatever string a future auth path presented as a bearer."""
    import gating as g

    for info in ({"key_id": "k", "user_id": "u"},
                 {"key_id": "k", "user_id": "u", "via": ""},
                 {"key_id": "k", "user_id": "u", "via": "cookie"},
                 {"key_id": "k", "user_id": "u", "via": "KEY "}):
        reset = g.bind_caller(info, "something-the-caller-sent")
        try:
            if (info.get("via") or "").strip().lower() == "key":
                continue
            assert g.current_caller().upstream_key is None, info
            with pytest.raises(g.TenantContextUnavailable):
                mcp_server._headers()
        finally:
            g.release_caller(reset)


async def test_the_caller_key_id_is_not_a_credential_the_caller_chooses(upstream):
    """Reintroduction variant 6: no caller-supplied value weakens the check.

    A client that sends its own `X-Forge-Caller-Key-Id` must not have it
    forwarded: the id upstream is the one the GATE resolved, every time.
    """
    from mcp_client import MCPSession, app_client

    async with app_client() as client:
        s = MCPSession(client, TENANT_A_KEY)
        base = s._headers

        def _hdrs(extra=None, _b=base):
            h = _b(extra)
            h["X-Forge-Caller-Key-Id"] = TENANT_B_KEY_ID
            h["X-Forge-Origin"] = "mcp"
            return h

        s._headers = _hdrs  # type: ignore[assignment]
        await s.initialize()
        upstream.reset()
        out = await s.call("get_coverage", {})
        assert out["ok"], out.get("error")
    assert upstream.caller_key_ids() == [TENANT_A_KEY_ID], (
        f"a client-supplied caller id was forwarded: {upstream.caller_key_ids()}")
