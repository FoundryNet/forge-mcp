"""cacheScope: private — what is achievable on the pinned line, and the gap.

The MCP 2026-07-28 spec makes `cacheScope` a first-class field on a tool result,
for exactly this server's situation: Smithery proxies user traffic through its
own hosted gateway and mcp.foundrynet.io is Cloudflare-fronted, so there are
HTTP caches between a tenant and their own machine data.

MEASURED on the pinned line and asserted below: neither `fastmcp` (3.4.x, pinned
`<4` because 4.x is a beta that drops the 3.x compat shims this tool surface is
built on) nor the `mcp` SDK it depends on knows the string `cacheScope`, and the
SDK's `LATEST_PROTOCOL_VERSION` is `2025-11-25`. The native field is therefore
NOT achievable here. That is declared, not papered over — and asserted, so that
the day it becomes achievable this test fails and someone has to decide.

What is achievable is done and asserted: `_meta.cacheScope = "private"` on every
tool result, and `Cache-Control: no-store, private` + `Vary: Authorization` on
every tenant-scoped HTTP response.
"""
from __future__ import annotations

import pathlib

import pytest

import gating
from identities import SANDBOX_KEY, TENANT_A_KEY
from mcp_client import MCPSession, app_client, session
from toolargs import ARGS

pytestmark = pytest.mark.asyncio

PRIVATE_PATHS = ["/mcp", "/sse", "/messages", "/a2a/tasks", "/a2a/agents", "/oauth/token"]
PUBLIC_PATHS = ["/.well-known/mcp/server-card.json", "/.well-known/agent.json",
                "/.well-known/oauth-authorization-server", "/health", "/ping"]


# ── The declared gap ─────────────────────────────────────────────────────────

def test_the_pinned_libraries_do_not_support_cachescope_natively():
    """The gap, asserted. If this starts failing, the native field has arrived
    and `_meta` should give way to it."""
    import mcp
    import mcp.types

    assert mcp.types.LATEST_PROTOCOL_VERSION < "2026-07-28", (
        f"the MCP SDK now implements {mcp.types.LATEST_PROTOCOL_VERSION}; "
        f"re-check whether cacheScope is a first-class field and use it")

    found = []
    for mod in (mcp, __import__("fastmcp")):
        root = pathlib.Path(mod.__file__).parent
        for f in root.rglob("*.py"):
            try:
                if "cacheScope" in f.read_text(errors="ignore"):
                    found.append(str(f))
            except OSError:
                pass
    assert not found, (
        f"cacheScope is now implemented in the pinned libraries ({found}); "
        f"switch from the _meta declaration to the native field")


# ── What is achievable: the result-level declaration ─────────────────────────

async def test_every_tool_result_declares_a_private_cache_scope():
    """n = 32 tools. A result that does not declare its scope is a result an
    intermediary may treat as shareable."""
    async with session(TENANT_A_KEY) as s:
        tools = sorted(t.name for t in await __import__("mcp_server").mcp.list_tools())
        missing = []
        for name in tools:
            out = await s.call(name, ARGS[name])
            assert out["ok"], f"{name}: {out.get('error')}"
            meta = (out["result"] or {}).get("_meta") or (out["result"] or {}).get("meta")
            if not isinstance(meta, dict) or meta.get("cacheScope") != "private":
                missing.append((name, meta))
    assert not missing, f"tool results with no private cache scope: {missing}"
    assert len(tools) == 32


async def test_a_refusal_is_covered_by_the_http_half_not_the_meta_half():
    """A 402 body names the caller's tier and the tools THEY can call, so it is
    tenant-scoped too — but a refusal is raised as a `ToolError`, which fastmcp
    converts into the error result itself, so there is no ToolResult for the
    middleware to annotate.

    Deliberate choice: the refusal is covered by the `no-store, private` HTTP
    header, which is the half with teeth, and the error SHAPE is left exactly as
    every deployed client already parses it. Reshaping a live error payload to
    add a field no library reads yet would be a real risk taken for a
    declaration. Asserted here so the decision is recorded rather than looking
    like an oversight.
    """
    async with session(SANDBOX_KEY) as s:
        out = await s.call("machine_intelligence", ARGS["machine_intelligence"])
    assert not out["ok"]
    assert out["error"]["error"] == "payment_method_required"
    # The error payload is unchanged: content text carrying the gate's JSON.
    assert out["text"].startswith("{")
    # And the transport refuses to let it be stored.
    assert "no-store" in (out["cache_control"] or "").lower(), out["cache_control"]


def test_marking_a_result_private_cannot_fail_the_call():
    """Fail-soft: a result shape that cannot carry _meta is returned untouched,
    because a failed annotation must never turn a good call into an error."""
    class _NoMeta:
        __slots__ = ()

    obj = _NoMeta()
    assert gating._mark_private(obj) is obj
    assert gating._mark_private(None) is None

    class _Dict:
        def __init__(self):
            self.meta = {"existing": 1}

    d = _Dict()
    gating._mark_private(d)
    assert d.meta == {"existing": 1, "cacheScope": "private"}

    # An existing declaration is not overwritten.
    class _Already:
        def __init__(self):
            self.meta = {"cacheScope": "public"}

    a = _Already()
    gating._mark_private(a)
    assert a.meta["cacheScope"] == "public"


# ── What is achievable: the HTTP half ────────────────────────────────────────

@pytest.mark.parametrize("path", PRIVATE_PATHS)
async def test_tenant_scoped_responses_are_not_storable(path):
    """`no-cache` is not enough: it permits a cache to STORE the body and only
    requires revalidation — and the revalidation carries the next caller's key.
    The measured default on this build was `no-cache, no-transform`."""
    async with app_client() as client:
        if path in ("/a2a/agents", "/health", "/ping"):
            r = await client.get(path, headers={"Authorization": f"Bearer {TENANT_A_KEY}"})
        else:
            r = await client.post(path, json={},
                                  headers={"Authorization": f"Bearer {TENANT_A_KEY}",
                                           "Content-Type": "application/json"})
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc, f"{path} → Cache-Control: {cc!r} (storable)"
    assert "private" in cc, f"{path} → Cache-Control: {cc!r} (not marked private)"
    assert "authorization" in (r.headers.get("vary") or "").lower(), (
        f"{path} does not Vary on Authorization, so one cache entry can serve "
        f"two keys")


@pytest.mark.parametrize("path", PUBLIC_PATHS)
async def test_public_discovery_stays_cacheable(path):
    """The path that must KEEP working. Discovery payloads are identical for
    every caller; making them uncacheable would cost every directory crawl a
    cold hit for no privacy gain."""
    async with app_client() as client:
        r = await client.get(path)
    assert r.status_code == 200, f"{path} → {r.status_code}"
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" not in cc, f"{path} was made uncacheable: {cc!r}"


async def test_a_route_added_later_is_private_by_default():
    """Reintroduction variant: the private set is matched by PREFIX, so a new
    tenant-scoped route under /mcp or /a2a inherits the header instead of
    needing to be remembered."""
    async with app_client() as client:
        for path in ("/mcp/anything/new", "/a2a/tasks/123", "/a2a/whatever"):
            r = await client.get(path, headers={"Authorization": f"Bearer {TENANT_A_KEY}"})
            cc = (r.headers.get("cache-control") or "").lower()
            assert "no-store" in cc, f"{path} → {cc!r} (status {r.status_code})"
