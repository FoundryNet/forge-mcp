"""Tool-call idempotency at the upstream hop.

The proxy retries once on a transient transport failure. Three different
failures were treated as one:

  ConnectError        — the connection never came up; the request was never
                        delivered. Safe to retry anything.
  ReadTimeout         — the request WAS delivered and only the response was
                        lost. The kernel may already have applied it.
  RemoteProtocolError — ambiguous, which resolves the same way as delivered.

A `POST /v1/settle` that read-timed-out was therefore retried blindly, so a
kernel that had already succeeded applied it twice: two work records for one
action, and two metered calls — against the CALLER's key now that the proxy
presents it upstream. A duplicated write and a double charge, from one dropped
response packet.

These tests drive each failure for each method and count the upstream
deliveries.
"""
from __future__ import annotations

import httpx
import pytest

from identities import TENANT_A_KEY
from mcp_client import session

pytestmark = pytest.mark.asyncio

# (tool, args, method, path) — one read, three writes that mutate or settle.
READ_TOOL = ("get_coverage", {}, "GET")
WRITE_TOOLS = [
    ("verify_record", {"payload": {"a": 1}}, "POST"),
    ("normalize_telemetry", {"data": {"SpindleSpeed": 1}}, "POST"),
    ("identify_machine", {"oem": "haas", "model": "VF-2", "serial": "s1"}, "POST"),
    ("delete_automation", {"trigger_id": "t-1"}, "DELETE"),
    ("disable_automation", {"trigger_id": "t-1"}, "PATCH"),
]

FAILURES = {
    "ConnectError": lambda req: httpx.ConnectError("boom", request=req),
    "ReadTimeout": lambda req: httpx.ReadTimeout("boom", request=req),
    "RemoteProtocolError": lambda req: httpx.RemoteProtocolError("boom", request=req),
}


def _fail_first(upstream, make_exc):
    """Fail the first delivery, succeed on any second. Deliveries are counted by
    the recorder, so a withheld retry is visibly one and a fired retry is two."""
    state = {"n": 0}

    def responder(request):
        state["n"] += 1
        if state["n"] == 1:
            raise make_exc(request)
        return httpx.Response(200, json={"ok": True, "attempt": state["n"]})

    upstream.responder = responder
    return state


@pytest.mark.parametrize("failure", sorted(FAILURES))
async def test_a_read_is_retried_on_every_transient_failure(upstream, failure):
    """The path that must KEEP working. GET has no side effect, so losing a
    response to a blip must not surface as an error to the caller."""
    tool, args, _ = READ_TOOL
    _fail_first(upstream, FAILURES[failure])
    async with session(TENANT_A_KEY) as s:
        out = await s.call(tool, args)
    assert out["ok"], f"a retryable {failure} on a GET surfaced as an error: {out.get('error')}"
    assert len(upstream.forge_requests) == 2, (
        f"GET was delivered {len(upstream.forge_requests)} time(s) on {failure}; "
        f"expected a retry")


@pytest.mark.parametrize("tool,args,method", WRITE_TOOLS)
async def test_a_write_is_never_retried_after_delivery(upstream, tool, args, method):
    """ReadTimeout means delivered. The write must NOT be re-sent."""
    _fail_first(upstream, FAILURES["ReadTimeout"])
    async with session(TENANT_A_KEY) as s:
        out = await s.call(tool, args)
    assert not out["ok"], f"{tool} reported success off a lost response"
    assert len(upstream.forge_requests) == 1, (
        f"{method} {tool} was delivered {len(upstream.forge_requests)} times after a "
        f"ReadTimeout — the kernel may have applied it twice")
    assert out["error"].get("retry_withheld") == "non_idempotent_method_delivery_unknown", (
        f"the refusal does not say why the retry was withheld: {out['error']}")


@pytest.mark.parametrize("tool,args,method", WRITE_TOOLS)
async def test_a_write_is_never_retried_after_a_protocol_error(upstream, tool, args, method):
    """RemoteProtocolError is ambiguous, and ambiguity resolves to 'delivered'."""
    _fail_first(upstream, FAILURES["RemoteProtocolError"])
    async with session(TENANT_A_KEY) as s:
        out = await s.call(tool, args)
    assert not out["ok"]
    assert len(upstream.forge_requests) == 1, (
        f"{method} {tool} was re-sent after a RemoteProtocolError "
        f"({len(upstream.forge_requests)} deliveries)")


@pytest.mark.parametrize("tool,args,method", WRITE_TOOLS)
async def test_a_write_IS_retried_when_it_provably_never_arrived(upstream, tool, args,
                                                                 method):
    """The path that must keep working on the other side of the rule: a
    ConnectError proves nothing was delivered, so withholding the retry would
    turn every momentary connection blip into a failed customer write."""
    _fail_first(upstream, FAILURES["ConnectError"])
    async with session(TENANT_A_KEY) as s:
        out = await s.call(tool, args)
    assert out["ok"], f"{tool} failed on a ConnectError that never reached the kernel"
    assert len(upstream.forge_requests) == 2


# ── Reintroduction variant ───────────────────────────────────────────────────

def test_the_retry_rule_is_by_method_not_by_path():
    """Reintroduction variant: the rule must not be a list of paths.

    A path allow-list goes stale the first time a tool is added — and the tool
    that is added is exactly the one nobody remembers to list. The decision is
    made from the HTTP method and the exception class only.
    """
    import inspect

    import mcp_server

    src = inspect.getsource(mcp_server._may_retry)
    assert "/v1/" not in src, "_may_retry is deciding by path"
    assert "GET" in src or "_IDEMPOTENT_METHODS" in src

    # And the rule itself, directly: every unsafe method x every ambiguous
    # failure must be withheld; every safe method must be allowed.
    import httpx as _h

    req = _h.Request("POST", "https://x.invalid/v1/settle")
    for method in ("POST", "PUT", "PATCH", "DELETE", "post", "patch"):
        assert mcp_server._may_retry(method, _h.ReadTimeout("x", request=req)) is False
        assert mcp_server._may_retry(method, _h.RemoteProtocolError("x", request=req)) is False
        assert mcp_server._may_retry(method, _h.ConnectError("x", request=req)) is True
    for method in ("GET", "HEAD", "OPTIONS", "get"):
        for exc in (_h.ReadTimeout("x", request=req),
                    _h.RemoteProtocolError("x", request=req),
                    _h.ConnectError("x", request=req)):
            assert mcp_server._may_retry(method, exc) is True, (method, type(exc).__name__)
    # An unknown method is not a safe method.
    assert mcp_server._may_retry("", _h.ReadTimeout("x", request=req)) is False
    assert mcp_server._may_retry("FROB", _h.ReadTimeout("x", request=req)) is False


async def test_one_tool_call_makes_one_metered_delivery(upstream):
    """Idempotency has a billing face: one tools/call must reach the kernel once
    on the happy path, because the kernel now meters the caller directly."""
    async with session(TENANT_A_KEY) as s:
        out = await s.call("normalize_telemetry", {"data": {"SpindleSpeed": 1}})
    assert out["ok"], out.get("error")
    posts = [r for r in upstream.forge_requests if r.method == "POST"]
    assert len(posts) == 1, f"one call produced {len(posts)} upstream POSTs"


async def test_repeated_identical_reads_do_not_change_the_upstream_identity(upstream):
    """A read repeated inside one session must stay scoped to the same caller —
    i.e. the ContextVar is bound per call and not left behind or overwritten."""
    async with session(TENANT_A_KEY) as s:
        for _ in range(5):
            out = await s.call("get_coverage", {})
            assert out["ok"]
    ids = set(upstream.caller_key_ids())
    assert len(ids) == 1, f"caller identity varied across repeated reads: {ids}"
