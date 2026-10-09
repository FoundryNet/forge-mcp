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

# asyncio_mode = auto in pytest.ini marks the async tests; an explicit module
# mark also lands on the sync ones and emits a warning per test.

TS = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]

# (tool, args, method) — one read, then the calls that really do mutate or
# settle, then the POSTs that only compute.
READ_TOOL = ("get_coverage", {}, "GET")

# The unsafe set, which is the SMALL stable one: a settlement, a signed record,
# a metered normalize, and the trigger lifecycle.
WRITE_TOOLS = [
    ("verify_record", {"payload": {"a": 1}}, "POST"),
    ("normalize_telemetry", {"data": {"SpindleSpeed": 1}}, "POST"),
    ("delete_automation", {"trigger_id": "t-1"}, "DELETE"),
    ("disable_automation", {"trigger_id": "t-1"}, "PATCH"),
    ("restore_automation", {"trigger_id": "t-1"}, "PATCH"),
    # predict_breach SETTLES when asked to, so the body decides, not the path.
    ("predict_breach", {"time_series": TS, "threshold": 100.0, "settle": True}, "POST"),
]

# POSTs that compute and return. These are also the SLOWEST calls on the service
# — REQUEST_TIMEOUT defaults to 120s for the TimesFM set — so a ReadTimeout is
# their MOST likely failure, and withholding their retry was the regression the
# first version of this rule introduced. Each is declared safe on the allowlist
# in mcp_server, not inferred.
SAFE_POST_TOOLS = [
    ("predict", {"time_series": TS}, "POST"),
    ("predict_batch", {"machines": [{"machine_id": "m-1", "time_series": TS}]}, "POST"),
    ("remaining_life", {"time_series": TS, "failure_threshold": 100.0}, "POST"),
    ("fleet_health", {"machines": [{"machine_id": "m-1"}]}, "POST"),
    ("detect_anomalies", {"values": TS}, "POST"),
    ("machine_intelligence", {"machine_id": "m-1", "telemetry": {"x": 1}}, "POST"),
    ("check_guardrail", {"machine_id": "m-1", "proposed": {"spindle_speed_rpm": 1}}, "POST"),
    ("diagnose_machine", {"machine_id": "m-1"}, "POST"),
    # The tool's own docstring: "Idempotent — calling again with the same
    # (oem, model, serial) returns the same mint_id."
    ("identify_machine", {"oem": "haas", "model": "VF-2", "serial": "s1"}, "POST"),
    # settle omitted entirely, i.e. no side effect asked for.
    ("predict_breach", {"time_series": TS, "threshold": 100.0}, "POST"),
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


@pytest.mark.parametrize("tool,args,method", SAFE_POST_TOOLS)
async def test_a_computing_post_is_retried_on_every_transient_failure(
        upstream, tool, args, method):
    """The path that must KEEP working, and the one the method-only rule broke.

    A POST that computes has nothing to duplicate, and these are exactly the
    calls whose responses get lost: inference that legitimately runs for 30s+.
    """
    for failure in sorted(FAILURES):
        upstream.reset()
        _fail_first(upstream, FAILURES[failure])
        async with session(TENANT_A_KEY) as s:
            out = await s.call(tool, args)
        assert out["ok"], (
            f"{tool} failed on a retryable {failure} even though it only computes: "
            f"{out.get('error')}")
        assert len(upstream.forge_requests) == 2, (
            f"{tool} was not retried after {failure} "
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

def test_the_retry_rule_is_an_allowlist_that_defaults_to_withholding():
    """Reintroduction variant: an undeclared path must not be retried.

    The safe set is the one that grows — every new read-only inference endpoint
    joins it — and the unsafe set is small and stable. So the rule is an
    allowlist, and the default for anything nobody classified is to withhold.
    A denylist here would mean the next mutating endpoint is retried by default,
    and the endpoint nobody remembers to list is always the new one.
    """
    import httpx as _h

    import mcp_server

    req = _h.Request("POST", "https://x.invalid/v1/settle")
    delivered = (_h.ReadTimeout("x", request=req),
                 _h.RemoteProtocolError("x", request=req))
    never = _h.ConnectError("x", request=req)

    # Safe methods: always.
    for method in ("GET", "HEAD", "OPTIONS", "get"):
        for exc in delivered + (never,):
            assert mcp_server._may_retry(method, exc, "/v1/anything") is True

    # Unsafe methods on an UNDECLARED path: only when never delivered.
    for method in ("POST", "PUT", "PATCH", "DELETE", "post", "", "FROB"):
        for exc in delivered:
            assert mcp_server._may_retry(method, exc, "/v1/brand_new_endpoint") is False, method
        assert mcp_server._may_retry(method, never, "/v1/brand_new_endpoint") is True, method

    # The four paths that must NEVER be re-sent after delivery, named.
    for path in ("/v1/settle", "/v1/verify_record", "/v1/normalize",
                 "/v1/triggers/t-1", "/v1/triggers/t-1/restore"):
        for exc in delivered:
            assert mcp_server._may_retry("POST", exc, path) is False, path
            assert mcp_server._may_retry("PATCH", exc, path) is False, path
            assert mcp_server._may_retry("DELETE", exc, path) is False, path

    # Declared-safe POSTs: retried even after delivery.
    for path in sorted(mcp_server._SAFE_POST_PATHS) + ["/v1/diagnose/m-1"]:
        for exc in delivered:
            assert mcp_server._may_retry("POST", exc, path) is True, path
        # ...but only for POST. The same path under a mutating method is not
        # covered by a POST allowlist.
        assert mcp_server._may_retry("DELETE", delivered[0], path) is False, path

    # The conditional one: the BODY decides, and only ever to withhold.
    pb = "/v1/predict_breach"
    assert mcp_server._may_retry("POST", delivered[0], pb, {}) is True
    assert mcp_server._may_retry("POST", delivered[0], pb, None) is True
    assert mcp_server._may_retry("POST", delivered[0], pb, {"settle": False}) is True
    assert mcp_server._may_retry("POST", delivered[0], pb, {"settle": True}) is False
    assert mcp_server._may_retry("POST", delivered[0], pb, {"settle": "yes"}) is False
    assert mcp_server._may_retry("POST", delivered[0], pb, {"settle": 1}) is False

    # Path matching is anchored: a lookalike is not the declared path.
    for near in ("/v1/predictx", "/v2/predict", "/v1/predict/settle",
                 "/evil/v1/predict"):
        assert mcp_server._may_retry("POST", delivered[0], near) is False, near


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
