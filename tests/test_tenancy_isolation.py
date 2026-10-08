"""D1 — two-tenant + keyless isolation, measured at the upstream hop.

The MCP server is a proxy. Whatever it does with the caller's key at the door,
the only thing forge-prod ever sees is the request this server makes on the
caller's behalf — and forge-prod scopes every row it returns to the identity on
THAT request. So "are two MCP tenants isolated?" is not a question about the
gate; it is a question about which identity leaves this process.

That is what these tests measure: for each of two distinct paying tenants, and
for a free tenant, what identity does the proxy present upstream?

Severity, stated plainly, because these tests encode a live finding: several
tools take no machine argument at all (`fleet_oee`, `shift_report`,
`fleet_health`, `list_agents`, `list_automations` is per-machine but
`shift_report` and `fleet_oee` are account-wide). Whatever account the upstream
identity names, those tools return THAT account's entire floor. If every tenant
presents the same upstream identity, every tenant reads the same floor.
"""
from __future__ import annotations

import pytest

from identities import (
    SANDBOX_KEY,
    SERVER_SHARED_KEY,
    TENANT_A_KEY,
    TENANT_A_KEY_ID,
    TENANT_B_KEY,
    TENANT_B_KEY_ID,
)
from mcp_client import session

pytestmark = pytest.mark.asyncio

# Tools that take NO machine/tenant argument and therefore return whatever the
# upstream identity's whole account holds. These are the blast radius.
ACCOUNT_WIDE_TOOLS = [
    ("fleet_oee", {}),
    ("shift_report", {}),
    ("list_agents", {}),
    ("prediction_accuracy", {}),
]

# Tools that take a machine_id the caller supplies. A caller who can name
# another tenant's machine reads it, because the upstream identity — not the
# argument — is what forge-prod scopes on.
MACHINE_SCOPED_TOOLS = [
    ("query_machine_history", {"mint_id": "m-belongs-to-tenant-a"}),
    ("calculate_oee", {"machine_id": "m-belongs-to-tenant-a"}),
    ("energy_consumption", {"machine_id": "m-belongs-to-tenant-a"}),
    ("list_guardrails", {"machine_id": "m-belongs-to-tenant-a"}),
    ("list_automations", {"machine_id": "m-belongs-to-tenant-a"}),
]


async def _upstream_identity(upstream, token, tool, args):
    upstream.reset()
    async with session(token) as s:
        out = await s.call(tool, args)
    assert out["ok"], f"{tool} failed for this caller: {out.get('error')}"
    assert len(upstream.requests) == 1, f"{tool} made {len(upstream.requests)} upstream calls"
    req = upstream.last
    auth = req.headers.get("authorization", "")
    return {
        "bearer": auth[7:].strip() if auth.lower().startswith("bearer ") else auth,
        "caller_key_id": req.headers.get("x-forge-caller-key-id"),
        "origin": req.headers.get("x-forge-origin"),
        "path": req.url.path,
    }


# ── The core isolation assertion ─────────────────────────────────────────────

@pytest.mark.parametrize("tool,args", ACCOUNT_WIDE_TOOLS + MACHINE_SCOPED_TOOLS)
async def test_two_tenants_do_not_share_one_upstream_identity(upstream, tool, args):
    """Tenant A and tenant B must not reach forge-prod as the same principal.

    Either the bearer differs (per-caller pass-through) or, if the shared proxy
    key is kept, the request must NAME the caller so forge-prod can scope to
    them. Presenting an identical, caller-free identity for both tenants means
    forge-prod cannot tell them apart, and every row it returns is scoped to
    whoever owns the shared key.
    """
    a = await _upstream_identity(upstream, TENANT_A_KEY, tool, args)
    b = await _upstream_identity(upstream, TENANT_B_KEY, tool, args)

    distinguishable = (a["bearer"] != b["bearer"]) or (
        a["caller_key_id"] not in (None, "") and a["caller_key_id"] != b["caller_key_id"])

    assert distinguishable, (
        f"{tool}: tenant A and tenant B both reached forge-prod as the SAME "
        f"principal with NO caller named.\n"
        f"  A: bearer={a['bearer']!r} caller_key_id={a['caller_key_id']!r}\n"
        f"  B: bearer={b['bearer']!r} caller_key_id={b['caller_key_id']!r}\n"
        f"  path={a['path']}\n"
        f"forge-prod scopes rows by the authenticated identity, so this tool "
        f"returns the shared account's data to both tenants.")


async def test_free_tenant_is_not_the_paying_tenant_upstream(upstream):
    """A free sandbox key must not reach forge-prod as a production account."""
    a = await _upstream_identity(upstream, TENANT_A_KEY, "get_coverage", {})
    c = await _upstream_identity(upstream, SANDBOX_KEY, "get_coverage", {})
    distinguishable = (a["bearer"] != c["bearer"]) or (
        a["caller_key_id"] not in (None, "") and a["caller_key_id"] != c["caller_key_id"])
    assert distinguishable, (
        "a free sandbox key and a paying production key presented the same "
        f"upstream identity: {a['bearer']!r} / caller={a['caller_key_id']!r}")


async def test_caller_is_always_named_upstream(upstream):
    """forge-prod already has the receiving half of this: `_meter_attribution`
    reads `x-forge-caller-key-id` and, when it is absent on a proxied call,
    returns `(None, 'mcp_caller_unidentified')` — no meter event, no attributed
    subject. The proxy must send it on every upstream request, for every tenant.
    """
    for token, expected in ((TENANT_A_KEY, TENANT_A_KEY_ID),
                            (TENANT_B_KEY, TENANT_B_KEY_ID)):
        got = await _upstream_identity(upstream, token, "get_coverage", {})
        assert got["caller_key_id"] == expected, (
            f"upstream request carried caller_key_id={got['caller_key_id']!r}, "
            f"expected {expected!r}. forge-prod cannot attribute or scope this call.")


# ── Keyless ──────────────────────────────────────────────────────────────────

async def test_keyless_caller_never_reaches_upstream(upstream):
    """No Authorization header: the gate must refuse before any upstream hop.

    This is the third leg of the isolation measurement. A keyless caller that
    reached upstream would arrive as the shared proxy key — i.e. as a tenant.
    """
    async with session(None) as s:
        for tool, args in ACCOUNT_WIDE_TOOLS + MACHINE_SCOPED_TOOLS:
            out = await s.call(tool, args)
            assert not out["ok"], f"keyless call to {tool} was ALLOWED"
            assert out["error"]["error"] == "missing_api_key", out["error"]
    assert upstream.requests == [], (
        f"a keyless caller caused {len(upstream.requests)} upstream request(s): "
        f"{[r.url.path for r in upstream.requests]}")


async def test_keyless_cannot_borrow_the_shared_key_via_a_header(upstream):
    """Reintroduction variant: no client-supplied header may stand in for auth.

    The shared proxy key is the one identity that would see everything. A
    caller must not be able to name it, claim its origin, or claim a caller key
    id, and get through.
    """
    from mcp_client import MCPSession, app_client

    forged = [
        {"X-Forge-Origin": "mcp"},
        {"X-Forge-Caller-Key-Id": TENANT_A_KEY_ID},
        {"X-Forge-Origin": "mcp", "X-Forge-Caller-Key-Id": TENANT_A_KEY_ID},
        {"X-Api-Key": SERVER_SHARED_KEY},
        {"Authorization": "Bearer "},
        {"Authorization": "Basic " + "Zm9vOmJhcg=="},
    ]
    async with app_client() as client:
        for extra in forged:
            s = MCPSession(client, None)
            s._headers = (lambda e=extra, _s=s: {  # type: ignore[assignment]
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2025-06-18",
                **({"Mcp-Session-Id": _s._sid} if _s._sid else {}),
                **e,
            })
            await s.initialize()
            out = await s.call("fleet_oee", {})
            assert not out["ok"], f"headers {extra} got through the gate"
    assert upstream.requests == [], (
        f"forged-header callers reached upstream: "
        f"{[r.url.path for r in upstream.requests]}")


# ── Revoked / expired keys are not tenants ───────────────────────────────────

@pytest.mark.parametrize("name", ["REVOKED_KEY", "EXPIRED_KEY", "ROTATING_EXPIRED",
                                  "BOGUS_KEY", "WRONG_PREFIX_KEY"])
async def test_dead_credentials_never_reach_upstream(upstream, name):
    import identities

    token = getattr(identities, name)
    async with session(token) as s:
        out = await s.call("fleet_oee", {})
    assert not out["ok"], f"{name} was allowed to call fleet_oee"
    assert out["error"]["error"] in ("invalid_api_key", "missing_api_key"), out["error"]
    assert upstream.requests == [], f"{name} reached upstream"


async def test_rotating_key_inside_grace_still_works(upstream):
    """The path that must KEEP working. A rotation grace window that silently
    stopped honouring keys would lock out every customer mid-rotation."""
    from identities import ROTATING_IN_GRACE

    async with session(ROTATING_IN_GRACE) as s:
        out = await s.call("get_coverage", {})
    assert out["ok"], out.get("error")
    assert len(upstream.requests) == 1
