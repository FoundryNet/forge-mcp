"""REST/MCP free-tier parity, measured against forge-prod's own gate function.

"Free tier is transport-aligned: REST and MCP give the same tools." That claim
had been made by comparing two hand-maintained lists — `gating.FREE_TOOLS` here
and `_FREE_TOOL_NAMES` in forge-prod — and a list compared against a list proves
only that two people typed the same thing. The gate forge-prod actually enforces
is `_endpoint_to_billing_meter`: a path is free when it returns None.

So this measures, per tool: the REST endpoint the MCP tool proxies to (read out
of `mcp_server.py`), run through forge-prod's extracted
`_endpoint_to_billing_meter` / `_sandbox_may_call`, against whether
`gating.FREE_TOOLS` lets a free key call it over MCP.

Direction matters, and more than it used to. MCP NARROWER than REST is a product
inconsistency. MCP WIDER than REST is now a functional break as well, because
the proxy presents the caller's own key upstream: a tool MCP admits free but the
kernel meters is admitted at the door and then 402'd — the "billing allow-list
that 402'd the MCP proxy" failure, inverted. Both are reported with n.

Declared limit of this measurement: it reads the METER. forge-prod has a second
gate, `_require_perm`, that a static reading of the meter map cannot see, so
"free on REST" here means "carries no meter", not "callable by any key". The one
tool where that matters (`machine_intelligence`) is named in the pinned set
below with that as its reason.
"""
from __future__ import annotations

import pytest

import forge_prod_gate
import gating
import toolroutes

PROD = None
EXTRACTION_ERROR = ""
try:
    PROD = forge_prod_gate.load()
except AssertionError as e:
    EXTRACTION_ERROR = str(e)

needs_prod = pytest.mark.skipif(
    PROD is None,
    reason="forge-prod/api.py not on this machine; set FORGE_PROD_API to measure parity")


# Tools free on REST (no meter) but not on MCP's free tier, each with the reason
# it is allowed to stay that way. Pinned exactly: closing one must fail this
# test and force the entry to be removed, and a NEW divergence must fail it too.
DECLARED_NARROWER = {
    # Mutating trigger-lifecycle calls. forge-prod carries no meter on
    # PATCH/DELETE /v1/triggers/* and prices all three 0.00. Promoting a WRITE
    # into the free tier is a pricing decision, not a test fix. LANE_REQUESTS R-10.
    ("disable_automation", "PATCH", "/v1/triggers/{}"),
    ("delete_automation", "DELETE", "/v1/triggers/{}"),
    ("restore_automation", "PATCH", "/v1/triggers/{}/restore"),
    # Gated on forge-prod by _require_perm(PERM_PREDICT) + the prediction rate
    # limiter rather than by a meter, so "no meter" does not mean "any key may
    # call it". MCP keeping it Pro-only AGREES with REST; the meter-only
    # measurement cannot see that. LANE_REQUESTS R-11 asks forge-prod to give it
    # a meter or a rate-card line so the two gates stop disagreeing on paper.
    ("machine_intelligence", "POST", "/v1/machine_intelligence"),
    # Priced $0.02 in forge-prod TOOL_COSTS but `_endpoint_to_billing_meter`
    # returns None for both of its paths — i.e. a PRICED tool with NO Stripe
    # meter, on REST, for every caller. That is a forge-prod revenue gap, not an
    # MCP divergence; MCP keeping it Pro-only is the conservative side.
    # LANE_REQUESTS R-12.
    ("verify_record", "POST", "/v1/verify_record"),
    ("verify_record", "POST", "/v1/settle"),
}


def test_the_extraction_itself_worked():
    assert not EXTRACTION_ERROR, EXTRACTION_ERROR


def test_every_tool_maps_to_at_least_one_rest_endpoint():
    """A tool whose route cannot be read is a tool the measurement would omit."""
    r = toolroutes.resolved_routes()
    assert len(r) == 32, f"read routes for {len(r)} of 32 tools: {sorted(r)}"
    for tool, calls in r.items():
        assert calls, f"{tool} has no readable kernel call"


def _parity_rows():
    routes = toolroutes.resolved_routes()
    assert set(routes) == set(gating.ALL_TOOLS), (
        f"route map and tool registry disagree: {set(routes) ^ set(gating.ALL_TOOLS)}")
    rows = []
    for tool in sorted(routes):
        free_on_mcp = tool in gating.FREE_TOOLS
        for method, path in dict.fromkeys(routes[tool]):   # de-dup repeated call sites
            rows.append({
                "key": (tool, method, path),
                "free_on_mcp": free_on_mcp,
                "free_on_rest": PROD.sandbox_may_call(method, path),
                "meter": PROD.meter_for(method, path),
            })
    return rows


@needs_prod
def test_mcp_is_never_wider_than_rest():
    """A hard assertion. MCP admitting what the kernel meters means the call is
    allowed at the door and refused by the kernel under the caller's own key."""
    rows = _parity_rows()
    wider = [r for r in rows if r["free_on_mcp"] and not r["free_on_rest"]]
    assert not wider, (
        f"MCP offers free what REST meters, on {len(wider)} of n={len(rows)} "
        f"(tool, endpoint) pairs: {[(r['key'], r['meter']) for r in wider]}")


@needs_prod
def test_free_tier_parity_rest_vs_mcp():
    """THE measurement. n = every tool x every distinct endpoint it calls."""
    rows = _parity_rows()
    n = len(rows)
    narrower = {r["key"] for r in rows if r["free_on_rest"] and not r["free_on_mcp"]}
    wider = {r["key"] for r in rows if r["free_on_mcp"] and not r["free_on_rest"]}

    report = (
        f"\nREST/MCP free-tier parity — n = {n} (tool, endpoint) pairs over 32 tools\n"
        f"  gate source   : {PROD.source}\n"
        f"  MCP free set  : {len(gating.FREE_TOOLS)} tools\n"
        f"  REST free set : {len(PROD.sandbox_free_tool_names)} tools (prod's echo)\n"
        f"  MCP wider     : {len(wider)} {sorted(wider)}\n"
        f"  MCP narrower  : {len(narrower)} {sorted(narrower)}\n")
    print(report)

    assert not wider, report
    assert narrower == DECLARED_NARROWER, (
        "the set of endpoints free on REST but paid on MCP changed." + report
        + f"  declared: {sorted(DECLARED_NARROWER)}\n"
        + "  If a divergence was CLOSED, remove it from DECLARED_NARROWER. If one "
          "APPEARED, it is a free-tier inconsistency between transports — fix it, "
          "do not widen the expectation.")


@needs_prod
def test_the_free_tool_sets_are_identical_name_for_name():
    """The strongest form of the claim, and the one it is safe to publish:
    MCP's free tier and forge-prod's cardless-sandbox tier are the SAME set of
    names. `detect_anomalies` was the only difference (free on REST, Pro-only on
    MCP) and is now aligned."""
    mcp_free = set(gating.FREE_TOOLS)
    rest_free = set(PROD.sandbox_free_tool_names)
    assert mcp_free == rest_free, (
        f"free tier differs by transport.\n"
        f"  only on MCP : {sorted(mcp_free - rest_free)}\n"
        f"  only on REST: {sorted(rest_free - mcp_free)}")
    assert len(mcp_free) == 20, f"the free tier is {len(mcp_free)} tools, not 20"


@needs_prod
def test_prods_own_echo_list_matches_its_own_gate():
    """forge-prod's `_FREE_TOOL_NAMES` is prose about its meter map, and the two
    disagree. Measured and pinned, because the echo is what a customer reads in
    the 402 body: it tells them four tools are paid that the kernel never
    meters. Not ours to fix — LANE_REQUESTS R-10/R-11/R-12."""
    routes = toolroutes.resolved_routes()
    disagree = set()
    for tool, calls in routes.items():
        echoed = tool in PROD.sandbox_free_tool_names
        gated_free = all(PROD.sandbox_may_call(m, p) for m, p in calls)
        if echoed != gated_free:
            disagree.add((tool, "echo:free" if echoed else "echo:paid",
                          "gate:free" if gated_free else "gate:paid"))
    expected = {
        ("disable_automation", "echo:paid", "gate:free"),
        ("delete_automation", "echo:paid", "gate:free"),
        ("restore_automation", "echo:paid", "gate:free"),
        ("verify_record", "echo:paid", "gate:free"),
        ("machine_intelligence", "echo:paid", "gate:free"),
    }
    assert disagree == expected, (
        f"forge-prod's free-tool echo vs its own meter gate changed.\n"
        f"  measured: {sorted(disagree)}\n"
        f"  declared: {sorted(expected)}")


# ── The cost ledger: one price, not two ──────────────────────────────────────

@needs_prod
def test_tool_costs_match_forge_prod_entry_for_entry():
    """Both files carry a comment saying they MUST stay identical. 13 of 34
    entries had drifted when this test was first written: every paid tool, in
    both directions. forge-prod wins — it is the side that fires the meter."""
    prod = PROD.tool_costs
    mine = gating.TOOL_COSTS
    shared = sorted(set(prod) & set(mine))
    drift = [(t, prod[t], mine[t]) for t in shared if prod[t] != mine[t]]
    assert not drift, (
        f"cost ledger drift on {len(drift)} of {len(shared)} shared tools "
        f"(tool, forge-prod, forge-mcp): {drift}")
    missing = sorted(set(gating.ALL_TOOLS) - set(mine))
    assert not missing, (
        f"tools with no entry in TOOL_COSTS — their call volume logs as 0.00 and "
        f"reads as free in the usage summary: {missing}")
    # Tools prod serves and MCP does not are fine; the reverse is not.
    mcp_only = sorted(set(mine) - set(prod))
    assert not mcp_only, f"MCP prices tools forge-prod does not know: {mcp_only}"


def test_truly_free_tools_are_a_subset_of_the_free_tier():
    """A metered key with no card gets TRULY_FREE_TOOLS. If that ever held a
    tool the free tier does not, the narrower tier would be the wider one."""
    assert gating.TRULY_FREE_TOOLS <= gating.FREE_TOOLS
    assert gating.FREE_TOOLS <= gating.ALL_TOOLS
    assert len(gating.ALL_TOOLS) == 32


def test_every_free_tool_is_priced_zero():
    """A tool in the free tier that carries a price is a contradiction a
    customer will find in their usage summary. normalize is the one exception:
    it is graduated per 1,000 NTE and the ledger value is the tier-1 unit rate."""
    for tool in sorted(gating.FREE_TOOLS - {"normalize_telemetry"}):
        assert gating.TOOL_COSTS[tool] == 0.0, (
            f"{tool} is in FREE_TOOLS but priced {gating.TOOL_COSTS[tool]}")
