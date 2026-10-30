"""Caller-supplied ids cannot retarget the upstream request (MCP audit G1).

MEASURED 2026-10-30: ids were interpolated raw, f"/v1/triggers/{trigger_id}",
and httpx collapses dot segments, so delete_automation(trigger_id="../../v1/x")
sent DELETE https://forge.foundrynet.io/v1/x. Encoding alone does not close it:
forge-prod routes on the percent-DECODED path, so "x%2Frestore" would arrive as
/v1/triggers/x/restore. Every crafted id must be refused before ANY upstream
request; every ordinary id must still reach exactly its own route.
"""
from __future__ import annotations

import pytest

import mcp_server as M
from identities import TENANT_A_KEY
from mcp_client import app_client, session

# tool -> (id argument, other required args, upstream path template)
TOOLS = {
    "query_machine_history": ("mint_id", {}, "/v1/history/{}"),
    "disable_automation":    ("trigger_id", {}, "/v1/triggers/{}"),
    "delete_automation":     ("trigger_id", {}, "/v1/triggers/{}"),
    "restore_automation":    ("trigger_id", {}, "/v1/triggers/{}/restore"),
    "query_webhook_history": ("trigger_id", {}, "/v1/triggers/{}/executions"),
    "calculate_oee":         ("machine_id", {}, "/v1/oee/{}"),
    "energy_consumption":    ("machine_id", {}, "/v1/energy/{}"),
    "diagnose_machine":      ("machine_id", {}, "/v1/diagnose/{}"),
    "health_index":          ("machine_id", {}, "/v1/health_index/{}"),
    "get_agent_card":        ("agent_id", {}, "/v1/agents/{}/card"),
    "correct_mapping":       ("mapping_id", {"source_field": "SpindleSpeed",
                                             "confirmed_canonical": "spindle_speed_rpm",
                                             "original_canonical": "spindle_speed"},
                              "/v1/feedback/{}/correct"),
}

# An empty value is not an attack on these two: it selects a documented default
# (agent "builtin"; the mapping id derived from source_field + oem).
EMPTY_MEANS_DEFAULT = {"get_agent_card", "correct_mapping"}

CRAFTED = [
    "../../v1/admin/keys",          # plain traversal
    "..",
    "x/../../v1/admin",
    "..\\..\\v1\\admin",            # backslash traversal
    "%2e%2e%2f%2e%2e%2fv1%2fadmin",  # encoded
    "%2E%2E/admin",                  # mixed case + literal slash
    "..%2f..%2fv1",
    "%252e%252e%252fv1",             # double-encoded
    "%25252e%25252e%25252f",         # triple-encoded
    "x/restore",                     # same-prefix retarget, raw
    "x%2Frestore",                   # same-prefix retarget, encoded
    "x%5c..%5cy",                    # encoded backslash
    "x\x00y",                        # NUL
    "x\ny",                          # control character
    "",
    "   ",
    "a" * 300,
]

NORMAL = [
    ("MINT-7f3a9b", "MINT-7f3a9b"),
    ("3f2b8c1e-9a4d-4e7b-8c21-5d6f7a8b9c0d", "3f2b8c1e-9a4d-4e7b-8c21-5d6f7a8b9c0d"),
    ("CNC 01", "CNC%2001"),
    ("line3:press?x=1#y", "line3%3Apress%3Fx%3D1%23y"),
]


@pytest.mark.parametrize("tool,bad", [
    (t, b) for t in sorted(TOOLS) for b in CRAFTED
    if not (b == "" and t in EMPTY_MEANS_DEFAULT)
], ids=lambda v: repr(v)[:30])
async def test_a_crafted_id_is_refused_before_any_upstream_request(upstream, tool, bad):
    arg, extra, _ = TOOLS[tool]
    async with session(TENANT_A_KEY) as s:
        out = await s.call(tool, {arg: bad, **extra})
    assert not out["ok"], f"{tool}({arg}={bad!r}) succeeded"
    assert out["error"].get("error") == "invalid_argument", out["error"]
    assert out["error"].get("status") == 400
    assert out["error"].get("field") == arg
    assert upstream.forge_requests == [], (
        f"{tool}({arg}={bad!r}) reached forge-prod at "
        f"{[str(r.url) for r in upstream.forge_requests]}")


@pytest.mark.parametrize("tool", sorted(TOOLS))
@pytest.mark.parametrize("good,encoded", NORMAL, ids=[n[0] for n in NORMAL])
async def test_an_ordinary_id_reaches_exactly_its_own_route(upstream, tool, good, encoded):
    arg, extra, template = TOOLS[tool]
    async with session(TENANT_A_KEY) as s:
        out = await s.call(tool, {arg: good, **extra})
    assert out["ok"], out["error"]
    assert len(upstream.forge_requests) == 1
    sent = upstream.forge_requests[0].url.raw_path.split(b"?")[0].decode()
    assert sent == template.format(encoded), sent


async def test_get_agent_card_default_still_resolves_builtin(upstream):
    async with session(TENANT_A_KEY) as s:
        out = await s.call("get_agent_card", {})
    assert out["ok"], out["error"]
    assert upstream.forge_requests[0].url.path == "/v1/agents/builtin/card"


async def test_correct_mapping_derived_id_reaches_its_route(upstream):
    """No mapping_id: the id is a hash of source_field, so even a hostile
    source_field cannot shape the path."""
    async with session(TENANT_A_KEY) as s:
        out = await s.call("correct_mapping", {
            "source_field": "../../v1/admin", "original_canonical": "spindle_speed",
            "confirmed_canonical": "spindle_speed_rpm", "oem": "haas"})
    assert out["ok"], out["error"]
    path = upstream.forge_requests[0].url.path
    assert path.startswith("/v1/feedback/") and path.endswith("/correct"), path
    assert len(path.split("/")) == 5, path


# ── A2A carries the same rule ────────────────────────────────────────────────

@pytest.mark.parametrize("bad", ["../../v1/admin", "%2e%2e%2fadmin", "x%2Fhistory"])
async def test_a2a_diagnose_refuses_a_crafted_machine_id(upstream, bad):
    async with app_client() as client:
        r = await client.post("/a2a/tasks", headers={
            "Authorization": f"Bearer {TENANT_A_KEY}", "Content-Type": "application/json"},
            json={"skill_id": "diagnose", "params": {"machine_id": bad}})
    assert r.status_code == 400, r.text[:300]
    assert r.json()["error"] == "invalid_argument"
    assert upstream.forge_requests == []


async def test_a2a_diagnose_still_works_for_an_ordinary_id(upstream):
    async with app_client() as client:
        r = await client.post("/a2a/tasks", headers={
            "Authorization": f"Bearer {TENANT_A_KEY}", "Content-Type": "application/json"},
            json={"skill_id": "diagnose", "params": {"machine_id": "MINT-7f3a9b"}})
    assert r.status_code == 200, r.text[:300]
    assert upstream.forge_requests[0].url.path == "/v1/diagnose/MINT-7f3a9b"


# ── The last-line check, for a call site that forgets _seg ───────────────────

@pytest.mark.parametrize("path", [
    "/v1/triggers/../../admin/keys",
    "/v1/triggers/x%2Frestore",
    "/v1/triggers/%2e%2e/x",
    "/v1/triggers/%252e%252e%252f",
    "/admin/keys",
])
async def test_the_wire_check_refuses_an_unsafe_path_even_without_seg(upstream, path):
    out = await M._call_forge_raw("GET", path)
    assert out.get("error") == "invalid_argument", out
    assert upstream.forge_requests == []


ORDINARY_PATHS = ("/v1/normalize", "/v1/triggers/abc/restore", "/v1/oee/CNC%2001",
                  "/v1/reports/shift/current", "/v1/agents/builtin/card",
                  "/v1/triggers/line3%3Apress%3Fx%3D1%23y/executions")


def test_the_wire_check_passes_every_ordinary_path():
    for p in ORDINARY_PATHS:
        assert M._path_problem(p) is None, p


def test_real_httpx_sends_every_accepted_path_unchanged():
    """The property the wire check relies on, measured on the REAL client (the
    harness swaps mcp_server.httpx for a recorder): a path the check accepts is
    sent byte-for-byte, and one it refuses is one httpx would have rewritten."""
    import httpx as real
    for p in ORDINARY_PATHS:
        assert real.URL(M.FORGE_BASE_URL + p).raw_path.decode() == p, p
    rewritten = "/v1/triggers/../../admin/keys"
    assert real.URL(M.FORGE_BASE_URL + rewritten).raw_path.decode() == "/admin/keys"
    assert M._path_problem(rewritten) is not None
