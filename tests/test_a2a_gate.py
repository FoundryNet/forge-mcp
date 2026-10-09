"""POST /a2a/tasks and GET /a2a/agents must obey the same gate as tools/call.

They did not. `_a2a_auth` proved the caller held *a* valid key and then
`_a2a_dispatch` went straight to the kernel: no tier check, no monthly cap, no
payment gate, under the shared server key. A free `forge_sandbox_` key that is
told `payment_method_required` for `fleet_health` on tools/call could get the
same answer, unmetered and unlimited, by posting `skill_id=fleet_intelligence`
here. Same for `diagnose` and `predict_failure`.

The skills and the tools are now gated by one function, so the two routes
cannot drift: a tool that becomes paid becomes paid on both at once.
"""
from __future__ import annotations

import pytest

from identities import (
    SANDBOX_KEY,
    SANDBOX_KEY_ID,
    SERVER_SHARED_KEY,
    TENANT_A_KEY,
    TENANT_A_KEY_ID,
    TENANT_B_KEY,
)
from mcp_client import app_client

# asyncio_mode = auto in pytest.ini marks the async tests; an explicit module
# mark also lands on the sync ones and emits a warning per test.

# skill_id -> the tool it is. The paid ones are the bypass.
PAID_SKILLS = ["fleet_intelligence", "diagnose", "predict_failure"]
FREE_SKILLS = ["normalize_telemetry", "agent_trust"]

SKILL_PARAMS = {
    "normalize_telemetry": {"data": {"SpindleSpeed": 1200}},
    "predict_failure": {"time_series": [1, 2, 3, 4, 5], "threshold": 100},
    "fleet_intelligence": {"machines": [{"machine_id": "m-1"}]},
    "diagnose": {"machine_id": "m-1"},
    "agent_trust": {},
}


async def _task(client, token, skill, params=None, headers=None):
    h = {"Content-Type": "application/json"}
    if token is not None:
        h["Authorization"] = f"Bearer {token}"
    if headers:
        h.update(headers)
    return await client.post("/a2a/tasks", headers=h, json={
        "skill_id": skill, "params": params if params is not None else SKILL_PARAMS[skill]})


@pytest.mark.parametrize("skill", PAID_SKILLS)
async def test_free_key_cannot_run_a_paid_skill_through_a2a(upstream, skill):
    """The entitlement bypass. A sandbox key must be refused here exactly as it
    is on tools/call."""
    async with app_client() as client:
        r = await _task(client, SANDBOX_KEY, skill)
    assert r.status_code == 402, (
        f"a free sandbox key ran paid skill {skill!r} through /a2a/tasks: "
        f"HTTP {r.status_code} {r.text[:300]}")
    assert r.json().get("error") == "payment_method_required", r.json()
    assert upstream.forge_requests == [], (
        f"{skill} reached the kernel anyway: "
        f"{[x.url.path for x in upstream.forge_requests]}")


@pytest.mark.parametrize("skill", FREE_SKILLS)
async def test_free_key_can_still_run_a_free_skill_through_a2a(upstream, skill):
    """The path that must KEEP working. Blocking the bypass must not blanket-
    refuse A2A: a sandbox key's free surface is the same on both transports."""
    async with app_client() as client:
        r = await _task(client, SANDBOX_KEY, skill)
    assert r.status_code == 200, f"{skill} refused for a sandbox key: {r.text[:300]}"
    assert upstream.forge_requests, f"{skill} made no kernel call"
    for req in upstream.forge_requests:
        assert req.headers.get("x-forge-caller-key-id") == SANDBOX_KEY_ID


async def test_a2a_runs_under_the_callers_identity_not_the_proxys(upstream):
    """The tenancy half: /a2a/tasks used the shared key too."""
    async with app_client() as client:
        for token in (TENANT_A_KEY, TENANT_B_KEY):
            upstream.reset()
            r = await _task(client, token, "normalize_telemetry")
            assert r.status_code == 200, r.text[:300]
            for req in upstream.forge_requests:
                auth = req.headers.get("authorization", "")
                assert SERVER_SHARED_KEY not in auth, (
                    "/a2a/tasks still runs under the shared proxy key")
                assert auth == f"Bearer {token}"


async def test_a2a_agents_is_gated_and_scoped(upstream):
    async with app_client() as client:
        r = await client.get("/a2a/agents",
                             headers={"Authorization": f"Bearer {TENANT_A_KEY}"})
        assert r.status_code == 200, r.text[:300]
        assert upstream.forge_requests
        assert upstream.caller_key_ids()[-1] == TENANT_A_KEY_ID

        upstream.reset()
        r = await client.get("/a2a/agents")
        assert r.status_code == 401
        assert upstream.forge_requests == []


async def test_a2a_unknown_skill_never_reaches_the_kernel(upstream):
    """Allowlist, not denylist: an unmapped skill is unknown, not free."""
    async with app_client() as client:
        for skill in ("machine_intelligence", "verify_record", "", "../predict",
                      "settle", "attest_machine_action"):
            upstream.reset()
            r = await _task(client, TENANT_A_KEY, skill, params={})
            assert r.status_code == 400, f"{skill!r} → HTTP {r.status_code}"
            assert upstream.forge_requests == [], f"{skill!r} reached the kernel"


async def test_a2a_counts_against_the_monthly_cap(upstream, fake_db):
    """An ungated route is also an uncapped one: A2A calls used to cost a
    tenant nothing against its allowance, so the cap could be walked around
    rather than reached."""
    async with app_client() as client:
        await _task(client, SANDBOX_KEY, "normalize_telemetry")
    rpcs = [p for n, p in fake_db.rpcs if n == "increment_mcp_usage"]
    assert rpcs, "no cap increment fired for an A2A task"
    assert rpcs[-1]["p_user_id"]


async def test_a2a_rejects_dead_credentials(upstream):
    import identities

    async with app_client() as client:
        for name in ("REVOKED_KEY", "EXPIRED_KEY", "ROTATING_EXPIRED",
                     "BOGUS_KEY", "WRONG_PREFIX_KEY"):
            upstream.reset()
            r = await _task(client, getattr(identities, name), "normalize_telemetry")
            assert r.status_code == 401, f"{name} → HTTP {r.status_code}"
            assert upstream.forge_requests == []
