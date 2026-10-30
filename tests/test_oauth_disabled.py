"""OAuth token exchange is OFF by default (MCP audit G9, 2026-10-30).

/oauth/token minted JWTs that could call no tool: `enforce_call` refuses every
JWT caller because a JWT carries a key id, not a key forge-prod accepts. Until a
real exchange exists the endpoint, its metadata and JWT acceptance are disabled
behind ENABLE_OAUTH_EXCHANGE (default false), and nothing advertises OAuth.
"""
from __future__ import annotations

import pytest

import gating as g
from identities import TENANT_A_KEY
from mcp_client import app_client


@pytest.fixture()
def exchange_off(monkeypatch):
    monkeypatch.setattr(g, "OAUTH_EXCHANGE_ENABLED", False)


@pytest.mark.parametrize("value,expected", [(None, "False False"), ("false", "False False"),
                                            ("true", "True True")])
def test_the_flag_defaults_off_and_true_turns_it_on(value, expected):
    """In a fresh process: reloading gating here would re-create its exception
    classes under every module that imported them by name."""
    import os
    import subprocess
    import sys
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = {k: v for k, v in os.environ.items() if k != "ENABLE_OAUTH_EXCHANGE"}
    env["MCP_JWT_SECRET"] = "harness-placeholder-signing-material"
    if value is not None:
        env["ENABLE_OAUTH_EXCHANGE"] = value
    p = subprocess.run(
        [sys.executable, "-c",
         "import gating as g; print(g.OAUTH_EXCHANGE_ENABLED, g.oauth_enabled())"],
        cwd=root, env=env, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr[-800:]
    assert p.stdout.strip().splitlines()[-1:] == [expected], (p.stdout, p.stderr[-400:])


@pytest.mark.parametrize("body", [
    {"grant_type": "client_credentials", "client_id": "x", "client_secret": TENANT_A_KEY},
    {},
])
async def test_token_endpoint_answers_501(exchange_off, body):
    async with app_client() as client:
        r = await client.post("/oauth/token", data=body)
    assert r.status_code == 501, r.text
    assert r.json() == {"error": "not_implemented",
                        "error_description": g.OAUTH_DISABLED_MESSAGE}
    assert "not yet available" in r.json()["error_description"]
    assert "no-store" in r.headers.get("cache-control", "")


async def test_metadata_answers_501(exchange_off):
    async with app_client() as client:
        r = await client.get("/.well-known/oauth-authorization-server")
    assert r.status_code == 501, r.text
    assert r.json()["error"] == "not_implemented"


async def test_nothing_advertises_oauth(exchange_off):
    async with app_client() as client:
        health = (await client.get("/health")).json()
        card = (await client.get("/.well-known/mcp/server-card.json")).text
        agent = (await client.get("/.well-known/agent.json")).text
    assert health["oauth_token_issuance"] is False
    assert "oauth" not in card.lower(), card[:400]
    assert "oauth" not in agent.lower(), agent[:400]


def test_a_jwt_is_not_accepted_while_disabled(exchange_off, monkeypatch):
    """Minted while on, presented while off: refused, not honoured."""
    monkeypatch.setattr(g, "OAUTH_EXCHANGE_ENABLED", True)
    token = g.issue_access_token("harness", TENANT_A_KEY)["access_token"]
    monkeypatch.setattr(g, "OAUTH_EXCHANGE_ENABLED", False)
    assert g.resolve_bearer(token) is None


async def test_re_enabling_restores_the_flow(monkeypatch):
    monkeypatch.setattr(g, "OAUTH_EXCHANGE_ENABLED", True)
    async with app_client() as client:
        r = await client.post("/oauth/token", data={
            "grant_type": "client_credentials", "client_id": "x",
            "client_secret": TENANT_A_KEY})
        meta = await client.get("/.well-known/oauth-authorization-server")
    assert r.status_code == 200, r.text
    assert r.json().get("access_token")
    assert meta.status_code == 200
