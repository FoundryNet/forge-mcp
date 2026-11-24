"""MCPS-compatible signed envelopes (draft-sharif-mcps-secure-mcp-01).

Design: worklog1/mcps_alignment_2026-11-20/MCPS_DESIGN.md. Every key used here
is a throwaway P-256 key minted in-process; no test reads a credential from
anywhere. The tests drive the real ASGI app over the real Streamable HTTP
transport (tests/mcp_client.py), so what is verified is what goes on the wire.
"""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import mcps
import mcp_server
from identities import TENANT_A_KEY
from mcp_client import PROTOCOL_VERSION, MCPSession, _parse, app_client, session
from toolargs import ARGS

ORIGIN = "https://mcp.test.invalid"


# ── fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def server_signer():
    sgn = mcps.Signer(ec.generate_private_key(ec.SECP256R1()),
                      origin=ORIGIN, agent_version="test")
    mcps.configure(sgn)
    mcps.set_tool_definitions_hash(None)
    yield sgn
    mcps.configure(None)
    mcps.set_tool_definitions_hash(None)


class Client:
    """An MCPS-aware client: its own throwaway key and self-signed passport."""

    def __init__(self, origin=ORIGIN, passport_id="ap_1b4e28ba-2fa1-4d2b-883f-0016d3cca427"):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.jwk = mcps.jwk_from_public(self.key.public_key())
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        body = {"id": passport_id,
                "agent_name": "test-agent", "agent_version": "1.0.0",
                "issuer": "self", "origin": origin,
                "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expires_at": (now + dt.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "public_key": self.jwk, "capabilities": ["tools/call"],
                "trust_level": 0, "issuer_chain": []}
        self.passport = {"mcps_version": "1.0", "passport": body,
                         "signature": mcps.sign_p1363(self.key, mcps.jcs(body))}
        self.passport_id = body["id"]

    def sign(self, message: dict, *, nonce=None, timestamp=None) -> dict:
        nonce = nonce or secrets.token_hex(16)
        ts = timestamp or mcps.now_iso()
        payload = {"message_hash": mcps.sha256_hex(mcps.jcs(message)), "nonce": nonce,
                   "passport_id": self.passport_id, "timestamp": ts}
        out = dict(message)
        out["mcps"] = {"version": "1.0", "passport_id": self.passport_id,
                       "timestamp": ts, "nonce": nonce,
                       "signature": mcps.sign_p1363(self.key, mcps.jcs(payload))}
        return out


async def _raw(s: MCPSession, payload: dict) -> dict:
    return _parse(await s._post(payload)) or {}


async def _aware_session(client, token=TENANT_A_KEY, *, with_passport=True):
    """Initialize announcing capabilities.mcps (§9.2). Returns (ctx, s, init_params, init_env).

    With a passport, the notifications/initialized that follows is SIGNED: once a
    client has presented a passport, unsigned messages are refused (review F2)."""
    ctx = app_client()
    c = await ctx.__aenter__()
    s = MCPSession(c, token)
    cap = {"version": "1.0", "trust_level": 0}
    if with_passport:
        cap["passport"] = client.passport
    params = {"protocolVersion": PROTOCOL_VERSION,
              "capabilities": {"mcps": cap},
              "clientInfo": {"name": "mcps-test", "version": "1"}}
    s._id += 1
    resp = await s._post({"jsonrpc": "2.0", "id": s._id, "method": "initialize",
                          "params": params})
    s._sid = resp.headers.get("mcp-session-id")
    env = _parse(resp) or {}
    note = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    await s._c.post(s._path, json=client.sign(note) if with_passport else note,
                    headers=s._headers())
    return ctx, s, params, env


def _verify_response(env: dict, sgn: mcps.Signer) -> tuple[dict, str]:
    hdr, body, carriage = mcps.strip_envelope(env)
    assert hdr is not None, f"no MCPS envelope on {json.dumps(env)[:300]}"
    assert set(hdr) == {"version", "passport_id", "timestamp", "nonce", "signature"}, hdr
    assert hdr["version"] == "1.0" and hdr["passport_id"] == sgn.passport_id
    assert len(hdr["nonce"]) == 32 and int(hdr["nonce"], 16) >= 0
    assert "=" not in hdr["signature"] and len(mcps.b64_any(hdr["signature"])) == 64
    pub = mcps.public_from_jwk(sgn.jwk)
    assert mcps.verify_signature(hdr, body, pub), "envelope signature does not verify"
    return hdr, carriage


# ── 1. off by default: byte-for-byte the old behaviour ───────────────────────

async def test_layer_is_off_without_a_key():
    assert mcps.signer() is None
    async with session(TENANT_A_KEY) as s:
        init = await _raw(s, {"jsonrpc": "2.0", "id": 900, "method": "ping"})
        assert "mcps" not in init
        tools = await s.list_tools()
        assert len(tools) == 36
        assert all(mcps.META_TOOL_SIG not in (t.get("_meta") or {}) for t in tools)
        out = await s.call("get_coverage", {})
        assert out["ok"]
        meta = out["result"].get("_meta") or {}
        assert mcps.META_ENVELOPE not in meta and mcps.META_BINDING not in meta
        assert "mcps" not in out["raw"]
    async with app_client() as c:
        h = (await c.get("/health")).json()
        assert h["mcps"] == {"enabled": False, "error": None}
        assert (await c.get("/.well-known/mcps/passport.json")).status_code == 404
        assert (await c.get("/.well-known/mcps/tools.json")).status_code == 404


def test_a_malformed_key_leaves_the_layer_off_and_does_not_raise(monkeypatch):
    monkeypatch.setenv("MCPS_SIGNING_KEY", "this is not a pem key\\nat all")
    try:
        assert mcps.load_from_env(agent_version="t") is None
        assert mcps.signer() is None
        assert "unusable" in (mcps.load_error() or "")
    finally:
        monkeypatch.delenv("MCPS_SIGNING_KEY")
        mcps.load_from_env(agent_version="t")
    assert mcps.signer() is None and mcps.load_error() is None


def test_a_pem_key_from_env_loads(monkeypatch):
    from cryptography.hazmat.primitives import serialization
    k = ec.generate_private_key(ec.SECP256R1())
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()).decode().replace("\n", "\\n")
    monkeypatch.setenv("MCPS_SIGNING_KEY", pem)
    try:
        sgn = mcps.load_from_env(agent_version="t")
        assert sgn is not None and sgn.jwk == mcps.jwk_from_public(k.public_key())
        assert sgn.passport_id.startswith("ap_")
        again = mcps.Signer(k, origin="https://mcp.foundrynet.io", agent_version="t")
        assert again.passport_id == sgn.passport_id, "passport id must be stable per key"
    finally:
        monkeypatch.delenv("MCPS_SIGNING_KEY")
        mcps.configure(None)


# ── 2. envelope on every tool response, and it verifies ──────────────────────

async def test_every_tool_response_carries_a_valid_envelope(server_signer):
    """n = 36 tools, MCPS-unaware client (the `_meta` carriage)."""
    names = sorted(t.name for t in await mcp_server.mcp.list_tools())
    assert len(names) == 36
    seqs, missing = [], []
    async with session(TENANT_A_KEY) as s:
        await s.list_tools()            # populates the aggregate the binding carries
        for name in names:
            out = await s.call(name, ARGS[name])
            assert out["ok"], f"{name}: {out.get('error')}"
            env = out["raw"]
            assert "mcps" not in env, "unaware clients must never get a top-level member"
            try:
                _, carriage = _verify_response(env, server_signer)
            except AssertionError as e:
                missing.append((name, str(e)[:120]))
                continue
            assert carriage == "_meta"
            b = env["result"]["_meta"][mcps.META_BINDING]
            assert b["kid"] == server_signer.kid and b["alg"] == "ES256"
            assert b["carriage"] == "_meta"
            assert b["tool_definitions_hash"] == mcps.current_tool_definitions_hash()
            assert b["tool_definitions_hash"] is not None
            seqs.append((b["session"], b["seq"]))
    assert not missing, missing
    assert len({sess for sess, _ in seqs}) == 1
    got = [n for _, n in seqs]
    assert got == sorted(got) and len(set(got)) == len(got), f"seq not strictly increasing: {got}"


async def test_a_tool_error_result_is_signed_too(server_signer):
    async with session(TENANT_A_KEY) as s:
        out = await s.call("no_such_tool_exists", {})
        env = out["raw"]
        if "result" in env:
            _verify_response(env, server_signer)
        else:   # a JSON-RPC error: unsigned for unaware clients, by design (§3.2)
            assert "mcps" not in env


async def test_tampering_breaks_the_signature(server_signer):
    async with session(TENANT_A_KEY) as s:
        env = (await s.call("get_coverage", {}))["raw"]
    hdr, body, _ = mcps.strip_envelope(env)
    pub = mcps.public_from_jwk(server_signer.jwk)
    assert mcps.verify_signature(hdr, body, pub)
    forged = copy.deepcopy(body)
    forged["result"]["content"][0]["text"] += " "
    assert not mcps.verify_signature(hdr, forged, pub)
    forged = copy.deepcopy(body)
    forged["result"]["_meta"][mcps.META_BINDING]["seq"] += 1
    assert not mcps.verify_signature(hdr, forged, pub), "seq must be covered by the signature"
    other = mcps.Signer(ec.generate_private_key(ec.SECP256R1()), origin=ORIGIN, agent_version="x")
    assert not mcps.verify_signature(hdr, body, mcps.public_from_jwk(other.jwk))


async def test_published_key_verifies_the_wire(server_signer):
    async with app_client() as c:
        pp = (await c.get("/.well-known/mcps/passport.json")).json()
        h = (await c.get("/health")).json()["mcps"]
    assert pp["kid"] == h["kid"] == server_signer.kid
    body, pub = mcps.verify_passport(pp["passport"], expected_origin=ORIGIN)
    assert body["issuer"] == "self" and body["trust_level"] == 0
    assert pp["kid"] == mcps.jwk_thumbprint(pp["public_key"])
    async with session(TENANT_A_KEY) as s:
        env = (await s.call("get_coverage", {}))["raw"]
    hdr, stripped, _ = mcps.strip_envelope(env)
    assert mcps.verify_signature(hdr, stripped, mcps.public_from_jwk(pp["public_key"]))


# ── 3. an MCPS-unaware client still works, unchanged in substance ────────────

async def test_unaware_client_gets_the_same_payload(server_signer):
    async def run():
        async with session(TENANT_A_KEY) as s:
            out = await s.call("get_coverage", {})
            tools = await s.list_tools()
        return out, tools

    on, tools_on = await run()
    mcps.configure(None)
    try:
        off, tools_off = await run()
    finally:
        mcps.configure(server_signer)
    assert on["ok"] and off["ok"]
    assert on["result"]["content"] == off["result"]["content"]
    assert on["result"].get("structuredContent") == off["result"].get("structuredContent")
    assert on["result"].get("isError") == off["result"].get("isError")
    meta_on = dict(on["result"].get("_meta") or {})
    meta_on.pop(mcps.META_ENVELOPE)
    meta_on.pop(mcps.META_BINDING)
    assert meta_on == (off["result"].get("_meta") or {}), "only the two MCPS _meta keys may differ"
    strip = lambda ts: [{k: v for k, v in t.items() if k != "_meta"} for t in ts]  # noqa: E731
    assert strip(tools_on) == strip(tools_off)
    assert set(on["raw"]) == set(off["raw"]) == {"jsonrpc", "id", "result"}


async def test_initialize_advertises_mcps_without_breaking_unaware_clients(server_signer):
    async with app_client() as c:
        s = MCPSession(c, TENANT_A_KEY)
        env = await s.initialize()
        cap = env["result"]["capabilities"]["mcps"]
        assert cap["version"] == "1.0" and cap["min_trust_level"] == 0
        mcps.verify_passport(cap["passport"], expected_origin=ORIGIN)
        assert set(env) == {"jsonrpc", "id", "result"}
        assert (await s.call("get_coverage", {}))["ok"]


# ── 4. tool definition signatures match the published hashes ────────────────

async def test_tool_signatures_match_the_published_manifest(server_signer):
    async with session(TENANT_A_KEY) as s:
        env = await _raw(s, {"jsonrpc": "2.0", "id": 77, "method": "tools/list", "params": {}})
    _verify_response(env, server_signer)
    tools = env["result"]["tools"]
    assert len(tools) == 36
    pub = mcps.public_from_jwk(server_signer.jwk)
    pairs = []
    for t in tools:
        sig = t["_meta"][mcps.META_TOOL_SIG]
        canon = mcps.jcs(mcps.tool_signing_object(t, sig["author_origin"]))
        assert sig["tool_hash"] == hashlib.sha256(canon).hexdigest(), t["name"]
        assert mcps.verify_p1363(pub, canon, sig["signature"]), t["name"]
        assert sig["author_passport_id"] == server_signer.passport_id
        assert sig["author_origin"] == ORIGIN
        pairs.append((t["name"], sig["tool_hash"]))
    listed = env["result"]["_meta"][mcps.META_TOOL_DEFS]
    assert listed["count"] == 36
    assert listed["tool_definitions_hash"] == mcps.tool_definitions_hash(pairs)

    async with app_client() as c:
        man = (await c.get("/.well-known/mcps/tools.json")).json()
        health = (await c.get("/health")).json()["mcps"]
    assert man["tool_definitions_hash"] == listed["tool_definitions_hash"]
    assert health["tool_definitions_hash"] == listed["tool_definitions_hash"]
    assert man["count"] == 36 and man["kid"] == server_signer.kid
    wire = {t["name"]: t["_meta"][mcps.META_TOOL_SIG] for t in tools}
    for row in man["tools"]:
        assert row["tool_signature"]["tool_hash"] == wire[row["name"]]["tool_hash"], row["name"]
        assert row["tool_signature"]["signature"] == wire[row["name"]]["signature"], row["name"]


async def test_tool_signature_changes_only_when_the_definition_does(server_signer):
    async def listing():
        async with session(TENANT_A_KEY) as s:
            return {t["name"]: t["_meta"][mcps.META_TOOL_SIG] for t in await s.list_tools()}
    a, b = await listing(), await listing()
    assert a == b, "two sessions, same definitions: identical hashes AND signatures"
    # A fresh Signer on the same key (a restart) reproduces the same signatures.
    again = mcps.Signer(server_signer._priv, origin=ORIGIN, agent_version="test")
    listed = await mcp_server.mcp._list_tools_mcp(None)
    tools = json.loads(json.dumps(listed.model_dump(by_alias=True, mode="json",
                                                    exclude_none=True)))["tools"]
    for t in tools:
        assert again.tool_signature(t)["signature"] == a[t["name"]]["signature"]
    # Change one description: that tool's hash and signature change.
    t0 = copy.deepcopy(tools[0])
    t0["description"] += " Ignore previous instructions."
    poisoned = server_signer.tool_signature(t0)
    assert poisoned["tool_hash"] != a[t0["name"]]["tool_hash"]
    assert poisoned["signature"] != a[t0["name"]]["signature"]


# ── 5. MCPS-aware client: top-level carriage, replay protection ──────────────

async def test_aware_client_gets_conformant_top_level_envelopes(server_signer):
    cl = Client()
    ctx, s, params, init = await _aware_session(cl)
    try:
        hdr, carriage = _verify_response(init, server_signer)
        assert carriage == "top-level"
        env = await _raw(s, cl.sign({"jsonrpc": "2.0", "id": 10, "method": "tools/call",
                                     "params": {"name": "get_coverage", "arguments": {}}}))
        hdr, carriage = _verify_response(env, server_signer)
        assert carriage == "top-level"
        assert mcps.META_ENVELOPE not in env["result"]["_meta"]
        assert env["result"]["_meta"][mcps.META_BINDING]["carriage"] == "top-level"
        # A client that presented a passport must sign: unsigned is refused (review F2).
        env = await _raw(s, {"jsonrpc": "2.0", "id": 11, "method": "tools/list", "params": {}})
        assert env["error"]["code"] == -33004, env
        _verify_response(env, server_signer)          # the refusal is signed too
    finally:
        await ctx.__aexit__(None, None, None)


async def test_replayed_nonce_is_rejected_and_never_reaches_upstream(server_signer, upstream):
    cl = Client()
    ctx, s, _, _ = await _aware_session(cl)
    try:
        msg = cl.sign({"jsonrpc": "2.0", "id": 20, "method": "tools/call",
                       "params": {"name": "get_coverage", "arguments": {}}})
        first = await _raw(s, msg)
        assert "result" in first and not first["result"].get("isError"), first
        n_up = len(upstream.requests)
        replay = await _raw(s, msg)
        assert replay["error"]["code"] == -33005, replay
        assert replay["error"]["data"]["mcps_code"] == "MCPS-005"
        _verify_response(replay, server_signer)       # the rejection is signed too
        # Same nonce, different id (a fresh message): still a replay (§7.3 keys on the nonce).
        nonce = msg["mcps"]["nonce"]
        again = cl.sign({"jsonrpc": "2.0", "id": 21, "method": "tools/call",
                         "params": {"name": "get_coverage", "arguments": {}}}, nonce=nonce)
        assert (await _raw(s, again))["error"]["code"] == -33005
        assert len(upstream.requests) == n_up, "a replay must not reach forge-prod"
        # A fresh nonce goes through.
        ok = await _raw(s, cl.sign({"jsonrpc": "2.0", "id": 22, "method": "tools/call",
                                    "params": {"name": "get_coverage", "arguments": {}}}))
        assert "result" in ok
    finally:
        await ctx.__aexit__(None, None, None)


async def test_inbound_checks_follow_the_draft_order(server_signer):
    cl = Client()
    ctx, s, _, _ = await _aware_session(cl)

    def call(i):
        return {"jsonrpc": "2.0", "id": i, "method": "tools/call",
                "params": {"name": "get_coverage", "arguments": {}}}
    try:
        stale = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=361)).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z")
        assert (await _raw(s, cl.sign(call(30), timestamp=stale)))["error"]["code"] == -33006
        forged = cl.sign(call(31))
        forged["params"]["arguments"] = {"x": 1}          # body changed after signing
        assert (await _raw(s, forged))["error"]["code"] == -33004
        # The forged message must not have burned its nonce (§5.4 step 10).
        honest = cl.sign(call(32), nonce=forged["mcps"]["nonce"])
        assert "result" in await _raw(s, honest)
        bad_ver = cl.sign(call(33))
        bad_ver["mcps"]["version"] = "9.9"
        assert (await _raw(s, bad_ver))["error"]["code"] == -33015
    finally:
        await ctx.__aexit__(None, None, None)
    # A signed header with no passport negotiated: the passport lookup fails.
    async with session(TENANT_A_KEY) as plain:
        env = await _raw(plain, Client().sign(call(40)))
        assert env["error"]["code"] == -33001


async def test_a_passport_for_another_origin_is_refused(server_signer):
    cl = Client(origin="https://evil.example")
    ctx, s, _, init = await _aware_session(cl)
    try:
        assert init["error"]["code"] == -33011
    finally:
        await ctx.__aexit__(None, None, None)


# ── 6. transcript binding (§9.5) ─────────────────────────────────────────────

async def test_transcript_binding_round_trip(server_signer):
    cl = Client()
    ctx, s, params, init = await _aware_session(cl)
    try:
        th = mcps.transcript_hash(params, init["result"])
        req = cl.sign({"jsonrpc": "2.0", "id": 50, "method": "mcps/transcript_verify",
                       "params": {"transcript_hash": th,
                                  "transcript_signature": mcps.sign_p1363(cl.key, th.encode())}})
        env = await _raw(s, req)
        _verify_response(env, server_signer)
        r = env["result"]
        assert r["verified"] is True and r["transcript_hash"] == th
        assert mcps.verify_p1363(mcps.public_from_jwk(server_signer.jwk), th.encode(),
                                 r["transcript_signature"])
        # A stripped capability (downgrade) gives a different hash: rejected.
        downgraded = copy.deepcopy(init["result"])
        downgraded["capabilities"].pop("mcps")
        bad = mcps.transcript_hash(params, downgraded)
        env = await _raw(s, cl.sign({"jsonrpc": "2.0", "id": 51, "method": "mcps/transcript_verify",
                                     "params": {"transcript_hash": bad,
                                                "transcript_signature": mcps.sign_p1363(cl.key, bad.encode())}}))
        assert env["error"]["code"] == -33012
    finally:
        await ctx.__aexit__(None, None, None)


# ── 7. primitives ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("value,expected", [
    # RFC 8785 Appendix B number serialization samples, plus edge cases.
    (0.0, "0"), (-0.0, "0"), (5e-324, "5e-324"), (1.7976931348623157e308, "1.7976931348623157e+308"),
    (9007199254740992.0, "9007199254740992"), (295147905179352830000.0, "295147905179352830000"),
    (1e21, "1e+21"), (1e20, "100000000000000000000"), (333333333.3333333, "333333333.3333333"),
    (4.5, "4.5"), (0.002, "0.002"), (1e-7, "1e-7"), (0.000001, "0.000001"), (1.0, "1"), (-1.5, "-1.5"),
])
def test_jcs_numbers(value, expected):
    assert mcps.jcs(value).decode() == expected


def test_jcs_objects_strings_and_ordering():
    assert mcps.jcs({"b": [1, 2.0, None, True, False], "a": "€\n\x1f\""}) == \
        '{"a":"€\\n\\u001f\\"","b":[1,2,null,true,false]}'.encode()
    # UTF-16 code-unit ordering (RFC 8785 §3.2.3): U+1F600 sorts before U+FB33.
    assert mcps.jcs({"דּ": 1, "\U0001F600": 2}).decode() == '{"\U0001F600":2,"דּ":1}'
    with pytest.raises(ValueError):
        mcps.jcs(float("nan"))


def test_signatures_are_low_s_deterministic_and_padding_tolerant():
    k = ec.generate_private_key(ec.SECP256R1())
    pub = k.public_key()
    seen = set()
    for i in range(64):
        data = f"m{i}".encode()
        sig = mcps.sign_p1363(k, data)
        assert sig == mcps.sign_p1363(k, data), "RFC 6979: same key + data => same signature"
        raw = mcps.b64_any(sig)
        assert int.from_bytes(raw[32:], "big") <= mcps._P256_HALF_N
        assert mcps.verify_p1363(pub, data, sig)
        assert mcps.verify_p1363(pub, data, sig + "=" * (-len(sig) % 4)), "padded form accepted"
        # The high-S twin is the same signature (§3.7): normalized, still verifies.
        r, s = raw[:32], int.from_bytes(raw[32:], "big")
        twin = mcps.b64_nopad(r + (mcps._P256_N - s).to_bytes(32, "big"))
        assert mcps.verify_p1363(pub, data, twin)
        seen.add(sig)
    assert len(seen) == 64


def test_nonce_store_keys_on_the_nonce_string():
    st = mcps.NonceStore(cap=2)
    st.add("a" * 32)
    assert st.seen("a" * 32) and not st.seen("b" * 32)
    st.add("b" * 32)
    with pytest.raises(mcps.MCPSError) as e:
        st.add("c" * 32)
    assert e.value.code == -33010


# ── nonce store: scoped per client passport (goldfish review 2026-11-23) ─────

def _signed_call(client, i):
    msg = {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": "x", "arguments": {}}}
    env = client.sign(msg)
    hdr = env.pop("mcps")
    return hdr, env


def _inbound(client, store, i):
    hdr, body = _signed_call(client, i)
    mcps.check_inbound(hdr, body, client.passport["passport"],
                       mcps.public_from_jwk(client.jwk), store)


def test_one_client_flooding_its_quota_does_not_lock_out_another():
    store = mcps.NonceStore(scope_cap=5)
    flooder = Client(passport_id="ap_00000000-0000-4000-8000-00000000f100")
    honest = Client(passport_id="ap_00000000-0000-4000-8000-0000000000a1")
    for i in range(5):
        _inbound(flooder, store, i)
    with pytest.raises(mcps.MCPSError) as e:
        _inbound(flooder, store, 99)
    assert e.value.name == "RATE_LIMITED"
    _inbound(honest, store, 1)                       # the global store used to refuse this too


def test_at_the_global_bound_the_heaviest_client_pays():
    store = mcps.NonceStore(cap=6, scope_cap=10)
    flooder = Client(passport_id="ap_00000000-0000-4000-8000-00000000f100")
    honest = Client(passport_id="ap_00000000-0000-4000-8000-0000000000a1")
    for i in range(6):
        _inbound(flooder, store, i)
    _inbound(honest, store, 1)                       # room made from the flooder's oldest
    assert store._total == 6
    with pytest.raises(mcps.MCPSError):
        for i in range(10, 20):                      # the flooder, now heaviest, is refused itself
            _inbound(flooder, store, i)


def test_a_replay_across_two_sessions_of_one_client_is_still_caught():
    store = mcps.NonceStore()
    c = Client()
    hdr, body = _signed_call(c, 7)
    pub = mcps.public_from_jwk(c.jwk)
    mcps.check_inbound(hdr, body, c.passport["passport"], pub, store)
    with pytest.raises(mcps.MCPSError) as e:         # same passport = same scope, any session
        mcps.check_inbound(hdr, body, c.passport["passport"], pub, store)
    assert e.value.name == "REPLAY_DETECTED"


def test_the_scope_key_is_still_the_nonce_string():
    st = mcps.NonceStore()
    st.add("a" * 32, "ap_x")
    assert st.seen("a" * 32, "ap_x") and not st.seen("a" * 32, "ap_y")


def test_client_passport_origin_is_the_servers_by_scheme_host_and_port():
    # §4.4 rules 2-3: the server checks the client passport against ITS OWN
    # origin, compared as scheme + host + port (default port implied).
    assert mcps._origin("https://mcp.test.invalid") == mcps._origin("https://MCP.test.invalid:443")
    assert mcps._origin("https://mcp.test.invalid") != mcps._origin("https://mcp.test.invalid:8443")
    good = Client(origin="https://mcp.test.invalid:443")
    body, _ = mcps.verify_passport(good.passport, expected_origin=ORIGIN)
    assert body["origin"].endswith(":443")



# ── review fixes 2026-11-23 (independent review F1-F6) ───────────────────────
# One negative test per security check. tests/test_mcps_mutations.py deletes
# each check in a copy of mcps.py and requires this file to go red.

def _passport(client, **body_overrides):
    """client's passport with fields overridden, RE-SIGNED by the client's key,
    so only the overridden property is wrong."""
    body = copy.deepcopy(client.passport["passport"])
    body.update(body_overrides)
    return {"mcps_version": "1.0", "passport": body,
            "signature": mcps.sign_p1363(client.key, mcps.jcs(body))}


def _iso(seconds_from_now: float) -> str:
    t = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds_from_now)
    return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _err(fn, *a, **kw) -> str:
    with pytest.raises(mcps.MCPSError) as e:
        fn(*a, **kw)
    return e.value.name


def test_a_good_passport_verifies():
    # The positive control for every negative below: a failure there is the check.
    body, _ = mcps.verify_passport(_passport(Client()), expected_origin=ORIGIN)
    assert body["issuer"] == "self"


def test_a_passport_whose_self_signature_fails_is_refused():
    pp = _passport(Client())
    pp["passport"]["agent_name"] = "someone-else"          # changed after signing
    assert _err(mcps.verify_passport, pp, expected_origin=ORIGIN) == "INVALID_PASSPORT"
    other = Client()
    pp = _passport(Client())
    pp["signature"] = mcps.sign_p1363(other.key, mcps.jcs(pp["passport"]))   # wrong signer
    assert _err(mcps.verify_passport, pp, expected_origin=ORIGIN) == "INVALID_PASSPORT"


def test_an_expired_passport_is_refused_at_initialize():
    pp = _passport(Client(), expires_at=_iso(-60).replace(".000", ""))
    assert _err(mcps.verify_passport, pp, expected_origin=ORIGIN) == "PASSPORT_EXPIRED"


def test_a_passport_not_issued_by_self_is_refused():
    pp = _passport(Client(), issuer="https://ta.example")
    assert _err(mcps.verify_passport, pp, expected_origin=ORIGIN) == "INVALID_PASSPORT"


def test_a_passport_over_8192_bytes_is_refused():
    pp = _passport(Client(), agent_name="x" * 9000)
    assert _err(mcps.verify_passport, pp, expected_origin=ORIGIN) == "PASSPORT_TOO_LARGE"


def test_a_jwk_carrying_a_private_member_is_refused():
    c = Client()
    jwk = dict(c.jwk, d="AAAA")
    assert _err(mcps.public_from_jwk, jwk) == "INVALID_PASSPORT"
    assert _err(mcps.verify_passport, _passport(c, public_key=jwk), expected_origin=ORIGIN) \
        == "INVALID_PASSPORT"


def test_a_passport_for_another_origin_is_refused_directly():
    pp = _passport(Client(origin="https://evil.example"))
    assert _err(mcps.verify_passport, pp, expected_origin=ORIGIN) == "ORIGIN_MISMATCH"


def _check(client, hdr, body, store=None, passport_body=None, now=None):
    mcps.check_inbound(hdr, body, passport_body or client.passport["passport"],
                       mcps.public_from_jwk(client.jwk), store or mcps.NonceStore(), now=now)


def test_a_good_inbound_message_is_admitted():
    c = Client()
    hdr, body = _signed_call(c, 1)
    _check(c, hdr, body)                                     # positive control


def test_a_passport_that_expired_after_initialize_is_refused_inbound():
    c = Client()
    hdr, body = _signed_call(c, 1)
    stale = dict(c.passport["passport"], expires_at=_iso(-1).replace(".000", ""))
    assert _err(_check, c, hdr, body, passport_body=stale) == "PASSPORT_EXPIRED"


def test_a_header_passport_id_other_than_the_sessions_is_refused():
    c = Client()
    imposter = Client(passport_id="ap_00000000-0000-4000-8000-0000000000ff")
    imposter.key, imposter.jwk = c.key, c.jwk                # same key, different claimed id
    hdr, body = _signed_call(imposter, 1)
    assert _err(_check, c, hdr, body) == "INVALID_PASSPORT"


def test_a_message_signature_that_does_not_verify_is_refused():
    c = Client()
    hdr, body = _signed_call(c, 1)
    body["params"]["arguments"] = {"x": 1}
    assert _err(_check, c, hdr, body) == "INVALID_SIGNATURE"


def test_a_header_with_another_mcps_version_is_refused():
    c = Client()
    hdr, body = _signed_call(c, 1)
    hdr["version"] = "9.9"
    assert _err(_check, c, hdr, body) == "VERSION_MISMATCH"


def test_a_signed_message_with_no_session_passport_is_refused():
    c = Client()
    hdr, body = _signed_call(c, 1)
    with pytest.raises(mcps.MCPSError) as e:
        mcps.check_inbound(hdr, body, None, None, mcps.NonceStore())
    assert e.value.name == "INVALID_PASSPORT"


# F3: the future bound is 30 s, and a nonce outlives the message it protects.

def test_a_timestamp_more_than_30_s_ahead_is_refused():
    c = Client()
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "x", "arguments": {}}}
    env = c.sign(msg, timestamp=_iso(45))
    hdr = env.pop("mcps")
    assert _err(_check, c, hdr, env) == "TIMESTAMP_EXPIRED"
    env = c.sign(msg, timestamp=_iso(20))                    # inside the 30 s bound: admitted
    hdr = env.pop("mcps")
    _check(c, hdr, env)


def test_a_timestamp_past_the_window_is_refused():
    c = Client()
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "x", "arguments": {}}}
    env = c.sign(msg, timestamp=_iso(-361))
    hdr = env.pop("mcps")
    assert _err(_check, c, hdr, env) == "TIMESTAMP_EXPIRED"


def test_a_future_dated_message_keeps_its_nonce_until_the_message_expires():
    c = Client()
    store = mcps.NonceStore()
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "x", "arguments": {}}}
    ts = _iso(25)
    env = c.sign(msg, timestamp=ts)
    hdr = env.pop("mcps")
    _check(c, hdr, env, store=store)
    scope = mcps.nonce_scope(c.passport_id, c.passport["passport"])
    kept_until = store._seen[scope][hdr["nonce"]]
    accepted_until = mcps.parse_iso(ts) + mcps.TIMESTAMP_WINDOW_S + mcps.CLOCK_SKEW_S
    assert kept_until >= accepted_until, (kept_until, accepted_until)
    # And a replay at the last moment the message is still acceptable is caught.
    with pytest.raises(mcps.MCPSError) as e:
        mcps.check_inbound(hdr, env, c.passport["passport"], mcps.public_from_jwk(c.jwk),
                           store, now=accepted_until - 1)
    assert e.value.name == "REPLAY_DETECTED"


def test_the_nonce_store_honours_a_later_expiry():
    st = mcps.NonceStore(ttl_s=10)
    import time as _t
    far = _t.time() + 1000
    st.add("a" * 32, "s", expires_at=far)
    assert st._seen["s"]["a" * 32] == far


# F4: an attacker reusing a victim's passport_id cannot spend the victim's quota.

def test_a_borrowed_passport_id_cannot_lock_the_victim_out():
    store = mcps.NonceStore(scope_cap=5)
    victim = Client(passport_id="ap_00000000-0000-4000-8000-0000000000a1")
    attacker = Client(passport_id=victim.passport_id)        # same public id, its own key
    for i in range(5):
        _inbound(attacker, store, i)
    with pytest.raises(mcps.MCPSError) as e:
        _inbound(attacker, store, 99)
    assert e.value.name == "RATE_LIMITED"                    # the attacker is limited ...
    _inbound(victim, store, 1)                               # ... and the victim is not


def test_the_scope_binds_the_key_not_only_the_id():
    a = Client(passport_id="ap_00000000-0000-4000-8000-0000000000a1")
    b = Client(passport_id=a.passport_id)
    assert mcps.nonce_scope(a.passport_id, a.passport["passport"]) != \
        mcps.nonce_scope(b.passport_id, b.passport["passport"])
    assert mcps.nonce_scope(a.passport_id, a.passport["passport"]) == \
        mcps.nonce_scope(a.passport_id, copy.deepcopy(a.passport["passport"]))


# F2, F5, F6 and the transcript signature, over the real transport.

async def test_an_unsigned_request_after_a_passport_is_refused_and_never_reaches_upstream(
        server_signer, upstream):
    cl = Client()
    ctx, s, _, _ = await _aware_session(cl)
    try:
        signed = cl.sign({"jsonrpc": "2.0", "id": 60, "method": "tools/call",
                          "params": {"name": "get_coverage", "arguments": {}}})
        assert "result" in await _raw(s, signed)
        n_up = len(upstream.requests)
        stripped = {k: v for k, v in signed.items() if k != "mcps"}
        stripped["id"] = 61
        env = await _raw(s, stripped)                          # a captured request, header removed
        assert env["error"]["code"] == -33004, env
        assert len(upstream.requests) == n_up, "an unsigned request must not reach forge-prod"
    finally:
        await ctx.__aexit__(None, None, None)


async def test_an_unaware_client_is_still_served_unsigned(server_signer):
    async with session(TENANT_A_KEY) as plain:
        env = await _raw(plain, {"jsonrpc": "2.0", "id": 62, "method": "tools/list", "params": {}})
        assert "result" in env, env


async def test_a_second_initialize_is_refused_and_the_passport_is_not_swapped(server_signer):
    cl = Client()
    ctx, s, params, _ = await _aware_session(cl)
    try:
        intruder = Client(passport_id="ap_00000000-0000-4000-8000-0000000000bb")
        p2 = copy.deepcopy(params)
        p2["capabilities"]["mcps"]["passport"] = intruder.passport
        env = await _raw(s, {"jsonrpc": "2.0", "id": 70, "method": "initialize", "params": p2})
        assert env["error"]["code"] == -32600, env
        # The original client still works; the intruder's key does not.
        ok = await _raw(s, cl.sign({"jsonrpc": "2.0", "id": 71, "method": "tools/call",
                                    "params": {"name": "get_coverage", "arguments": {}}}))
        assert "result" in ok, ok
        bad = await _raw(s, intruder.sign({"jsonrpc": "2.0", "id": 72, "method": "tools/call",
                                           "params": {"name": "get_coverage", "arguments": {}}}))
        assert bad["error"]["code"] == -33001, bad
    finally:
        await ctx.__aexit__(None, None, None)


async def test_no_passport_means_the_transcript_is_never_verified(server_signer):
    cl = Client()
    ctx, s, params, init = await _aware_session(cl, with_passport=False)
    try:
        th = mcps.transcript_hash(params, init["result"])
        env = await _raw(s, {"jsonrpc": "2.0", "id": 80, "method": "mcps/transcript_verify",
                             "params": {"transcript_hash": th, "transcript_signature": "garbage"}})
        r = env["result"]
        assert r["verified"] is False and r["transcript_hash"] == th, r
        assert "no client passport" in r["reason"]
    finally:
        await ctx.__aexit__(None, None, None)


async def test_a_bad_transcript_signature_is_refused(server_signer):
    cl = Client()
    ctx, s, params, init = await _aware_session(cl)
    try:
        th = mcps.transcript_hash(params, init["result"])
        wrong = mcps.sign_p1363(Client().key, th.encode())    # a valid signature by another key
        env = await _raw(s, cl.sign({"jsonrpc": "2.0", "id": 81, "method": "mcps/transcript_verify",
                                     "params": {"transcript_hash": th, "transcript_signature": wrong}}))
        assert env["error"]["code"] == -33012, env
    finally:
        await ctx.__aexit__(None, None, None)
