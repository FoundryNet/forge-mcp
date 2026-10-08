"""Behavioural harness for the Forge MCP server (Lane D, D1).

The point of this file is that nothing in the gate is mocked. The tests drive
the real ASGI app `build_dual_app()` returns, over the real Streamable HTTP
transport, through the real `GatingMiddleware`, and down the real
`_call_forge_raw()` upstream path. Exactly two things are substituted:

  * Supabase — a fake whose rows have the SAME shape `forge_api_keys` returns,
    so `validate_key()`, `_key_id_live()` and `check_and_increment()` run their
    own logic (key hashing, status, rotation grace, hard expiry, tier
    derivation) against known rows. The gate is measured, not simulated. The
    fake deliberately implements only the operators gating.py chains: an
    unknown filter raises instead of silently matching everything, because a
    filter that silently does nothing is how a gate comes to read a column that
    is not there, see None, and never fire.
  * The upstream hop to forge-prod — an `httpx.MockTransport` that RECORDS every
    request the server makes. The recording IS the measurement: what identity
    the proxy presents to forge-prod is precisely the tenancy question D1 asks.

Credentials: there are none, and no test needs one. See tests/identities.py.
"""
from __future__ import annotations

import copy
import json
import os
import pathlib
import sys
import types
from datetime import datetime, timedelta, timezone

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
if str(pathlib.Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from identities import (  # noqa: E402
    EXPIRED_KEY,
    METERED_KEY_ID,
    METERED_NOCARD,
    METERED_USER,
    REVOKED_KEY,
    ROTATING_EXPIRED,
    ROTATING_IN_GRACE,
    SANDBOX_KEY,
    SANDBOX_KEY_ID,
    SANDBOX_USER,
    SERVER_KEY_ID,
    SERVER_SHARED_KEY,
    SERVER_USER,
    TENANT_A_KEY,
    TENANT_A_KEY_ID,
    TENANT_A_USER,
    TENANT_B_KEY,
    TENANT_B_KEY_ID,
    TENANT_B_USER,
    sha,
)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _key_rows():
    now = datetime.now(timezone.utc)
    return [
        # Two paying tenants on one deployment. This pair is the whole point of
        # D1: nothing either does may be visible to the other.
        {"id": TENANT_A_KEY_ID, "user_id": TENANT_A_USER, "key_hash": sha(TENANT_A_KEY),
         "status": "active", "is_demo": False, "free_tier": False, "plan": "production",
         "stripe_customer_id": "cus_tenant_a", "stripe_subscription_id": "sub_a",
         "rotation_grace_until": None, "expires_at": None, "metadata": {}},
        {"id": TENANT_B_KEY_ID, "user_id": TENANT_B_USER, "key_hash": sha(TENANT_B_KEY),
         "status": "active", "is_demo": False, "free_tier": False, "plan": "production",
         "stripe_customer_id": "cus_tenant_b", "stripe_subscription_id": "sub_b",
         "rotation_grace_until": None, "expires_at": None, "metadata": {}},
        # Free (sandbox) tenant — the free-tier surface.
        {"id": SANDBOX_KEY_ID, "user_id": SANDBOX_USER, "key_hash": sha(SANDBOX_KEY),
         "status": "active", "is_demo": False, "free_tier": True, "plan": "sandbox",
         "stripe_customer_id": None, "stripe_subscription_id": None,
         "rotation_grace_until": None, "expires_at": None, "metadata": {}},
        # Metered key with no card on file.
        {"id": METERED_KEY_ID, "user_id": METERED_USER, "key_hash": sha(METERED_NOCARD),
         "status": "active", "is_demo": False, "free_tier": False, "plan": "metered",
         "stripe_customer_id": "cus_no_card", "stripe_subscription_id": None,
         "rotation_grace_until": None, "expires_at": None, "metadata": {}},
        # The proxy's own shared key, shaped as forge-prod carries it today:
        # metadata.trusted_origin='mcp' and billing_exempt.
        {"id": SERVER_KEY_ID, "user_id": SERVER_USER, "key_hash": sha(SERVER_SHARED_KEY),
         "status": "active", "is_demo": False, "free_tier": False, "plan": "production",
         "stripe_customer_id": None, "stripe_subscription_id": None,
         "rotation_grace_until": None, "expires_at": None,
         "metadata": {"trusted_origin": "mcp", "billing_exempt": True}},
        # Liveness edges.
        {"id": "keyid-revoked", "user_id": "user-revoked", "key_hash": sha(REVOKED_KEY),
         "status": "revoked", "is_demo": False, "free_tier": False, "plan": "production",
         "stripe_customer_id": None, "stripe_subscription_id": None,
         "rotation_grace_until": None, "expires_at": None, "metadata": {}},
        {"id": "keyid-expired", "user_id": "user-expired", "key_hash": sha(EXPIRED_KEY),
         "status": "active", "is_demo": False, "free_tier": False, "plan": "production",
         "stripe_customer_id": None, "stripe_subscription_id": None,
         "rotation_grace_until": None, "expires_at": _iso(now - timedelta(days=1)),
         "metadata": {}},
        {"id": "keyid-rot-ok", "user_id": "user-rot-ok", "key_hash": sha(ROTATING_IN_GRACE),
         "status": "rotating", "is_demo": False, "free_tier": False, "plan": "production",
         "stripe_customer_id": None, "stripe_subscription_id": None,
         "rotation_grace_until": _iso(now + timedelta(hours=12)), "expires_at": None,
         "metadata": {}},
        {"id": "keyid-rot-gone", "user_id": "user-rot-gone", "key_hash": sha(ROTATING_EXPIRED),
         "status": "rotating", "is_demo": False, "free_tier": False, "plan": "production",
         "stripe_customer_id": None, "stripe_subscription_id": None,
         "rotation_grace_until": _iso(now - timedelta(hours=1)), "expires_at": None,
         "metadata": {}},
    ]


def _user_rows():
    return [
        {"id": TENANT_A_USER, "stripe_customer_id": "cus_tenant_a"},
        {"id": TENANT_B_USER, "stripe_customer_id": "cus_tenant_b"},
        {"id": SANDBOX_USER, "stripe_customer_id": None},
        {"id": METERED_USER, "stripe_customer_id": "cus_no_card"},
    ]


# ── Fake Supabase ────────────────────────────────────────────────────────────
class _Result:
    def __init__(self, data):
        self.data = data


class _Query:
    def __init__(self, store, table):
        self._store, self._table = store, table
        self._eq, self._in, self._limit = {}, {}, None

    def select(self, *_cols):
        self._selected = _cols
        return self

    def eq(self, col, val):
        self._eq[col] = val
        return self

    def in_(self, col, vals):
        self._in[col] = list(vals)
        return self

    def limit(self, n):
        self._limit = n
        return self

    def execute(self):
        if self._store.raise_on_read:
            raise RuntimeError("fake supabase: forced read failure")
        rows = self._store.tables.get(self._table, [])
        out = []
        for r in rows:
            if any(r.get(k) != v for k, v in self._eq.items()):
                continue
            if any(r.get(k) not in v for k, v in self._in.items()):
                continue
            out.append(copy.deepcopy(r))
        if self._limit is not None:
            out = out[: self._limit]
        self._store.reads.append((self._table, dict(self._eq), dict(self._in)))
        return _Result(out)


class _Insert:
    def __init__(self, store, table, payload):
        self._store, self._table, self._payload = store, table, payload

    def execute(self):
        self._store.inserts.append((self._table, copy.deepcopy(self._payload)))
        return _Result([self._payload])


class _Table:
    def __init__(self, store, name):
        self._store, self._name = store, name

    def select(self, *cols):
        return _Query(self._store, self._name).select(*cols)

    def insert(self, payload):
        return _Insert(self._store, self._name, payload)


class _Rpc:
    def __init__(self, store, name, params):
        self._store, self._name, self._params = store, name, params

    def execute(self):
        self._store.rpcs.append((self._name, dict(self._params)))
        if self._name != "increment_mcp_usage":
            return _Result([])
        uid = self._params["p_user_id"]
        month = self._params["p_month"]
        cap = int(self._params["p_cap"])
        bucket = self._store.counters.setdefault((uid, month), 0)
        if bucket >= cap:
            return _Result([{"allowed": False, "call_count": bucket, "cap": cap}])
        self._store.counters[(uid, month)] = bucket + 1
        return _Result([{"allowed": True, "call_count": bucket + 1, "cap": cap}])


class FakeSupabase:
    def __init__(self):
        self.tables = {"forge_api_keys": _key_rows(), "forge_users": _user_rows()}
        self.counters: dict = {}
        self.reads: list = []
        self.inserts: list = []
        self.rpcs: list = []
        self.raise_on_read = False

    def table(self, name):
        return _Table(self, name)

    def rpc(self, name, params):
        return _Rpc(self, name, params)


_FAKE_DB = FakeSupabase()


def _install_stubs():
    fake_supabase = types.ModuleType("supabase")
    fake_supabase.Client = FakeSupabase
    fake_supabase.create_client = lambda url, key: _FAKE_DB
    sys.modules["supabase"] = fake_supabase

    fake_stripe = types.ModuleType("stripe")
    fake_stripe.api_key = ""

    class _Cust:
        @staticmethod
        def retrieve(cid):
            return types.SimpleNamespace(
                invoice_settings=types.SimpleNamespace(default_payment_method=None))

    class _PM:
        @staticmethod
        def list(customer=None, type=None, limit=None):
            has_card = customer in ("cus_tenant_a", "cus_tenant_b")
            return types.SimpleNamespace(data=[{"id": "pm_x"}] if has_card else [])

    fake_stripe.Customer = _Cust
    fake_stripe.PaymentMethod = _PM
    sys.modules["stripe"] = fake_stripe


_install_stubs()

os.environ["SUPABASE_URL"] = "http://fake-supabase.invalid"
os.environ["SUPABASE_SERVICE_KEY"] = "harness-placeholder-not-a-credential"
os.environ["FOUNDRYNET_API_KEY"] = SERVER_SHARED_KEY
os.environ["FORGE_BASE_URL"] = "https://forge.test.invalid"
os.environ["MCP_JWT_SECRET"] = "harness-placeholder-signing-material"
os.environ.pop("ORIGIN_SHARED_SECRET", None)

import httpx  # noqa: E402

import gating  # noqa: E402
import mcp_server  # noqa: E402


# ── Upstream recorder ────────────────────────────────────────────────────────
class UpstreamRecorder:
    """Stands in for forge-prod and keeps every request the proxy made."""

    def __init__(self):
        self.requests: list = []
        self.bodies: list = []
        self.responder = None

    def reset(self):
        self.requests.clear()
        self.bodies.clear()
        self.responder = None

    @property
    def last(self):
        assert self.requests, "no upstream request was made"
        return self.requests[-1]

    @property
    def forge_requests(self) -> list:
        """Only the hops to forge-prod. `fire_sandbox` also POSTs to this
        server's own public /sandbox/echo route, which carries no credential by
        design — counting it as an upstream call would make the tenancy sweep
        look broken on exactly one tool."""
        host = os.environ["FORGE_BASE_URL"].split("//", 1)[-1]
        return [r for r in self.requests if r.url.host == host]

    def auth_tokens(self) -> list:
        out = []
        for r in self.requests:
            a = r.headers.get("authorization", "")
            out.append(a[7:].strip() if a.lower().startswith("bearer ") else a)
        return out

    def caller_key_ids(self) -> list:
        return [r.headers.get("x-forge-caller-key-id") for r in self.requests]

    def _handle(self, request):
        self.requests.append(request)
        try:
            self.bodies.append(json.loads(request.content or b"{}"))
        except Exception:
            self.bodies.append({})
        if self.responder is not None:
            return self.responder(request)
        return httpx.Response(200, json={"ok": True, "echo_path": request.url.path})


_UPSTREAM = UpstreamRecorder()


def pytest_configure(config):
    """Swap the AsyncClient the upstream path constructs so the real
    `_headers()` and the real retry policy run, but no socket opens."""
    real_client = httpx.AsyncClient

    def _factory(*args, **kwargs):
        kwargs.pop("transport", None)
        return real_client(*args, transport=httpx.MockTransport(_UPSTREAM._handle), **kwargs)

    mcp_server.httpx = types.SimpleNamespace(
        AsyncClient=_factory,
        Timeout=httpx.Timeout,
        ConnectError=httpx.ConnectError,
        ReadTimeout=httpx.ReadTimeout,
        RemoteProtocolError=httpx.RemoteProtocolError,
        HTTPError=httpx.HTTPError,
        Request=httpx.Request,
        Response=httpx.Response,
    )


@pytest.fixture(scope="session")
def upstream() -> UpstreamRecorder:
    return _UPSTREAM


@pytest.fixture(scope="session")
def fake_db() -> FakeSupabase:
    return _FAKE_DB


@pytest.fixture(autouse=True)
def _clean_state():
    _UPSTREAM.reset()
    _FAKE_DB.counters.clear()
    _FAKE_DB.reads.clear()
    _FAKE_DB.inserts.clear()
    _FAKE_DB.rpcs.clear()
    _FAKE_DB.raise_on_read = False
    gating._pm_cache.clear()
    gating._acct_cust_cache.clear()
    yield
