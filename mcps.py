"""MCPS-compatible signed envelopes for the Forge MCP server.

Implements, from the text of draft-sharif-mcps-secure-mcp-01 (section numbers
cited inline), the transport-signing layer described in
worklog1/mcps_alignment_2026-11-20/MCPS_DESIGN.md:

  * RFC 8785 (JCS) canonicalization                              (§3.5, §5.5)
  * ECDSA P-256, RFC 6979 deterministic, IEEE P1363 r||s, low-S,
    base64 without padding                                       (§3.5-§3.7)
  * a self-signed Agent Passport (issuer "self" => trust level L0) (§4, §3.4)
  * a signed envelope on every server->client message            (§5.1, §5.2)
  * inbound verification in the §5.4 order, with a nonce store
    keyed on the nonce string and a 300 s + 60 s window           (§5.4, §7)
  * tool definition signatures + an aggregate published hash      (§6)
  * capability negotiation and transcript binding                 (§9)

FORGE'S OWN DATA SIGNING (NTE, Ed25519, forge-prod) IS NOT TOUCHED. This layer
signs the TRANSPORT: which server sent which JSON-RPC message, in which session,
at which sequence number. Forge's records sign the DATA inside those messages.

OFF UNLESS `MCPS_SIGNING_KEY` IS SET. With no key the session streams are not
wrapped at all, so behaviour is byte-for-byte what it was before this module.
A malformed key is logged and leaves the layer off: it never fails boot.

TWO CARRIAGES (design §3.2). The draft puts the header at the top level of the
JSON-RPC message (§3.2) and claims non-MCPS peers ignore it. The official MCP
TypeScript SDK does not: its JSON-RPC response schema is `.strict()`, so an
extra top-level member makes the response unparseable for Claude Desktop,
mcp-remote and most JS clients. So the top-level `mcps` member is used ONLY for
a session whose client announced `capabilities.mcps` at initialize (§9.2);
every other session gets the identical header inside
`result._meta["io.foundrynet/mcps"]`, with `message_hash` computed over the
message with exactly that key removed.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import heapq
import json
import logging
import math
import os
import secrets
import threading
import time
import uuid
from collections import OrderedDict
from typing import Any, Optional

logger = logging.getLogger("foundrynet.mcps")

MCPS_VERSION = "1.0"
ALG = "ES256"                       # informational only; never in the §5.2 payload
META_ENVELOPE = "io.foundrynet/mcps"
META_BINDING = "io.foundrynet/mcps.binding"
META_TOOL_SIG = "io.foundrynet/mcps.tool_signature"
META_TOOL_DEFS = "io.foundrynet/mcps.tool_definitions"
TRANSCRIPT_METHOD = "mcps/transcript_verify"

TIMESTAMP_WINDOW_S = 300            # §7.2 default (30..3600 permitted)
CLOCK_SKEW_S = 60                   # §7.2 default: how far in the PAST a timestamp may lag
FUTURE_SKEW_S = 30                  # owner policy 2026-11-23: at most 30 s AHEAD of this clock.
                                    # Tighter than the draft's symmetric 60 s, and the nonce is
                                    # kept until the message itself expires (NonceStore.add), so a
                                    # future-dated message cannot outlive its nonce (review F3).
NONCE_STORE_CAP = 100_000           # §11.4: memory bound across EVERY client
NONCE_SCOPE_CAP = 10_000            # per client passport: ~28 signed msgs/s for the whole window

# Review N1 (2026-11-23). Passports cost nothing to mint, and initialize,
# notifications and tools/list need no bearer, so a per-PASSPORT quota is no
# rate limit: an anonymous client spread across many passports filled the one
# process-wide store and every MCPS client got -33010. Two defences, both
# applied BEFORE any ECDSA work (§11.4 "rate limiting on incoming messages"):
#   * a token bucket per connection AND per source -- the caller's key when the
#     session carries a valid bearer, else the client address -- checked before
#     the passport or the message signature is verified;
#   * a session with no valid bearer never writes to the shared store: its
#     nonces go to a small store of their own, so anonymous traffic can exhaust
#     only anonymous capacity. Replays are still checked against BOTH stores.
SOURCE_RATE_PER_S = 10.0            # signed messages per second, per source and per connection
SOURCE_BURST = 40                   # bucket depth
SOURCE_TABLE_CAP = 50_000           # buckets kept (LRU): bounded memory however many sources
ANON_NONCE_STORE_CAP = 10_000       # the unauthenticated store, across every anonymous session
ANON_NONCE_SCOPE_CAP = 1_000        # per anonymous client passport
# Which request header carries the client address. The nearest proxy APPENDS to
# X-Forwarded-For, so its rightmost entry is the one a client cannot forge.
# Behind Cloudflare set MCPS_CLIENT_IP_HEADER=cf-connecting-ip.
CLIENT_IP_HEADER_DEFAULT = "x-forwarded-for"

# §3.7 P-256 group order and half order.
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_HALF_N = _P256_N // 2

# §10 error codes.
ERR = {
    "INVALID_PASSPORT":   (-33001, "MCPS-001"),
    "PASSPORT_EXPIRED":   (-33002, "MCPS-002"),
    "INVALID_SIGNATURE":  (-33004, "MCPS-004"),
    "REPLAY_DETECTED":    (-33005, "MCPS-005"),
    "TIMESTAMP_EXPIRED":  (-33006, "MCPS-006"),
    "RATE_LIMITED":       (-33010, "MCPS-010"),
    "ORIGIN_MISMATCH":    (-33011, "MCPS-011"),
    "TRANSCRIPT_MISMATCH": (-33012, "MCPS-012"),
    "PASSPORT_TOO_LARGE": (-33013, "MCPS-013"),
    "VERSION_MISMATCH":   (-33015, "MCPS-015"),
    # Not a draft code: the draft is silent on a second initialize. JSON-RPC
    # Invalid Request, so a client reads it as "this request is not allowed".
    "ALREADY_INITIALIZED": (-32600, "INVALID_REQUEST"),
}


class MCPSError(Exception):
    def __init__(self, name: str, detail: str = ""):
        self.name = name
        self.code, self.string_code = ERR[name]
        self.detail = detail
        super().__init__(f"MCPS_{name}: {detail}")

    def error_data(self) -> dict:
        return {"code": self.code, "message": f"MCPS_{self.name}",
                "data": {"mcps_code": self.string_code, "detail": self.detail}}


# ── RFC 8785 JSON Canonicalization Scheme ───────────────────────────────────

def _jcs_number(x: float) -> str:
    """ECMAScript Number::toString (RFC 8785 §3.2.2.3), from Python's
    shortest round-trip repr."""
    from decimal import Decimal
    if math.isnan(x) or math.isinf(x):
        raise ValueError("JCS: NaN and Infinity are not representable")
    if x == 0:
        return "0"                      # also handles -0 (§5.5 item 5)
    sign = "-" if x < 0 else ""
    _, dt, exp = Decimal(repr(abs(x))).as_tuple()
    digits = "".join(map(str, dt)).lstrip("0")
    while len(digits) > 1 and digits.endswith("0"):
        digits = digits[:-1]
        exp += 1
    k = len(digits)
    n = k + exp                         # value = 0.<digits> * 10**n
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + s


def _jcs_str(s: str) -> str:
    # json.dumps with ensure_ascii=False emits exactly the RFC 8785 §3.2.2.2
    # escapes: \" \\ \b \f \n \r \t and \u00XX (lowercase hex) for the rest of
    # U+0000..U+001F; everything else, including U+007F and non-ASCII, raw.
    return json.dumps(s, ensure_ascii=False)


def _jcs(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if abs(v) <= 2 ** 53:
            return str(v)
        return _jcs_number(float(v))    # I-JSON: numbers are IEEE-754 doubles
    if isinstance(v, float):
        return _jcs_number(v)
    if isinstance(v, str):
        return _jcs_str(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_jcs(i) for i in v) + "]"
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise TypeError("JCS: object keys must be strings")
        # RFC 8785 §3.2.3: sort by UTF-16 code units.
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_jcs_str(k) + ":" + _jcs(v[k]) for k in keys) + "}"
    raise TypeError(f"JCS: unsupported type {type(v).__name__}")


def jcs(v: Any) -> bytes:
    return _jcs(v).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ── encodings ───────────────────────────────────────────────────────────────

def b64_nopad(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii").rstrip("=")


def b64_any(s: str) -> bytes:
    """Accept padded or unpadded, standard or url-safe base64. The draft (§3.5)
    says unpadded; its reference implementation emits padded."""
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)


def b64url_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def now_iso() -> str:
    t = _dt.datetime.now(_dt.timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def parse_iso(s: str) -> float:
    if not isinstance(s, str) or not s:
        raise ValueError("timestamp missing")
    t = s.strip()
    if t.endswith("Z") or t.endswith("z"):
        t = t[:-1] + "+00:00"
    d = _dt.datetime.fromisoformat(t)
    if d.tzinfo is None:
        raise ValueError("timestamp has no UTC offset")
    return d.timestamp()


# ── P-256 keys and signatures ───────────────────────────────────────────────

def _ec():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    return ec, hashes


def jwk_from_public(pub) -> dict:
    nums = pub.public_numbers()
    return {"kty": "EC", "crv": "P-256",
            "x": b64url_nopad(nums.x.to_bytes(32, "big")),
            "y": b64url_nopad(nums.y.to_bytes(32, "big"))}


def public_from_jwk(jwk: dict):
    """§4.7: kty EC, crv P-256, no `d`, point on curve (from_encoded_point
    validates the point)."""
    ec, _ = _ec()
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise MCPSError("INVALID_PASSPORT", "public_key must be an EC P-256 JWK")
    if "d" in jwk:
        raise MCPSError("INVALID_PASSPORT", "public_key must not carry a private member")
    try:
        x = b64_any(jwk["x"])
        y = b64_any(jwk["y"])
        if len(x) != 32 or len(y) != 32:
            raise ValueError("coordinate length")
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + x + y)
    except MCPSError:
        raise
    except Exception as e:
        raise MCPSError("INVALID_PASSPORT", f"public_key is not a valid P-256 point ({e})")


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint: required members only, lexicographic, no spaces."""
    req = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    return b64url_nopad(hashlib.sha256(jcs(req)).digest())


def sign_p1363(priv, data: bytes) -> str:
    ec, hashes = _ec()
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    der = priv.sign(data, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    if s > _P256_HALF_N:                # §3.7 item 2
        s = _P256_N - s
    return b64_nopad(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def verify_p1363(pub, data: bytes, sig: str) -> bool:
    ec, hashes = _ec()
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.exceptions import InvalidSignature
    try:
        raw = b64_any(sig)
    except Exception:
        return False
    if len(raw) != 64:
        return False
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    if s > _P256_HALF_N:                # §3.7 item 3: normalize before verify
        s = _P256_N - s
    try:
        pub.verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


# ── the server's identity ───────────────────────────────────────────────────

def _derived_passport_id(thumb: str) -> str:
    """Stable per key, formatted as a UUID v4 (version/variant bits set). Not
    random -- see design §3.1; MCPS_PASSPORT_ID overrides."""
    raw = bytearray(hashlib.sha256(("mcps-passport:" + thumb).encode()).digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return "ap_" + str(uuid.UUID(bytes=bytes(raw)))


class Signer:
    def __init__(self, private_key, *, origin: str, agent_version: str,
                 passport_id: Optional[str] = None, signed_at: Optional[str] = None):
        self._priv = private_key
        self.public_key = private_key.public_key()
        self.jwk = jwk_from_public(self.public_key)
        self.kid = jwk_thumbprint(self.jwk)
        self.origin = origin.rstrip("/")
        self.passport_id = passport_id or _derived_passport_id(self.kid)
        self.signed_at = signed_at or now_iso()
        issued = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
        body = {
            "id": self.passport_id,
            "agent_name": "forge-mcp",
            "agent_version": agent_version,
            "issuer": "self",               # §4.2: self-signed => L0 (§3.4)
            "origin": self.origin,
            "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (issued + _dt.timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "public_key": self.jwk,
            "capabilities": ["tools/list", "tools/call"],
            "trust_level": 0,
            "issuer_chain": [],
        }
        self.passport = {"mcps_version": MCPS_VERSION, "passport": body,
                         "signature": self.sign(jcs(body))}
        self._tool_cache: dict[str, str] = {}
        self._tool_lock = threading.Lock()

    @classmethod
    def from_pem(cls, pem: str, **kw) -> "Signer":
        from cryptography.hazmat.primitives import serialization
        ec, _ = _ec()
        text = pem.replace("\\n", "\n").strip().encode()
        key = serialization.load_pem_private_key(text, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
            raise ValueError("MCPS_SIGNING_KEY must be an EC P-256 (secp256r1) private key")
        return cls(key, **kw)

    def sign(self, data: bytes) -> str:
        return sign_p1363(self._priv, data)

    # §5.2
    def envelope(self, message_wo_mcps: dict) -> dict:
        nonce = secrets.token_hex(16)
        ts = now_iso()
        payload = {"message_hash": sha256_hex(jcs(message_wo_mcps)),
                   "nonce": nonce, "passport_id": self.passport_id, "timestamp": ts}
        return {"version": MCPS_VERSION, "passport_id": self.passport_id,
                "timestamp": ts, "nonce": nonce, "signature": self.sign(jcs(payload))}

    # §6.3
    def tool_signature(self, tool: dict) -> dict:
        obj = tool_signing_object(tool, self.origin)
        canon = jcs(obj)
        th = sha256_hex(canon)
        with self._tool_lock:
            sig = self._tool_cache.get(th)
            if sig is None:
                sig = self.sign(canon)      # deterministic, cached anyway
                self._tool_cache[th] = sig
        return {"author_passport_id": self.passport_id, "author_origin": self.origin,
                "signed_at": self.signed_at, "signature": sig, "tool_hash": th}

    def public_view(self) -> dict:
        return {"mcps_version": MCPS_VERSION, "alg": ALG, "kid": self.kid,
                "public_key": self.jwk, "passport_id": self.passport_id,
                "origin": self.origin, "trust_level": 0,
                "trust_level_note": "self-signed passport; capped at L0 by §3.4",
                "passport": self.passport}


def tool_signing_object(tool: dict, origin: Optional[str]) -> dict:
    return {"author_origin": origin if origin else None,
            "description": tool.get("description"),
            "inputSchema": tool.get("inputSchema") if tool.get("inputSchema") is not None else {},
            "name": tool.get("name")}


def tool_definitions_hash(pairs: list) -> str:
    """hex SHA-256 over JCS of [{name, tool_hash}] sorted by name."""
    rows = sorted(({"name": n, "tool_hash": h} for n, h in pairs), key=lambda r: r["name"])
    return sha256_hex(jcs(rows))


# ── verification helpers (also what a client would run) ─────────────────────

def strip_envelope(message: dict) -> tuple[Optional[dict], dict, str]:
    """Return (header, message_without_header, carriage)."""
    m = json.loads(json.dumps(message))
    if isinstance(m.get("mcps"), dict):
        return m.pop("mcps"), m, "top-level"
    res = m.get("result")
    if isinstance(res, dict) and isinstance(res.get("_meta"), dict) \
            and isinstance(res["_meta"].get(META_ENVELOPE), dict):
        hdr = res["_meta"].pop(META_ENVELOPE)
        if not res["_meta"]:
            res.pop("_meta")
        return hdr, m, "_meta"
    return None, m, "none"


def verify_passport(pp: dict, *, expected_origin: Optional[str] = None,
                    now: Optional[float] = None):
    """Self-signature, expiry, optional origin. Returns (body, public_key)."""
    if not isinstance(pp, dict) or not isinstance(pp.get("passport"), dict):
        raise MCPSError("INVALID_PASSPORT", "passport object missing")
    body = pp["passport"]
    if len(jcs(body)) > 8192:
        raise MCPSError("PASSPORT_TOO_LARGE", "passport exceeds 8192 bytes (§4.3)")
    for f in ("id", "agent_name", "agent_version", "issuer", "origin",
              "issued_at", "expires_at", "public_key"):
        if f not in body:
            raise MCPSError("INVALID_PASSPORT", f"passport.{f} missing")
    if not str(body["id"]).startswith("ap_"):
        raise MCPSError("INVALID_PASSPORT", "passport.id must start with ap_")
    pub = public_from_jwk(body["public_key"])
    # Only self-signed passports are accepted (no Trust Authority, §8, is
    # configured), and they are L0 regardless of any trust_level they claim.
    if body.get("issuer") != "self":
        raise MCPSError("INVALID_PASSPORT", "only self-signed passports are accepted (no TA configured)")
    if not verify_p1363(pub, jcs(body), pp.get("signature") or ""):
        raise MCPSError("INVALID_PASSPORT", "passport signature does not verify")
    try:
        exp = parse_iso(body["expires_at"])
    except Exception:
        raise MCPSError("INVALID_PASSPORT", "passport.expires_at unparseable")
    if (now if now is not None else time.time()) > exp:
        raise MCPSError("PASSPORT_EXPIRED", "passport expired")
    if expected_origin is not None and _origin(body["origin"]) != _origin(expected_origin):
        raise MCPSError("ORIGIN_MISMATCH", "passport origin does not match this server")
    return body, pub


def _origin(u: str) -> str:
    from urllib.parse import urlsplit
    p = urlsplit(str(u))
    port = p.port or (443 if p.scheme == "https" else 80 if p.scheme == "http" else None)
    return f"{p.scheme.lower()}://{(p.hostname or '').lower()}:{port}"


def verify_signature(header: dict, message_wo_header: dict, pub) -> bool:
    payload = {"message_hash": sha256_hex(jcs(message_wo_header)),
               "nonce": header.get("nonce"), "passport_id": header.get("passport_id"),
               "timestamp": header.get("timestamp")}
    if "channel_binding" in header:
        payload["channel_binding"] = header["channel_binding"]
    return verify_p1363(pub, jcs(payload), header.get("signature") or "")


class NonceStore:
    """§7.3: keyed on the nonce STRING, within the client's passport id;
    retained for window + skew.

    SCOPED PER CLIENT. One process-wide set let any client that minted a
    self-signed passport fill it (about 280 signed messages/s for 360 s) and
    every OTHER session's signed messages then got -33010 for six minutes
    (goldfish review 2026-11-23). Keying on (passport_id, nonce) still keys on
    the nonce string, never on message bytes, so the (r, n-s) malleable variant
    is still a replay. Two connections presenting the SAME passport share a
    scope, so a replay across sessions of one client is still caught. A nonce
    cannot be moved into another scope: the signed payload binds passport_id,
    and a nonce is stored only after the signature verifies (§5.4 step 10).

    §11.4: expired nonces are collected under pressure; one client is
    rate-limited at `scope_cap` without touching anyone else; and at the global
    `cap`, as the last resort the draft allows, room is made by evicting the
    oldest nonces of the HEAVIEST scope -- or, when the requester IS the
    heaviest, by refusing the requester alone.
    """

    def __init__(self, ttl_s: float = TIMESTAMP_WINDOW_S + CLOCK_SKEW_S,
                 cap: int = NONCE_STORE_CAP, scope_cap: int = NONCE_SCOPE_CAP):
        self.ttl = ttl_s
        self.cap = cap
        self.scope_cap = scope_cap
        self._seen: dict[str, dict[str, float]] = {}    # scope -> {nonce: expiry}, oldest first
        self._total = 0
        # (expiry, scope, nonce), soonest first. Collection pops only what has
        # expired, so it is amortised O(log n) per add instead of a scan of the
        # whole store under the lock on every add at the cap (review F7: 24 ms
        # per add at 100k, on the event loop). Entries for nonces evicted or
        # re-added since are stale and are skipped when they surface.
        self._heap: list[tuple[float, str, str]] = []
        self._lock = threading.Lock()

    def seen(self, nonce: str, scope: str = "") -> bool:
        with self._lock:
            t = (self._seen.get(scope) or {}).get(nonce)
            return t is not None and t > time.time()

    @property
    def total(self) -> int:
        """Nonces held (deliberately not __len__: an empty store must stay truthy)."""
        return self._total

    def _collect(self, now: float) -> None:
        h = self._heap
        while h and h[0][0] <= now:
            exp, sc, n = heapq.heappop(h)
            d = self._seen.get(sc)
            if d is not None and d.get(n) == exp:
                del d[n]
                self._total -= 1
                if not d:
                    del self._seen[sc]
        if len(h) > 2 * self.cap + 1024:            # stale entries from evictions
            self._heap = [(e, sc, n) for sc, d in self._seen.items() for n, e in d.items()]
            heapq.heapify(self._heap)

    def add(self, nonce: str, scope: str = "", expires_at: Optional[float] = None) -> None:
        """Store `nonce` in `scope` until `expires_at` (default now + ttl).

        check_inbound passes the time the MESSAGE stops being acceptable, so a
        message signed with a future timestamp keeps its nonce for as long as
        the message itself could be replayed (review F3)."""
        with self._lock:
            now = time.time()
            self._collect(now)
            mine = self._seen.get(scope) or {}
            if nonce in mine:                               # expired, not yet collected
                del mine[nonce]
                self._total -= 1
            if len(mine) >= self.scope_cap:
                raise MCPSError("RATE_LIMITED", "nonce quota for this client passport is full")
            if self._total >= self.cap:
                heaviest = max(self._seen, key=lambda sc: len(self._seen[sc]))
                if heaviest == scope or len(self._seen[heaviest]) <= len(mine) + 1:
                    raise MCPSError("RATE_LIMITED", "nonce store full")
                victims = self._seen[heaviest]
                del victims[next(iter(victims))]           # its oldest nonce
                self._total -= 1
            exp = max(now + self.ttl, expires_at or 0.0)
            self._seen.setdefault(scope, {})[nonce] = exp
            heapq.heappush(self._heap, (exp, scope, nonce))
            self._total += 1

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()
            self._heap.clear()
            self._total = 0


class RateLimiter:
    """Token buckets keyed by source (review N1). `take` is O(1), does no I/O
    and no crypto, so it can run before every expensive check. The table is
    LRU-bounded at `cap` keys."""

    def __init__(self, rate: float = SOURCE_RATE_PER_S, burst: float = SOURCE_BURST,
                 cap: int = SOURCE_TABLE_CAP, clock=time.monotonic):
        self.rate, self.burst, self.cap, self._clock = float(rate), float(burst), cap, clock
        self._b: "OrderedDict[str, tuple[float, float]]" = OrderedDict()
        self._lock = threading.Lock()

    def take(self, key: str) -> bool:
        with self._lock:
            now = self._clock()
            prev = self._b.pop(key, None)
            tokens = self.burst if prev is None else min(self.burst, prev[0] + (now - prev[1]) * self.rate)
            ok = tokens >= 1.0
            if ok:
                tokens -= 1.0
            self._b[key] = (tokens, now)
            if len(self._b) > self.cap:
                self._b.popitem(last=False)
            return ok

    def clear(self) -> None:
        with self._lock:
            self._b.clear()


def _env_float(name: str, default: float) -> float:
    try:
        v = float(os.environ.get(name, "") or default)
        return v if v > 0 else default
    except ValueError:
        return default


def client_source(request: Any, session_tag: str) -> str:
    """The rate-limit key for a session with no valid bearer: the client
    address from the configured header (rightmost entry: the one the nearest
    proxy appended), else the socket peer, else the connection itself."""
    hdr = (os.environ.get("MCPS_CLIENT_IP_HEADER") or CLIENT_IP_HEADER_DEFAULT).strip().lower()
    headers = getattr(request, "headers", None)
    if headers is not None and hdr:
        try:
            v = headers.get(hdr)
        except Exception:
            v = None
        if v:
            last = str(v).split(",")[-1].strip()
            if last:
                return "ip:" + last
    host = getattr(getattr(request, "client", None), "host", None)
    if host:
        return "ip:" + str(host)
    return "conn:" + session_tag


def nonce_scope(passport_id: Any, passport_body: Optional[dict]) -> str:
    """The nonce/quota scope: the passport id AND the RFC 7638 thumbprint of the
    key the session authenticated with (review F4).

    passport_id alone is chosen by the client and is public (it is in every
    header), so anyone could mint a self-signed passport with a VICTIM's id,
    fill that scope and lock the victim out with -33010. Binding the scope to
    the verified key means only the holder of the victim's private key can
    spend the victim's quota. It is deliberately not per-SESSION: passports are
    public, so a per-session scope would let a replay of the victim's signed
    message through in a new session that presents the victim's passport."""
    thumb = ""
    if isinstance(passport_body, dict) and isinstance(passport_body.get("public_key"), dict):
        try:
            thumb = jwk_thumbprint(passport_body["public_key"])
        except Exception:
            thumb = ""
    return f"{passport_id}|{thumb}"


def check_inbound(header: dict, message_wo_header: dict, passport_body: Optional[dict],
                  pub, nonces: NonceStore, now: Optional[float] = None,
                  also_seen: tuple = ()) -> None:
    """§5.4 steps 2-10, in the draft's order. Raises MCPSError.

    The nonce is stored in `nonces`; a replay is looked for there AND in every
    store in `also_seen`, so a message first accepted in an authenticated
    session cannot be replayed through an anonymous one, or the reverse."""
    for f in ("version", "passport_id", "timestamp", "nonce", "signature"):
        if not header.get(f):
            raise MCPSError("INVALID_SIGNATURE", f"mcps.{f} missing")
    if header["version"] != MCPS_VERSION:
        raise MCPSError("VERSION_MISMATCH", f"mcps.version {header['version']!r} unsupported")
    t = now if now is not None else time.time()
    try:
        ts = parse_iso(header["timestamp"])
    except Exception:
        raise MCPSError("TIMESTAMP_EXPIRED", "mcps.timestamp unparseable")
    if t - ts > TIMESTAMP_WINDOW_S + CLOCK_SKEW_S:
        raise MCPSError("TIMESTAMP_EXPIRED", "mcps.timestamp outside the acceptance window")
    if ts - t > FUTURE_SKEW_S:
        raise MCPSError("TIMESTAMP_EXPIRED", "mcps.timestamp more than 30 s in the future")
    nonce = header["nonce"]
    if not (isinstance(nonce, str) and len(nonce) == 32
            and all(c in "0123456789abcdefABCDEF" for c in nonce)):
        raise MCPSError("INVALID_SIGNATURE", "mcps.nonce must be 16 bytes, hex-encoded")
    scope = nonce_scope(header["passport_id"], passport_body)
    if nonces.seen(nonce, scope) or any(o.seen(nonce, scope) for o in also_seen):
        raise MCPSError("REPLAY_DETECTED", "nonce already observed")
    if passport_body is None or pub is None:
        raise MCPSError("INVALID_PASSPORT",
                        "no passport for this session; announce capabilities.mcps.passport at initialize")
    if header["passport_id"] != passport_body.get("id"):
        raise MCPSError("INVALID_PASSPORT", "mcps.passport_id does not match the session passport")
    try:
        if t > parse_iso(passport_body["expires_at"]):
            raise MCPSError("PASSPORT_EXPIRED", "passport expired")
    except MCPSError:
        raise
    except Exception:
        raise MCPSError("INVALID_PASSPORT", "passport.expires_at unparseable")
    if not verify_signature(header, message_wo_header, pub):
        raise MCPSError("INVALID_SIGNATURE", "signature does not verify")
    # step 10: only after the signature verifies; kept until the MESSAGE expires.
    nonces.add(nonce, scope, expires_at=ts + TIMESTAMP_WINDOW_S + CLOCK_SKEW_S)


def transcript_hash(client_init_params: dict, server_init_result: dict) -> str:
    return sha256_hex(jcs(client_init_params) + jcs(server_init_result))


# ── module state ────────────────────────────────────────────────────────────

def _anon_store() -> NonceStore:
    return NonceStore(cap=ANON_NONCE_STORE_CAP, scope_cap=ANON_NONCE_SCOPE_CAP)


def _limiter() -> RateLimiter:
    return RateLimiter(rate=_env_float("MCPS_SOURCE_RATE", SOURCE_RATE_PER_S),
                       burst=_env_float("MCPS_SOURCE_BURST", SOURCE_BURST))


_STATE: dict[str, Any] = {"signer": None, "nonces": NonceStore(), "anon_nonces": _anon_store(),
                          "limiter": _limiter(), "error": None, "tdh": None}


def signer() -> Optional[Signer]:
    return _STATE["signer"]


def nonces() -> NonceStore:
    """The shared store: written only by sessions with a valid bearer."""
    return _STATE["nonces"]


def anon_nonces() -> NonceStore:
    """The store for sessions with no valid bearer (review N1)."""
    return _STATE["anon_nonces"]


def limiter() -> RateLimiter:
    return _STATE["limiter"]


def configure(sgn: Optional[Signer]) -> None:
    """Install (or remove, with None) the signer. Tests mint throwaway keys."""
    _STATE["signer"] = sgn
    _STATE["nonces"] = NonceStore()
    _STATE["anon_nonces"] = _anon_store()
    _STATE["limiter"] = _limiter()


def load_from_env(agent_version: str, signed_at: Optional[str] = None) -> Optional[Signer]:
    pem = os.environ.get("MCPS_SIGNING_KEY", "")
    if not pem.strip():
        _STATE["error"] = None
        configure(None)
        return None
    try:
        sgn = Signer.from_pem(
            pem,
            origin=os.environ.get("MCPS_ORIGIN") or "https://mcp.foundrynet.io",
            agent_version=agent_version,
            passport_id=(os.environ.get("MCPS_PASSPORT_ID") or None),
            signed_at=signed_at)
    except Exception as e:  # never fail boot; report on /health
        logger.error("MCPS_SIGNING_KEY is set but unusable (%s); MCPS layer OFF",
                     type(e).__name__)
        _STATE["error"] = f"MCPS_SIGNING_KEY unusable: {type(e).__name__}"
        configure(None)
        return None
    _STATE["error"] = None
    configure(sgn)
    logger.info("MCPS layer ON: kid=%s passport_id=%s", sgn.kid, sgn.passport_id)
    return sgn


def set_tool_definitions_hash(h: Optional[str]) -> None:
    _STATE["tdh"] = h


def current_tool_definitions_hash() -> Optional[str]:
    return _STATE["tdh"]


def load_error() -> Optional[str]:
    return _STATE["error"]


# ── the per-session stream shim ─────────────────────────────────────────────

class _Session:
    """State for one MCP session (one LowLevelServer.run call)."""

    def __init__(self, sgn: Signer):
        self.signer = sgn
        self.session_tag = secrets.token_hex(8)
        self.seq = 0
        self.aware = False
        self.client_passport: Optional[dict] = None
        self.client_pub = None
        self.client_init_params: Optional[dict] = None
        self.initialized = False            # one initialize per session (review F5)
        # Review N3: an initialize MCPS admitted is IN FLIGHT until the SDK
        # answers it. Only its result marks the session initialized; an error
        # (e.g. -32602, no protocolVersion) undoes what it committed, so a valid
        # retry is not refused as a second initialize.
        self.init_inflight = False
        self.init_id: Any = None
        self.transcript: Optional[str] = None
        self.callers: dict[str, Optional[str]] = {}   # sha256(bearer) -> key id, or None (invalid)
        self.unsigned: set = set()          # request ids whose refusal goes out unsigned (N1)
        self.pending: dict[Any, str] = {}   # request id -> method
        self.lock = threading.Lock()

    def next_seq(self) -> int:
        with self.lock:
            self.seq += 1
            return self.seq

    def reset_identity(self) -> None:
        self.client_passport = None
        self.client_pub = None
        self.client_init_params = None
        self.aware = False
        self.transcript = None


def _dump(root) -> dict:
    # Exactly what the transports put on the wire (model_dump_json with
    # by_alias + exclude_none, see mcp/server/{streamable_http,sse,stdio}.py).
    return json.loads(root.model_dump_json(by_alias=True, exclude_none=True))


class _WriteProxy:
    def __init__(self, inner, sess: _Session):
        self._inner = inner
        self._s = sess

    def __getattr__(self, name):
        return getattr(self._inner, name)

    async def __aenter__(self):
        await self._inner.__aenter__()
        return self

    async def __aexit__(self, *exc):
        return await self._inner.__aexit__(*exc)

    async def send(self, msg):
        try:
            self._sign(msg)
        except Exception:  # signing must never take the session down
            logger.exception("MCPS: failed to sign an outbound message; sent unsigned")
        self._track(msg)
        await self._inner.send(msg)

    def send_nowait(self, msg):
        try:
            self._sign(msg)
        except Exception:
            logger.exception("MCPS: failed to sign an outbound message; sent unsigned")
        self._track(msg)
        return self._inner.send_nowait(msg)

    def _track(self, msg) -> None:
        """Review N3: the SDK's answer to the in-flight initialize decides it.
        A result makes the session initialized; an error undoes the passport,
        awareness and transcript that initialize committed."""
        import mcp.types as t
        s = self._s
        if not s.init_inflight:
            return
        root = getattr(getattr(msg, "message", None), "root", None)
        if not isinstance(root, (t.JSONRPCResponse, t.JSONRPCError)) or root.id != s.init_id:
            return
        s.init_inflight = False
        if isinstance(root, t.JSONRPCResponse):
            s.initialized = True
        else:
            s.reset_identity()

    def _sign(self, msg) -> None:
        import mcp.types as t
        root = getattr(getattr(msg, "message", None), "root", None)
        if root is None:
            return
        s, sg = self._s, self._s.signer
        rid = getattr(root, "id", None)
        if rid is not None and rid in s.unsigned:
            # A RATE_LIMITED refusal: signing it would hand a flood the very
            # ECDSA work the limit exists to refuse (review N1).
            s.unsigned.discard(rid)
            s.pending.pop(rid, None)
            return
        if isinstance(root, t.JSONRPCResponse):
            method = s.pending.pop(root.id, None)
            result = root.result if isinstance(root.result, dict) else None
            if result is None:
                return
            if method == "initialize":
                caps = result.setdefault("capabilities", {})
                caps["mcps"] = {"version": MCPS_VERSION, "min_trust_level": 0,
                                "passport": sg.passport}
            if method == "tools/list":
                pairs = []
                for tool in result.get("tools") or []:
                    if not isinstance(tool, dict):
                        continue
                    ts = sg.tool_signature(tool)
                    tool.setdefault("_meta", {})[META_TOOL_SIG] = ts
                    pairs.append((tool.get("name"), ts["tool_hash"]))
                tdh = tool_definitions_hash(pairs)
                if result.get("nextCursor") is None:
                    set_tool_definitions_hash(tdh)
                result.setdefault("_meta", {})[META_TOOL_DEFS] = {
                    "tool_definitions_hash": tdh,
                    "count": len(pairs),
                    "author_passport_id": sg.passport_id,
                    "author_origin": sg.origin,
                }
            result.setdefault("_meta", {})[META_BINDING] = {
                "seq": s.next_seq(), "session": s.session_tag, "kid": sg.kid,
                "alg": ALG, "carriage": "top-level" if s.aware else "_meta",
                "tool_definitions_hash": current_tool_definitions_hash(),
            }
            if method == "initialize" and s.client_init_params is not None:
                s.transcript = transcript_hash(s.client_init_params, _dump(root)["result"])
            body = _dump(root)
            body.pop("mcps", None)
            env = sg.envelope(body)
            if s.aware:
                root.mcps = env
            else:
                result["_meta"][META_ENVELOPE] = env
            return
        if s.aware and isinstance(root, (t.JSONRPCError, t.JSONRPCNotification, t.JSONRPCRequest)):
            if isinstance(root, t.JSONRPCError):
                s.pending.pop(root.id, None)
            body = _dump(root)
            body.pop("mcps", None)
            root.mcps = sg.envelope(body)
        elif isinstance(root, t.JSONRPCError):
            s.pending.pop(root.id, None)


class _ReadProxy:
    def __init__(self, inner, sess: _Session, writer: _WriteProxy):
        self._inner = inner
        self._s = sess
        self._w = writer

    def __getattr__(self, name):
        return getattr(self._inner, name)

    async def __aenter__(self):
        await self._inner.__aenter__()
        return self

    async def __aexit__(self, *exc):
        return await self._inner.__aexit__(*exc)

    def __aiter__(self):
        return self

    async def __anext__(self):
        while True:
            msg = await self._inner.__anext__()
            if await self._admit(msg):
                return msg

    async def receive(self):
        while True:
            msg = await self._inner.receive()
            if await self._admit(msg):
                return msg

    async def _reply(self, msg, request_id, *, result=None, error: Optional[MCPSError] = None,
                     sign: bool = True):
        import mcp.types as t
        from mcp.shared.message import SessionMessage
        if not sign:
            self._s.unsigned.add(request_id)
        if error is not None:
            root = t.JSONRPCError(jsonrpc="2.0", id=request_id,
                                  error=t.ErrorData(**error.error_data()))
        else:
            self._s.pending[request_id] = "_mcps_internal"
            root = t.JSONRPCResponse(jsonrpc="2.0", id=request_id, result=result)
        await self._w.send(SessionMessage(message=t.JSONRPCMessage(root),
                                          metadata=getattr(msg, "metadata", None)))

    async def _caller(self, msg) -> Optional[str]:
        """The key id of the session's VALID bearer, or None (review N1).

        Resolved once per distinct bearer per session, off the event loop. A
        bearer that does not resolve is cached as None: the session is then
        unauthenticated, and its nonces never reach the shared store."""
        req = getattr(getattr(msg, "metadata", None), "request_context", None)
        headers = getattr(req, "headers", None)
        auth = ""
        if headers is not None:
            try:
                auth = (headers.get("authorization") or "").strip()
            except Exception:
                auth = ""
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        if not token:
            return None
        h = hashlib.sha256(token.encode()).hexdigest()
        s = self._s
        if h not in s.callers:
            # A lookup costs a database round trip, so a stream of made-up
            # bearers is throttled too: by the address, in a bucket of its own,
            # so an anonymous flood from an address never blocks a real key's
            # first lookup from it.
            if not limiter().take("lookup:" + client_source(req, s.session_tag)):
                raise MCPSError("RATE_LIMITED", "too many signed messages from this source")
            import anyio
            import gating
            try:
                info = await anyio.to_thread.run_sync(gating.resolve_bearer, token)
            except Exception:
                info = None
            kid = None
            if isinstance(info, dict):
                kid = str(info.get("key_id") or info.get("user_id") or "") or None
            if len(s.callers) >= 8:
                s.callers.pop(next(iter(s.callers)))
            s.callers[h] = kid
            return kid
        return s.callers[h]

    async def _limit(self, msg) -> Optional[str]:
        """Review N1: per-connection and per-source token buckets, taken BEFORE
        the passport or any message signature is verified. Returns the caller's
        key id (None when the session has no valid bearer)."""
        s = self._s
        lim = limiter()
        if not lim.take("conn:" + s.session_tag):
            raise MCPSError("RATE_LIMITED", "too many signed messages on this connection")
        caller = await self._caller(msg)
        if caller is None:
            req = getattr(getattr(msg, "metadata", None), "request_context", None)
            src = client_source(req, s.session_tag)
        else:
            src = "caller:" + caller
        if not lim.take(src):
            raise MCPSError("RATE_LIMITED", "too many signed messages from this source")
        return caller

    async def _admit(self, msg) -> bool:
        """True to pass the message to the SDK, False if it was answered or dropped here."""
        import mcp.types as t
        if isinstance(msg, Exception):
            return True
        root = getattr(getattr(msg, "message", None), "root", None)
        is_req = isinstance(root, t.JSONRPCRequest)
        is_note = isinstance(root, t.JSONRPCNotification)
        if not (is_req or is_note):
            return True
        s = self._s
        try:
            is_init = is_req and root.method == "initialize"
            if is_init and (s.initialized or s.init_inflight):
                # One passport per session, no swaps (review F5): a second
                # initialize would rebind the session's MCPS identity mid-stream.
                raise MCPSError("ALREADY_INITIALIZED", "this session is already initialized")
            extra = root.model_extra or {}
            hdr = extra.get("mcps")
            params = cap = None
            if is_init:
                params = root.params if isinstance(root.params, dict) else {}
                cap = ((params.get("capabilities") or {}).get("mcps")
                       if isinstance(params.get("capabilities"), dict) else None)
            presents = isinstance(cap, dict) and cap.get("passport") is not None
            caller = None
            if hdr is not None or presents:
                # Review N1: every message that would cost ECDSA work pays a
                # token from its connection's and its source's bucket first.
                caller = await self._limit(msg)
            # Review N3: nothing is committed to the session until this
            # initialize has passed every MCPS check; until then the passport
            # lives in these locals.
            passport, pub = s.client_passport, s.client_pub
            if is_init and isinstance(cap, dict):
                vers = cap.get("version")
                vers = vers if isinstance(vers, list) else [vers]
                if MCPS_VERSION not in vers:
                    raise MCPSError("VERSION_MISMATCH", "server supports MCPS 1.0 only")
                if presents:
                    # §4.4 rule 2: "When a client presents a passport, the
                    # server MUST verify that the passport's origin matches
                    # ITS OWN published URI" -- the server's origin, by
                    # scheme + host + port (rule 3, RFC 6454; see _origin).
                    passport, pub = verify_passport(cap["passport"],
                                                    expected_origin=s.signer.origin)
            if hdr is None and s.client_passport is not None and not is_init:
                # Owner policy 2026-11-23 (review F2): a client that has
                # presented a passport is identified, and an unsigned message
                # from an identified client is refused, not served. Otherwise
                # stripping the header skips the signature, nonce and timestamp
                # checks, and a captured request replays unsigned. Applies to
                # notifications too (they are dropped: e.g. an unsigned
                # notifications/cancelled could cancel the client's request).
                raise MCPSError("INVALID_SIGNATURE",
                                "signed messages are required once a passport is presented")
            if hdr is not None:
                if not isinstance(hdr, dict):
                    raise MCPSError("INVALID_SIGNATURE", "mcps header must be an object")
                body = _dump(root)
                body.pop("mcps", None)
                # Review N1: only a session with a valid bearer writes to the
                # shared store; a replay is looked for in both.
                store, other = (nonces(), anon_nonces()) if caller else (anon_nonces(), nonces())
                check_inbound(hdr, body, passport, pub, store, also_seen=(other,))
            if is_init:
                s.client_init_params = json.loads(json.dumps(params))
                s.client_passport, s.client_pub = passport, pub   # None unless presented
                s.aware = isinstance(cap, dict)
                s.init_inflight, s.init_id = True, root.id
            if is_req and root.method == TRANSCRIPT_METHOD:
                await self._transcript(msg, root)
                return False
        except MCPSError as e:
            logger.info("MCPS: rejected %s (%s)", getattr(root, "method", "?"), e)
            if is_req:
                await self._reply(msg, root.id, error=e, sign=e.name != "RATE_LIMITED")
            return False
        if is_req:
            s.pending[root.id] = root.method
        return True

    async def _transcript(self, msg, root) -> None:
        s = self._s
        p = root.params if isinstance(root.params, dict) else {}
        if s.transcript is None:
            raise MCPSError("TRANSCRIPT_MISMATCH", "no initialize transcript in this session")
        if p.get("transcript_hash") != s.transcript:
            raise MCPSError("TRANSCRIPT_MISMATCH", "transcript_hash differs from the server's")
        # No passport = not verified (review F6): with no client key there is
        # nothing to check the client's transcript_signature against, whatever
        # it contains, so the server never reports the binding as verified.
        verified = False
        if s.client_pub is not None:
            if not verify_p1363(s.client_pub, s.transcript.encode(),
                                p.get("transcript_signature") or ""):
                raise MCPSError("TRANSCRIPT_MISMATCH", "transcript_signature does not verify")
            verified = True
        result = {
            "transcript_hash": s.transcript,
            # §9.5 is silent on bytes vs hex text; the reference implementation
            # signs the UTF-8 hex string, and so does this.
            "transcript_signature": s.signer.sign(s.transcript.encode()),
            "verified": verified,
        }
        if not verified:
            result["reason"] = "no client passport in this session: the client's signature was not checked"
        await self._reply(msg, root.id, result=result)


def wrap_streams(read_stream, write_stream):
    """Return (read, write) proxies for one session, or the originals when off."""
    sgn = signer()
    if sgn is None:
        return read_stream, write_stream
    sess = _Session(sgn)
    w = _WriteProxy(write_stream, sess)
    r = _ReadProxy(read_stream, sess, w)
    return r, w


def install(fastmcp_server) -> None:
    """Wrap the low-level server's run() so every session's streams pass
    through the shim. Idempotent."""
    low = fastmcp_server._mcp_server
    if getattr(low, "_mcps_installed", False):
        return
    original = low.run

    async def run(read_stream, write_stream, initialization_options, *a, **kw):
        r, w = wrap_streams(read_stream, write_stream)
        return await original(r, w, initialization_options, *a, **kw)

    low.run = run
    low._mcps_installed = True
