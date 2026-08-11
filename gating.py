"""Per-client API gating for the FoundryNet MCP server.

Until now every client of foundrynet-mcp-production shared one upstream
FOUNDRYNET_API_KEY. This module flips that: each MCP client presents its
own `Authorization: Bearer fnet_…` header on every tool call, we validate
the key against Supabase, look up its tier, gate the requested tool
against a tier→tools allowlist, and atomically check+increment a monthly
usage counter against the per-tier cap.

Two tiers (Enterprise + attest_machine_action are deferred):
  • Free  — 7 tools (normalize + read-only history/coverage + fire_sandbox demo
            + corpus-feedback), 100 calls/month. Free keys are minted self-serve
            via /v1/keys (no Stripe binding); `free_tier=true` in forge_api_keys.
            Demo (chat-minted) keys also fall here.
  • Pro   — all 29 deployed tools, 10 000 calls/month. Any active
            forge_api_keys row without `free_tier=true` (i.e. paid keys
            with a Stripe subscription) qualifies as Pro.

Errors are surfaced via `fastmcp.exceptions.ToolError`, which the MCP
wire layer translates to `isError=true` with the error message as the
content text. The message body is a JSON string carrying:
  {error, message, current_tier?, tool?, call_count?, cap?, upgrade_url, signup_url}
so any MCP client / LLM can read the structured fields and route the user
to the right URL.

Failure modes never produce 500s — Supabase blips fail OPEN (allow the
call but log) rather than 503'ing a paying customer's workflow.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

try:
    import jwt as _pyjwt            # PyJWT — optional at import so a missing dep
except Exception:                   # can't take the whole server down; OAuth just
    _pyjwt = None                   # stays disabled until the dep + secret land.

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.dependencies import get_http_headers
from supabase import create_client, Client

logger = logging.getLogger("foundrynet.mcp.gating")

# ── Tier → tools (existing tool names; spec's `normalize_field` etc. map
#    1:1 by intent — see error messages and README for the spec↔code map).
# The DISCOVERY set: everything a new developer needs to see the product WORK
# before they'll pay. A dev must be able to normalize their data, identify a
# machine, check coverage, correct a mapping, read an agent card, and discover
# other agents — all on a free sandbox key over MCP. These mirror the free
# surface of the REST API so MCP and REST agree on what "free" means.
# ALIGNED TO the published rate card (forge-prod/static/pricing.html) 2026-07-27:
# every tool the page prices at $0.00 is callable on the free tier. This set is a
# SUPERSET of the page's free column by design — normalize_telemetry ($0.01),
# fire_sandbox and query_webhook_history stay here as the trial allowance, since
# free-tier access is metered by the 100-calls/month cap, not by per-call price.
# A tool being in this set is NOT a claim that it costs $0; TOOL_COSTS is.
FREE_TOOLS: frozenset[str] = frozenset({
    "normalize_telemetry",     # THE first-value call — trial allowance, priced $0.01
    "identify_machine",        # register/identify a machine — discovery, free
    "get_coverage",            # pre-flight schema introspection (the "get_schema" need)
    "correct_mapping",         # corpus-improvement signal — free so every interaction trains the corpus
    "get_agent_card",          # agent credentials/reputation — discovery, free
    "list_agents",             # agent discovery — free so agents can find each other to coordinate
    "query_machine_history",   # spec: query_machine_data + get_machine_history
    "list_automations",        # spec: get_integrations (lists configured automations)
    "create_automation",       # spec: create_trigger — free per rate card
    "activate_automation",     # spec: execute_action — free per rate card
    "list_guardrails",         # safety boundaries are NEVER paywalled
    "check_guardrail",         # dry-run safety check — free so agents always pre-check
    "query_webhook_history",   # spec: get_integrations (delivery / status)
    "fire_sandbox",            # demo-to-conversion unlock: full loop, 10 fires/key lifetime
    "prediction_accuracy",     # forecast-quality trust signal — free per rate card
    "calculate_oee",           # OEE analytics — free per rate card
    "fleet_oee",               # whole-floor OEE — free per rate card
    "energy_consumption",      # energy + cost per machine — free per rate card
    "shift_report",            # shift handover summary — free per rate card
})
ALL_TOOLS: frozenset[str] = FREE_TOOLS | frozenset({
    "disable_automation",
    "delete_automation",
    "restore_automation",
    "verify_record",           # spec: settle_machine_work (Pro — $0.05/call)
    "predict",                 # TimesFM forecast (Pro — runs ML inference, $0.05/call)
    "predict_breach",          # parametric-insurance threshold-breach primitive (Pro — $0.05)
    "remaining_life",          # remaining-useful-life estimate (Pro — $0.05/call)
    "detect_anomalies",        # statistical anomaly detection (Pro — $0.02, no ML inference)
    "health_index",            # composite multi-sensor health (Pro — $0.25/call)
    "diagnose_machine",        # LLM root-cause analysis (Pro — $0.25/call)
    "fleet_health",            # fleet health dashboard (Pro — $0.50/assessment)
    "predict_batch",           # fleet-scale batch prediction (Pro — $0.50/call)
    "machine_intelligence",    # full-stack machine analysis (Pro — $1.00/call)
})

# Tools that are free on EVERY tier, including a metered account with no card on
# file. Mirrors forge-prod's free_tools exactly. A metered (fnet_) key without a
# payment method is limited to these — every other tool returns payment_required,
# identical to the REST 402. (The free/sandbox tier still gets the wider
# FREE_TOOLS set, including normalize, up to its monthly allowance.)
TRULY_FREE_TOOLS: frozenset[str] = frozenset({
    "identify_machine", "get_coverage", "correct_mapping", "get_agent_card",
})

FREE_CAP = int(os.environ.get("MCP_FREE_CAP", "100"))
PRO_CAP  = int(os.environ.get("MCP_PRO_CAP",  "10000"))

# fire_sandbox is the demo-to-conversion unlock — it's in FREE_TOOLS so any
# valid key can call it, but it carries its own lifetime cap (not monthly)
# so a single key can't pin the sandbox endpoint forever. Stored in the
# same forge_mcp_usage table using month='sandbox-lifetime' so the existing
# atomic check+increment RPC works unchanged.
SANDBOX_FIRE_CAP   = int(os.environ.get("MCP_SANDBOX_FIRE_CAP", "10"))
SANDBOX_MONTH_KEY  = "sandbox-lifetime"

# The pricing/signup pages live on forge.foundrynet.io — foundrynet.io/pricing
# is a 404, so pointing an upgrade CTA there is a closed door on a paying
# customer. Defaults corrected here AND the Railway env vars are updated to match.
PRICING_URL = os.environ.get("MCP_PRICING_URL", "https://forge.foundrynet.io/pricing")
SIGNUP_URL  = os.environ.get("MCP_SIGNUP_URL",  "https://forge.foundrynet.io/")

API_KEY_PREFIX = "fnet_"   # legacy default — kept for cosmetic error-message refs

# Every Forge key namespace the MCP server accepts. It used to be fnet_-only,
# which rejected every forge_prod_/forge_sandbox_/forge_monitor_/forge_agent_
# key the main product now mints — i.e. a paying Runtime customer's key was
# denied at the door. All of these resolve through the same forge_api_keys
# SHA256 hash lookup, so validation is identical; only the tier differs.
ACCEPTED_KEY_PREFIXES = ("fnet_", "forge_prod_", "forge_sandbox_",
                         "forge_monitor_", "forge_agent_")

# ── OAuth 2.0 client-credentials (RFC 6749 §4.4) config ──────────────────────
# Machine-to-machine flow AWS Bedrock AgentCore Gateway + Azure AI Foundry
# expect: the caller POSTs its Forge API key as `client_secret` to /oauth/token
# and gets back a short-lived HS256 JWT it then presents as a normal Bearer
# token. The MCP auth path accepts BOTH the JWT and the raw key (see
# resolve_bearer) so existing `Authorization: Bearer forge_prod_…` clients are
# untouched. Signing is disabled (issue returns None, resolve falls back to key
# lookup) until BOTH PyJWT is importable AND MCP_JWT_SECRET is set — so a
# half-configured deploy degrades to today's key-only behavior, never a 500.
JWT_SECRET      = (os.environ.get("MCP_JWT_SECRET") or "").strip()
JWT_ALG         = "HS256"
JWT_TTL_SECONDS = int(os.environ.get("MCP_JWT_TTL", "900"))    # 15 min (M8: bound the
#   window in which a revoked key's already-minted token can still be used, even
#   if the per-call revocation re-check below fails open during a DB outage).
OAUTH_ISSUER    = (os.environ.get("MCP_OAUTH_ISSUER")
                   or "https://mcp.foundrynet.io").rstrip("/")


def oauth_enabled() -> bool:
    """True only when JWTs can actually be signed/verified."""
    return bool(_pyjwt and JWT_SECRET)


_client: Optional[Client] = None


def _supabase() -> Optional[Client]:
    """Lazy Supabase client. Returns None if credentials aren't configured;
    callers MUST treat that as fail-open so the server still works as
    today during the rollout window before SUPABASE_* env vars land."""
    global _client
    if _client is not None:
        return _client
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_SERVICE_KEY", "").strip()
    if not (url and key):
        logger.warning("gating: SUPABASE_URL/SUPABASE_SERVICE_KEY not set — gating disabled (fail open)")
        return None
    try:
        _client = create_client(url, key)
    except Exception as e:
        logger.warning(f"gating: Supabase client init failed: {type(e).__name__}: {e}")
        return None
    return _client


def _hash_api_key(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _current_month_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


# ── Key validation + tier resolution ─────────────────────────────────────────

def _parse_ts(val) -> Optional[datetime]:
    """Parse a Supabase timestamptz into an aware datetime, else None. Never raises."""
    if not val:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    try:
        s = str(val).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _tier_for_row(row: dict) -> str:
    """Map a forge_api_keys row to 'free' or 'pro'.

    Prefer the `plan` column, which forge-prod sets for all current key
    namespaces (production/monitoring = pro, sandbox = free). forge_agent_
    keys carry their parent account's plan, so they inherit its tier here.
    Fall back to free_tier / is_demo for legacy fnet_ keys that have no plan.
    """
    plan = (row.get("plan") or "").strip().lower()
    if plan in ("production", "monitoring"):
        return "pro"
    if plan == "sandbox":
        return "free"
    return "free" if (row.get("free_tier") or row.get("is_demo")) else "pro"


def validate_key(token: str) -> Optional[dict]:
    """Return {user_id, tier, key_id} on a hit, None on any miss.

    Accepts every Forge key namespace (fnet_/forge_prod_/forge_sandbox_/
    forge_monitor_/forge_agent_). Mirrors forge-prod's `_lookup_api_key_user`:
    a key is live when status is 'active', OR 'rotating' and still inside its
    grace window, AND not past expires_at — so rotated keys keep working during
    their 24h grace and a paying customer's forge_prod_ key authenticates.
    """
    token = (token or "").strip()
    if not token.startswith(ACCEPTED_KEY_PREFIXES):
        return None
    client = _supabase()
    if client is None:
        return None
    try:
        h = _hash_api_key(token)
        r = (client.table("forge_api_keys")
             .select("id,user_id,status,is_demo,free_tier,plan,stripe_customer_id,"
                     "stripe_subscription_id,rotation_grace_until,expires_at")
             .eq("key_hash", h)
             .in_("status", ["active", "rotating"])
             .limit(1)
             .execute())
    except Exception as e:
        logger.warning(f"gating: validate_key Supabase failure: {type(e).__name__}: {e}")
        return None
    rows = r.data or []
    if not rows:
        return None
    row = rows[0]
    now = datetime.now(timezone.utc)
    # Hard expiry (opt-in; NULL = never) — mirror forge-prod's lazy expiry.
    exp = _parse_ts(row.get("expires_at"))
    if exp is not None and now > exp:
        return None
    # Rotation grace: a 'rotating' key is live only inside its window.
    if row.get("status") == "rotating":
        grace = _parse_ts(row.get("rotation_grace_until"))
        if grace is None or now > grace:
            return None
    return {
        "user_id":            row["user_id"],
        "tier":               _tier_for_row(row),
        "key_id":             row["id"],
        # Plan + customer let the middleware apply the SAME payment-method gate
        # forge-prod applies on REST, so a metered (fnet_) key can't run paid
        # tools free over MCP. forge_agent_ keys inherit the parent plan but
        # carry no customer of their own — resolved from the account downstream.
        "plan":               (row.get("plan") or "").strip().lower(),
        "stripe_customer_id": row.get("stripe_customer_id"),
    }


# ── OAuth: mint + verify JWT access tokens ───────────────────────────────────

def issue_access_token(client_id: str, client_secret: str) -> Optional[dict]:
    """client_credentials grant. `client_secret` IS a Forge API key: validate
    it, then mint a 1-hour HS256 JWT. Returns the RFC 6749 §5.1 token response,
    or None when the key is invalid or signing isn't configured (the caller
    maps None → invalid_client)."""
    if not oauth_enabled():
        return None
    info = validate_key(client_secret)
    if info is None:
        return None
    now = int(time.time())
    claims = {
        "sub":       info["user_id"],
        "tier":      info["tier"],
        "key_id":    info["key_id"],
        # Carry the billing context so the payment-method gate applies to OAuth
        # callers exactly as it does to raw-key callers (bounded by the short TTL).
        "plan":      info.get("plan") or "",
        "cust":      info.get("stripe_customer_id"),
        "client_id": (client_id or "").strip() or info["user_id"],
        "iss":       OAUTH_ISSUER,
        "iat":       now,
        "exp":       now + JWT_TTL_SECONDS,
        "scope":     "mcp",
    }
    token = _pyjwt.encode(claims, JWT_SECRET, algorithm=JWT_ALG)
    if isinstance(token, bytes):        # PyJWT <2 returned bytes
        token = token.decode("utf-8")
    return {
        "access_token": token,
        "token_type":   "Bearer",
        "expires_in":   JWT_TTL_SECONDS,
        "scope":        "mcp",
    }


def _resolve_jwt(token: str) -> Optional[dict]:
    """If `token` is a JWT this server signed, verify signature + expiry and
    return caller info; otherwise None (so the caller falls back to key
    lookup). A JWT is exactly three base64url segments, so anything without
    two dots can't be one — skip the decode attempt entirely for raw keys."""
    if not oauth_enabled() or token.count(".") != 2:
        return None
    try:
        claims = _pyjwt.decode(
            token, JWT_SECRET, algorithms=[JWT_ALG],
            options={"require": ["exp", "sub"], "verify_aud": False},
        )
    except Exception:
        # Bad signature / expired / malformed — not a token we honor. Fall back
        # to treating the string as a raw key (it won't match, but that path
        # owns the invalid-credential error message).
        return None
    uid = claims.get("sub")
    if not uid:
        return None
    # M8: a JWT is only as trustworthy as the key it was minted from. Re-check
    # that the underlying key has not been revoked since — otherwise a revoked
    # key's token would stay valid for its whole TTL. Fail-open on DB error to
    # match this module's availability-first posture (the shortened TTL bounds
    # that window); fail-closed on a definitive "key no longer live".
    if not _key_id_live(claims.get("key_id")):
        return None
    return {
        "user_id":            uid,
        "tier":               claims.get("tier") or "free",
        "key_id":             claims.get("key_id"),
        "plan":               (claims.get("plan") or "").strip().lower(),
        "stripe_customer_id": claims.get("cust"),
        "via":                "jwt",
    }


def _key_id_live(key_id: Optional[str]) -> bool:
    """True if forge_api_keys row `key_id` is still usable (active, or rotating
    within grace, and not past hard expiry). Mirrors validate_key's liveness
    rules but keyed on the id carried in a JWT. Fail-OPEN on DB unreachability
    (return True) so a momentary outage doesn't break paying clients; fail-CLOSED
    (return False) on a definitive revoked/expired/missing row."""
    if not key_id:
        return False
    client = _supabase()
    if client is None:
        return True  # can't check → don't break auth (TTL bounds exposure)
    try:
        r = (client.table("forge_api_keys")
             .select("id,status,rotation_grace_until,expires_at")
             .eq("id", key_id)
             .in_("status", ["active", "rotating"])
             .limit(1)
             .execute())
    except Exception as e:
        logger.warning(f"gating: _key_id_live failure: {type(e).__name__}: {e}")
        return True  # DB error → fail open
    rows = r.data or []
    if not rows:
        return False  # revoked / deleted / status no longer active|rotating
    row = rows[0]
    now = datetime.now(timezone.utc)
    exp = _parse_ts(row.get("expires_at"))
    if exp is not None and now > exp:
        return False
    if row.get("status") == "rotating":
        grace = _parse_ts(row.get("rotation_grace_until"))
        if grace is None or now > grace:
            return False
    return True


def resolve_bearer(token: str) -> Optional[dict]:
    """Accept BOTH auth methods on a `Authorization: Bearer …` header:
    an OAuth JWT (checked first — verify signature) OR a raw Forge API key
    (fallback). Returns {user_id, tier, …} or None. This is the single entry
    point the gating middleware uses so both paths gate identically."""
    token = (token or "").strip()
    if not token:
        return None
    via_jwt = _resolve_jwt(token)
    if via_jwt is not None:
        return via_jwt
    return validate_key(token)


# ── Rate-limit counter (atomic RPC) ──────────────────────────────────────────

def check_and_increment(user_id: str, tier: str) -> tuple[bool, int, int]:
    """Atomically check the monthly cap, then increment if under it.
    Returns (allowed, new_call_count, cap). Fails OPEN on Supabase errors
    so a momentary outage never breaks paying clients."""
    cap = PRO_CAP if tier == "pro" else FREE_CAP
    client = _supabase()
    if client is None:
        return (True, 0, cap)
    try:
        r = client.rpc("increment_mcp_usage", {
            "p_user_id": user_id,
            "p_month":   _current_month_utc(),
            "p_cap":     cap,
        }).execute()
    except Exception as e:
        logger.warning(f"gating: increment_mcp_usage RPC failed: {type(e).__name__}: {e}")
        return (True, 0, cap)
    rows = r.data or []
    if not rows:
        return (True, 0, cap)
    row = rows[0]
    return (bool(row.get("allowed")), int(row.get("call_count") or 0), int(row.get("cap") or cap))


# ── Error payloads (JSON-encoded into ToolError messages) ────────────────────

def _err(payload: dict) -> ToolError:
    return ToolError(json.dumps(payload))


def _err_no_auth() -> ToolError:
    return _err({
        "error":      "missing_api_key",
        "message":    f"Authorization: Bearer fnet_… required. Sign up free at {SIGNUP_URL}",
        "signup_url": SIGNUP_URL,
    })


def _err_invalid_key() -> ToolError:
    return _err({
        "error":      "invalid_api_key",
        "message":    f"API key not recognized or revoked. Mint a new key at {SIGNUP_URL}",
        "signup_url": SIGNUP_URL,
    })


def _err_unknown_tool(tool_name: str) -> ToolError:
    """A tool name that doesn't exist at all — NEVER route this to the paywall.
    A typo must read as 'unknown tool', not 'pay us'."""
    return _err({
        "error":   "unknown_tool",
        "message": (f"'{tool_name}' is not a Forge tool. Call tools/list to see "
                    f"the available tools."),
        "tool":    tool_name,
    })


def _err_tier(tool_name: str, tier: str) -> ToolError:
    msg = (
        f"{tool_name} requires Forge Runtime ($999/month). Try `fire_sandbox` "
        f"for free to see the full watch→fire→settle loop (10 lifetime fires per "
        f"key, no card), or upgrade for unlimited at {PRICING_URL}"
    )
    return _err({
        "error":         "tool_requires_upgrade",
        "message":       msg,
        "tool":          tool_name,
        "current_tier":  tier,
        "required_tier": "runtime",
        "free_demo":     "fire_sandbox",
        "upgrade_url":   PRICING_URL,
    })


def _err_sandbox_exhausted(count: int) -> ToolError:
    return _err({
        "error":        "sandbox_cap_reached",
        "message":      (f"fire_sandbox cap reached ({count}/{SANDBOX_FIRE_CAP} lifetime fires "
                         f"on this key). The full loop is unlimited on Pro — {PRICING_URL}"),
        "tool":         "fire_sandbox",
        "call_count":   count,
        "cap":          SANDBOX_FIRE_CAP,
        "upgrade_url":  PRICING_URL,
    })


def _err_rate(tier: str, count: int, cap: int) -> ToolError:
    return _err({
        "error":        "rate_limit_exceeded",
        "message":      (f"Monthly cap of {cap:,} tool calls reached on {tier} tier. "
                         f"Upgrade at {PRICING_URL}"),
        "current_tier": tier,
        "call_count":   count,
        "cap":          cap,
        "upgrade_url":  PRICING_URL,
    })


def _err_payment_required(tool_name: str, entitlement: str = "metered_unpaid") -> ToolError:
    """402 for a caller that may not call this tool, on either gated tier.

    Every tool list here is DERIVED from the frozensets the gate actually
    enforces. It used to be prose, and the prose was wrong: it told developers a
    sandbox key covers "normalize, predict, and fleet health" when `predict` and
    `fleet_health` are Pro-only — so the refusal that was supposed to unblock
    someone walked them straight into a second 402. `free_tools` was wrong in the
    other direction too: it always returned TRULY_FREE_TOOLS, understating a
    sandbox key's surface by fifteen tools.

    Both lists are now caller-accurate:
      * `free_tools`    — what THIS key can call right now
      * `sandbox_tools` — what a no-card forge_sandbox_ key covers

    If a tool moves between FREE_TOOLS and ALL_TOOLS, this message follows it.
    Nothing here is hand-maintained.
    """
    if entitlement == "free":
        # A sandbox key that reached for a Pro tool. It is not "unpaid" — it has
        # a real free surface; say what that surface is instead of implying none.
        callable_now = sorted(FREE_TOOLS)
        msg = (f"{tool_name} requires a paid plan. Your forge_sandbox_ key covers "
               f"{len(callable_now)} tools free (listed in free_tools), up to "
               f"{FREE_CAP} calls/month. Add a payment method at {PRICING_URL} "
               f"to enable {tool_name}.")
    else:
        # Metered (fnet_) key with no card: narrowed to the truly-free surface.
        callable_now = sorted(TRULY_FREE_TOOLS)
        msg = (f"{tool_name} is a paid tool and this metered (fnet_) key has no "
               f"payment method on file. Add one at {PRICING_URL} to enable it, or "
               f"evaluate with no card on a free forge_sandbox_ key, which covers "
               f"{len(FREE_TOOLS)} tools including normalize_telemetry "
               f"(listed in sandbox_tools) up to {FREE_CAP} calls/month.")
    return _err({
        "error":         "payment_method_required",
        "message":       msg,
        "tool":          tool_name,
        "free_tools":    callable_now,
        "sandbox_tools": sorted(FREE_TOOLS),
        "upgrade_url":   PRICING_URL,
    })


# ── Per-tool cost ledger (forge_api_usage) ───────────────────────────────────
# Canonical per-call USD price by MCP tool name. MUST stay in sync with
# forge-prod/api.py TOOL_COSTS. Free tools are 0.00 but STILL logged so a
# customer sees total call volume even on free tools. This ledger is VISIBILITY
# ONLY (read by GET /v1/usage/summary); it NEVER charges — Stripe metering on
# forge-prod (which honours the flat-plan exemption) is the sole charge path.
# ALIGNED TO forge-prod/static/pricing.html, 2026-07-27. Must stay identical to
# forge-prod/api.py TOOL_COSTS and to billing.METER_UNIT_CENTS/100.
TOOL_COSTS: dict[str, float] = {
    # ── Paid (must match the rate card to the cent) ──────────────────────────
    "normalize_telemetry": 0.01,
    "predict": 0.05,
    "predict_breach": 0.05,
    "remaining_life": 0.05,
    "verify_record": 0.05,
    "detect_anomalies": 0.02,
    "health_index": 0.25,
    "diagnose_machine": 0.25,
    "fleet_health": 0.50,
    "predict_batch": 0.50,
    "machine_intelligence": 1.00,
    # ── Free (logged at 0.00 so call volume stays visible) ───────────────────
    "identify_machine": 0.00,
    "get_coverage": 0.00,
    "correct_mapping": 0.00,
    "calculate_oee": 0.00,
    "fleet_oee": 0.00,
    "energy_consumption": 0.00,
    "shift_report": 0.00,
    "get_agent_card": 0.00,
    "list_agents": 0.00,
    "list_guardrails": 0.00,
    "check_guardrail": 0.00,
    "prediction_accuracy": 0.00,
    "create_automation": 0.00,
    "activate_automation": 0.00,
    "list_automations": 0.00,
    "query_machine_history": 0.00,
    "fire_sandbox": 0.00,
    # In ALL_TOOLS and callable, but previously missing from this ledger — so
    # their call volume never reached /v1/usage/summary. Free. Kept byte-identical
    # to forge-prod/api.py TOOL_COSTS.
    "delete_automation": 0.00,
    "disable_automation": 0.00,
    "restore_automation": 0.00,
    "query_webhook_history": 0.00,
}


def _insert_usage_row(key_id: str, tool_name: str, cost: float) -> None:
    """Synchronous single-row insert into forge_api_usage (runs off-thread).
    Uses the service-key client, so RLS (service_role-only) is satisfied."""
    client = _supabase()
    if client is None:
        return
    try:
        client.table("forge_api_usage").insert({
            "api_key_id": key_id,
            "tool_name":  tool_name,
            "cost_usd":   round(float(cost or 0.0), 4),
        }).execute()
    except Exception as e:
        logger.debug(f"gating: usage ledger insert skipped: {type(e).__name__}: {e}")


async def log_usage(key_id: Optional[str], tool_name: str, cost: float) -> None:
    """Fire-and-forget cost-ledger write for one tool call, keyed on the REAL
    caller's key_id (from resolve_bearer). Non-blocking and fully fail-open —
    supabase-py is sync so the insert runs in a worker thread; a ledger failure
    must never surface to the tool caller. VISIBILITY ONLY — does not charge."""
    if not key_id or not tool_name:
        return
    try:
        await asyncio.to_thread(_insert_usage_row, key_id, tool_name, float(cost or 0.0))
    except Exception as e:
        logger.debug(f"gating: log_usage skipped: {type(e).__name__}: {e}")


# ── The middleware itself ────────────────────────────────────────────────────

# ── Payment-method gate (shared source of truth with forge-prod: Stripe) ─────
# Mirrors forge-prod/api.py _customer_has_pm + _account_customer_id so a metered
# fnet_ key is metered IDENTICALLY on MCP and REST. Both checks fail OPEN (treat
# as entitled) on any error — a billing hiccup or an unset STRIPE_SECRET_KEY must
# never break a live client; it only leaves the gate permissive until configured.

_pm_cache: dict = {}
_PM_TTL_S = 300
_acct_cust_cache: dict = {}
_ACCT_CUST_TTL_S = 300


def _customer_has_pm(customer_id: Optional[str]) -> bool:
    """Whether a Stripe customer has a usable card. Cached 5 min. Fail-OPEN."""
    if not customer_id:
        return False
    now = time.time()
    hit = _pm_cache.get(customer_id)
    if hit and (now - hit[0]) < _PM_TTL_S:
        return hit[1]
    ok = True
    try:
        import stripe
        stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
        cust = stripe.Customer.retrieve(customer_id)
        inv = getattr(cust, "invoice_settings", None)
        dm = getattr(inv, "default_payment_method", None) if inv else None
        if dm:
            ok = True
        else:
            pms = stripe.PaymentMethod.list(customer=customer_id, type="card", limit=1)
            ok = bool(getattr(pms, "data", []))
    except Exception as e:
        logger.info(f"gating: PM check failed for {customer_id} ({type(e).__name__}) — fail-open")
        ok = True
    _pm_cache[customer_id] = (now, ok)
    return ok


def _account_customer_id(user_id: Optional[str]) -> Optional[str]:
    """Stripe customer_id for an ACCOUNT (forge_users), cached 5 min. Lets an
    forge_agent_ key — which inherits the parent plan but has no customer of its
    own — resolve the owning account's billing. Fail-soft to None."""
    if not user_id:
        return None
    now = time.time()
    hit = _acct_cust_cache.get(user_id)
    if hit and (now - hit[0]) < _ACCT_CUST_TTL_S:
        return hit[1]
    cust = None
    client = _supabase()
    if client is not None:
        try:
            row = (client.table("forge_users").select("stripe_customer_id")
                   .eq("id", user_id).limit(1).execute().data or [{}])[0]
            cust = row.get("stripe_customer_id")
        except Exception as e:
            logger.info(f"gating: account customer lookup failed for {user_id}: {type(e).__name__}")
    _acct_cust_cache[user_id] = (now, cust)
    return cust


def _entitlement(info: dict) -> str:
    """Collapse a caller's plan + card status into a gating decision:
      'pro'            — metered WITH a card, or a flat paid plan → all tools
      'metered_unpaid' — metered (fnet_) with NO card → only TRULY_FREE_TOOLS
      'free'           — sandbox / legacy free_tier → FREE_TOOLS on the free cap
    Keeps MCP metering identical to forge-prod's REST payment gate."""
    plan = (info.get("plan") or "").strip().lower()
    if plan == "metered":
        cust = info.get("stripe_customer_id") or _account_customer_id(info.get("user_id"))
        if cust and not _customer_has_pm(cust):
            return "metered_unpaid"
        return "pro"   # card on file, or customer unresolvable → fail-open
    # sandbox → free; production/monitoring/runtime → pro; legacy → info['tier'].
    return info.get("tier") or "free"


class GatingMiddleware(Middleware):
    """fastmcp middleware: gates every tool call by tier + monthly cap.

    on_call_tool runs once per `tools/call`. We pull headers via
    `get_http_headers()` (works for SSE because each client message is its
    own HTTP request that carries the Authorization header), validate the
    fnet_ key, then either allow the call or raise ToolError with the
    structured payload the client/LLM can parse.
    """

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        # Tool name lives on the inbound message; defensive defaults so a
        # malformed request still produces a clean structured error.
        tool_name = getattr(context.message, "name", None) or ""

        # IMPORTANT: get_http_headers() strips `authorization` by default
        # (it's in fastmcp's excluded-headers set, treated as "problematic for
        # proxy forwarding"). We need it as the gate's only input, so opt back
        # in via the `include` set.
        headers = get_http_headers(include={"authorization"}) or {}
        auth = (headers.get("authorization") or "").strip()
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""

        if not token:
            raise _err_no_auth()

        # Accept a raw Forge API key OR an OAuth client-credentials JWT. JWT is
        # verified first, then we fall back to direct key lookup — existing
        # `Bearer forge_prod_…` clients are unaffected.
        info = resolve_bearer(token)
        if info is None:
            raise _err_invalid_key()

        # Resolve entitlement from plan + card status so a metered fnet_ key is
        # metered on MCP exactly as on REST (Finding 3: no free ride via MCP).
        ent = _entitlement(info)

        # Existence BEFORE paywall: a tool name we don't know is a typo / bad
        # call, not a paid feature. Telling a developer to "upgrade" for a tool
        # that doesn't exist is both wrong and infuriating.
        if tool_name not in ALL_TOOLS:
            raise _err_unknown_tool(tool_name)

        # Metered (fnet_) account with no card on file: only the truly-free
        # tools work; every paid tool returns payment_required, identical to the
        # REST 402. Free evaluation with no card is the forge_sandbox_ tier.
        if ent == "metered_unpaid":
            if tool_name not in TRULY_FREE_TOOLS:
                raise _err_payment_required(tool_name, ent)
            tier = "free"
        else:
            # SANDBOX (free tier) is restricted to FREE_TOOLS. This mirrors the
            # REST 402 gate: a cardless sandbox key gets the free surface plus
            # normalize (its trial allowance) and nothing else.
            #
            # This branch previously allowed a sandbox key to call ANY tool, on
            # the stated assumption that "sandbox is not tool-restricted on REST".
            # That assumption held until the REST paywall gate was added — after
            # which MCP became a trivial bypass: the same sandbox key that gets
            # 402 on POST /v1/machine_intelligence still got a full $1.00 answer
            # by asking for it over MCP. Verified live before this fix.
            #
            # Paid accounts with no card were already narrowed to
            # TRULY_FREE_TOOLS above; 'pro' keys are unrestricted.
            if ent == "free" and tool_name not in FREE_TOOLS:
                raise _err_payment_required(tool_name, ent)
            tier = ent  # 'pro' (paid/flat, PRO_CAP) or 'free' (sandbox, FREE_CAP)

        # fire_sandbox runs against a separate lifetime counter (not the
        # monthly one) so a Free key can demo the full loop without burning
        # its month's allowance, and so the sandbox endpoint can't be
        # held open by a single key forever.
        if tool_name == "fire_sandbox":
            client = _supabase()
            if client is not None:
                try:
                    r = client.rpc("increment_mcp_usage", {
                        "p_user_id": info["user_id"],
                        "p_month":   SANDBOX_MONTH_KEY,
                        "p_cap":     SANDBOX_FIRE_CAP,
                    }).execute()
                    rows = r.data or []
                    if rows:
                        row = rows[0]
                        if not bool(row.get("allowed")):
                            raise _err_sandbox_exhausted(int(row.get("call_count") or 0))
                except ToolError:
                    raise
                except Exception as e:
                    logger.warning(f"gating: sandbox counter failed: {type(e).__name__}: {e}")
                    # Fail OPEN — same posture as the monthly counter.
        else:
            ok, count, cap = check_and_increment(info["user_id"], tier)
            if not ok:
                raise _err_rate(tier, count, cap)

        # Stash tier so tools could surface it via meta if useful later.
        try:
            ctx = getattr(context, "fastmcp_context", None)
            if ctx is not None:
                # Best-effort: keep the key off the request for any downstream
                # tool that wants to log the caller without re-validating.
                ctx.state = getattr(ctx, "state", {}) or {}
                ctx.state.update({
                    "mcp_tier":       tier,
                    "mcp_user_id":    info["user_id"],
                    "mcp_call_count": count,
                    "mcp_cap":        cap,
                })
        except Exception:
            pass

        result = await call_next(context)

        # Per-tool cost ledger (visibility only; never charges). Logged AFTER a
        # successful call, keyed on the REAL caller's key_id — fixes the
        # shared-key attribution gap (upstream proxy calls run under the server's
        # FOUNDRYNET_API_KEY). Free tools log at 0.00 so call volume is visible.
        # Fire-and-forget: a ledger failure must never affect the tool response.
        try:
            asyncio.create_task(
                log_usage(info.get("key_id"), tool_name, TOOL_COSTS.get(tool_name, 0.0)))
        except Exception:
            pass

        return result
