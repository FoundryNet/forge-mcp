"""FoundryNet MCP Server — 30 tools wrapping the live Forge v1 API,
gated per-client by fnet_ tier (Free vs Pro) as of 2026-05-28.

Connects any AI agent to industrial equipment over the Model Context
Protocol so any compatible agent (Claude Desktop, Cursor, etc.) can:
  - identify a machine and provision its persistent identity
  - normalize raw OEM telemetry into canonical FCS data
  - query the machine's operational history
  - set up natural-language automations against canonical fields
  - record verifiable attestations of completed work

Per-call gating (see gating.py): every tools/call must carry
`Authorization: Bearer fnet_…` on the wire. The middleware validates the
key against Supabase, looks up the tier (free → 12 read-only + demo tools,
100 calls/mo; pro → all 27 tools, 10000 calls/mo), and atomically increments
a monthly counter. Tier or rate-limit violations surface as structured
JSON ToolError payloads with `upgrade_url: forge.foundrynet.io/pricing`.

Upstream calls from each tool still use the shared FOUNDRYNET_API_KEY
configured on this service (Bearer fnet_… key created via /v1/keys on
the Forge service); per-user pass-through is a future deliverable.

Transport: dual. Streamable HTTP at /mcp (modern clients + Smithery's hosted
gateway, which 405s on legacy SSE) AND legacy SSE at /sse (+ /messages) so
existing mcp-remote configs published since May keep working. New users get /mcp.

Health check: GET /health (returns config presence without leaking the key).

Required env:
  FOUNDRYNET_API_KEY    fnet_… key for the Forge user this server represents.

Optional env:
  FORGE_BASE_URL        Default https://forge.foundrynet.io
  PORT                  Default 8080 (Railway sets this automatically)
  REQUEST_TIMEOUT       HTTP read timeout in seconds, default 120 (TimesFM inference is slow)
"""
from __future__ import annotations

import asyncio
import base64
import logging
import os
from typing import Optional

import httpx
from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("foundrynet.mcp")

FORGE_BASE_URL     = (os.environ.get("FORGE_BASE_URL") or "https://forge.foundrynet.io").rstrip("/")
FOUNDRYNET_API_KEY = os.environ.get("FOUNDRYNET_API_KEY", "")
REQUEST_TIMEOUT    = int(os.environ.get("REQUEST_TIMEOUT", "120"))
# predict / predict_breach / remaining_life run TimesFM inference and legitimately
# take 30-37s (batch more). A 30s read timeout killed exactly the most valuable
# tools, so read/write/pool get the full REQUEST_TIMEOUT while connect stays short
# (10s) so a genuinely dead upstream can't hang the proxy indefinitely.
HTTP_TIMEOUT       = httpx.Timeout(REQUEST_TIMEOUT, connect=10.0)
PORT               = int(os.environ.get("PORT", "8080"))

if not FOUNDRYNET_API_KEY:
    logger.warning(
        "FOUNDRYNET_API_KEY is not set — every tool call will return a 401. "
        "Set it via the Railway dashboard before traffic hits this server."
    )

mcp = FastMCP("foundrynet")

# Per-client tier gating. Free keys see 7 tools (read-only + fire_sandbox +
# correct_mapping + get_coverage, 100/mo); Pro keys see all 14 (10 000/mo).
# Errors are ToolError-wrapped structured JSON payloads carrying
# upgrade_url/signup_url. See gating.py.
from gating import (  # noqa: E402 — needs mcp instantiated first
    GatingMiddleware, issue_access_token, oauth_enabled,
    OAUTH_ISSUER, JWT_TTL_SECONDS, FREE_TOOLS, resolve_bearer,
)
mcp.add_middleware(GatingMiddleware())


# ── HTTP plumbing ────────────────────────────────────────────────────────────

def _headers() -> dict:
    return {
        "Authorization": f"Bearer {FOUNDRYNET_API_KEY}",
        "Content-Type":  "application/json",
        "User-Agent":    "FoundryNet-MCP/1.0",
    }


def _shape_error(status: int, body_text: str) -> dict:
    """Forge returns either a structured {detail: …} payload or HTML on
    edge errors. Normalize both into a single shape the LLM can read."""
    try:
        import json as _json
        return {"error": f"forge_{status}", "detail": _json.loads(body_text)}
    except Exception:
        return {"error": f"forge_{status}", "detail": body_text[:500]}


RETRY_DELAY_SECONDS = 2
RETRYABLE_EXCEPTIONS = (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError)


async def _call_forge(method: str, path: str, *,
                      body: Optional[dict] = None,
                      params: Optional[dict] = None) -> dict:
    """One HTTP call to Forge with one retry on transient transport errors.

    Always returns a dict (never raises) so the LLM gets a structured
    error in the tool result rather than an MCP-protocol exception. The
    -32602 transient failures observed in early Claude Desktop sessions
    came from upstream restarts during deploys; a single 2-second retry
    handles them without masking persistent issues.

    Retry policy: ConnectError / ReadTimeout / RemoteProtocolError → wait
    2s and try once more. Anything else (4xx/5xx HTTP, JSON decode
    failures, programmer errors) returns immediately with the error
    shape the LLM can read."""
    url = f"{FORGE_BASE_URL}{path}"
    last_exc: Optional[BaseException] = None
    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
                r = await client.request(method, url, headers=_headers(),
                                         json=body if body is not None else None,
                                         params=params)
        except RETRYABLE_EXCEPTIONS as e:
            last_exc = e
            if attempt == 0:
                logger.info(f"_call_forge transient {type(e).__name__} on {method} {path}, retrying in {RETRY_DELAY_SECONDS}s")
                await asyncio.sleep(RETRY_DELAY_SECONDS)
                continue
            return {"error": "network",
                    "detail": f"{type(e).__name__}: {e}",
                    "attempts": 2}
        except httpx.HTTPError as e:
            # Non-retryable transport class — return immediately.
            return {"error": "network", "detail": f"{type(e).__name__}: {e}"}

        if r.status_code >= 400:
            return _shape_error(r.status_code, r.text)
        try:
            return r.json()
        except Exception as e:
            return {"error": "non_json_response",
                    "detail": f"{type(e).__name__}: {e}",
                    "raw":    r.text[:500]}

    # Unreachable, but type-checks: returned inside the loop on every path.
    return {"error": "unreachable", "detail": str(last_exc)}


# Back-compat alias — old name `_request` was used in earlier file revisions.
# Keep both bindings so anything in flight or in transit still works.
_request = _call_forge


# ── Tool 1: identify_machine ─────────────────────────────────────────────────

@mcp.tool
async def identify_machine(
    oem: str,
    model: str,
    serial: str,
    site: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> dict:
    """Provision or retrieve a persistent identity (mint_id) for any
    industrial machine. Works for CNC machines, industrial robots, PLCs,
    additive manufacturing cells, injection molders, presses, turbines,
    pumps, compressors, conveyors — any equipment from any OEM:
    Fanuc, Siemens, Haas, DMG Mori, Mazak, Okuma, Hurco, Doosan, Makino,
    ABB, KUKA, Universal Robots, Yaskawa, Stäubli, FANUC Robotics,
    Komatsu, Caterpillar, John Deere, Trumpf, Bystronic, Amada, EMAG,
    Bosch Rexroth, Beckhoff, Rockwell Allen-Bradley.

    Returns the mint_id (universal handle, format "MINT-xxxxxx"). Idempotent
    — calling again with the same (oem, model, serial) returns the same
    mint_id with `created: false`.

    USE WHEN: a user references a specific machine by OEM/model/serial and
    you need a stable handle to attach normalized data, automations, or
    attestations to. Always call this first when a new machine is
    introduced to the conversation, before normalize_telemetry or
    create_automation.
    """
    body: dict = {"oem": oem, "model": model, "serial": serial}
    if site is not None:     body["site"] = site
    if metadata is not None: body["metadata"] = metadata
    return await _call_forge("POST", "/v1/identify", body=body)


# ── Tool 2: normalize_telemetry ──────────────────────────────────────────────

@mcp.tool
async def normalize_telemetry(
    data: dict,
    machine_id: Optional[str] = None,
    oem: Optional[str] = None,
    model: Optional[str] = None,
    serial: Optional[str] = None,
    site: Optional[str] = None,
) -> dict:
    """Give your agent a semantic understanding of machine data from any OEM:
    translate raw vendor telemetry into one universal canonical schema (FCS,
    FoundryNet Canonical Schema) so the agent can reason across vendors it has
    never seen before.
    Maps vendor-specific column names like "Spindle_Speed", "servo_load_x",
    "CoolantTemp", "FeedRateOverride" into standard fields like
    spindle_speed_rpm, axes.x_load_pct, sensor_readings.coolant_temp,
    feed_override_pct.

    Accepts a `data` dict of {raw_field: value}. If `machine_id` (mint_id
    or internal_id) is omitted but oem+model+serial are provided, silently
    auto-provisions the machine identity (same effect as calling
    identify_machine first).

    Each call:
      - Returns canonical_data + a per-field mapping_id (use mapping_id
        with /v1/feedback/{mapping_id}/correct if a mapping is wrong)
      - Writes a row to forge_normalized_history (visible via
        query_machine_history)
      - Evaluates active triggers; the response includes a `triggers_fired`
        array if any condition matched. The actual webhooks fire async, so
        the array tells you what was triggered without blocking on remote
        latency.

    USE WHEN: you have raw machine data — a CSV row, a sensor reading, an
    MES export, an alarm log line — and need to either (a) understand it
    semantically using canonical field names, (b) feed an automation that
    watches canonical fields, or (c) build up history for the machine.
    """
    body: dict = {"data": data}
    if machine_id is not None: body["machine_id"] = machine_id
    if oem is not None:        body["oem"] = oem
    if model is not None:      body["model"] = model
    if serial is not None:     body["serial"] = serial
    if site is not None:       body["site"] = site
    return await _call_forge("POST", "/v1/normalize", body=body)


# ── Tool 3: query_machine_history ────────────────────────────────────────────

@mcp.tool
async def query_machine_history(
    mint_id: str,
    from_dt: Optional[str] = None,
    to_dt: Optional[str] = None,
    fields: Optional[str] = None,
    limit: int = 100,
    summary: bool = False,
) -> dict:
    """Retrieve operational history for an identified machine. Each row is
    one /v1/normalize call's canonical output (FCS field → value).

    Query options:
      from_dt, to_dt   ISO-8601 timestamps to bound the time range
      fields           comma-separated FCS field names to project; omit for
                       full canonical_data
      limit            max rows (1–1000, default 100)
      summary          true → returns aggregate stats only (row_count,
                       time range, avg coverage_pct, fields_covered set)
                       without the raw rows. Always cheap.

    USE WHEN: your agent needs to reason over how a machine has been running,
    surface utilization or throughput or health trends, find patterns in
    alarms or operational state, compare periods ("how was today vs
    yesterday"), or discover what data is even available for a machine. Prefer
    `summary=true` first to orient on volume + which fields are present,
    then drill in with field projection on a smaller time window.
    """
    params: dict = {"limit": limit, "summary": str(summary).lower()}
    if from_dt is not None: params["from"] = from_dt
    if to_dt is not None:   params["to"]   = to_dt
    if fields is not None:  params["fields"] = fields
    return await _call_forge("GET", f"/v1/history/{mint_id}", params=params)


# ── Tool 4: create_automation ────────────────────────────────────────────────

@mcp.tool
async def create_automation(
    mint_id: str,
    instruction: str,
) -> dict:
    """Let your agent wire machine telemetry to any business system in plain
    English — ERP, CMMS, MES, Slack, Teams, email, Zapier, n8n — via webhooks
    already registered as tools on the Forge service. The agent describes the
    condition and the action; Forge parses it into a structured trigger.

    Examples of `instruction`:
      "Alert maintenance Slack when spindle load exceeds 90 percent."
      "Create a Fiix work order when coolant temperature stays above 35°C
       for five minutes."
      "Notify the supervisor when part_count hits 500."
      "When the maintenance_type changes to CORRECTIVE, post to the ops
       channel."

    Returns a `parsed_trigger` JSON for HUMAN review — DOES NOT
    auto-activate. The caller (you, with user confirmation) must
    explicitly POST the parsed_trigger to /v1/triggers on the Forge API
    to actually create it. The response includes
    `confirmation_required: true` and may include `notes` if the parser
    had to make a fuzzy match (e.g. resolved an ambiguous field name to
    its closest canonical match).

    USE WHEN: a user wants to set up monitoring, alerts, or automations
    for machine state transitions. Always show the parsed_trigger to the
    user verbatim and ask "Confirm to activate?" before they activate it.
    """
    # The MCP tool exposes `mint_id` as the parameter name (consistent with
    # the rest of the v1 surface), but /v1/triggers/natural's body schema
    # uses `machine_id` (which accepts mint_id OR internal_id) — map here.
    return await _call_forge(
        "POST", "/v1/triggers/natural",
        body={"machine_id": mint_id, "instruction": instruction},
    )


# ── Tool 5: activate_automation ──────────────────────────────────────────────

@mcp.tool
async def activate_automation(
    machine_id: str,
    name: str,
    condition: dict,
    actions: list,
    enabled: bool = True,
) -> dict:
    """Activate a parsed automation trigger on a machine. Call this AFTER
    create_automation returns a parsed_trigger and the user explicitly
    confirms they want to arm it.

    Creates a live trigger that monitors the machine's normalized telemetry
    and fires the listed actions when the condition matches. Each action
    references a registered tool by tool_id; on fire, the tool's webhook
    is POSTed with {{variable}} interpolation against the canonical data
    context (mint_id, oem, model, serial, site, field, value, threshold,
    plus every canonical field on the matched record).

    Inputs:
      machine_id  mint_id ("MINT-…") or internal_id; resolved to canonical mint_id
      name        short human label, ≤ 80 chars (e.g. "high spindle load")
      condition   simple {field, op, value|threshold} OR compound {all: [...]}
                  ops: >, <, >=, <=, ==, !=
      actions     list of {tool_id, payload_overrides?, headers_overrides?}
      enabled     defaults to true; pass false to create the trigger paused

    Returns the persisted trigger row including `id` (use it later to
    pause/edit/delete via the Forge API). Once active, the trigger fires
    on every subsequent normalize_telemetry call where the condition
    matches — no further activation needed.

    USE WHEN: the user has reviewed the parsed_trigger from
    create_automation and said something like "yes, activate it" /
    "go ahead" / "arm it." Never call this tool without explicit
    confirmation — it changes machine behavior in a way the user can
    feel (real Slack messages, real ERP work orders).
    """
    return await _call_forge(
        "POST", "/v1/triggers",
        body={
            "machine_id": machine_id,
            "name":       name,
            "condition":  condition,
            "actions":    actions,
            "enabled":    enabled,
        },
    )


# ── Tool 6: list_automations ─────────────────────────────────────────────────

@mcp.tool
async def list_automations(machine_id: str) -> dict:
    """List all active automations / triggers configured for one machine.

    Returns each trigger with: id, name, condition (field/op/value or
    compound `all`), actions (each resolved to its tool name + url +
    method), enabled state, fire_count, last_fired_at, last_error.

    USE WHEN: the user asks "what automations do I have on this machine"
    / "show me my triggers" / "what alerts am I getting" / "what's
    monitoring this machine right now". Always pass the machine's
    mint_id (or internal_id — both resolve)."""
    return await _call_forge("GET", "/v1/triggers", params={"machine_id": machine_id})


# ── Tool 7: disable_automation ───────────────────────────────────────────────

@mcp.tool
async def disable_automation(trigger_id: str) -> dict:
    """Pause an automation trigger without deleting it. The trigger stops
    evaluating against incoming /v1/normalize calls but its configuration
    (condition, actions, history) is preserved. Re-enable later by
    PATCHing /v1/triggers/{id} with `{"enabled": true}` (or by asking
    the user to confirm and creating a follow-up tool for resume).

    USE WHEN: the user wants to TEMPORARILY stop an automation — e.g.
    "pause the high-spindle alert during planned maintenance," "stop
    that alarm for now, I'll re-enable it tomorrow." Distinct from
    delete_automation, which is permanent."""
    return await _call_forge("PATCH", f"/v1/triggers/{trigger_id}",
                             body={"enabled": False})


# ── Tool 8: delete_automation ────────────────────────────────────────────────

@mcp.tool
async def delete_automation(trigger_id: str) -> dict:
    """Soft-deletes the trigger (recoverable for 30 days via
    restore_automation). The trigger immediately stops evaluating against
    /v1/normalize calls and is hidden from list_automations, but the row
    persists with deleted_at set so an accidental delete can be undone.
    Use restore_automation to undo. For permanent deletion, the API
    supports ?permanent=true.

    Past forge_trigger_executions rows for this trigger remain in either
    case (audit trail).

    USE WHEN: the user wants to remove an automation they no longer need —
    "delete the coolant alert," "remove that trigger." Safer than hard
    delete because misclicks are recoverable; tell the user about
    restore_automation if they later change their mind."""
    return await _call_forge("DELETE", f"/v1/triggers/{trigger_id}")


# ── Tool 9: query_webhook_history ────────────────────────────────────────────

@mcp.tool
async def query_webhook_history(trigger_id: str, limit: int = 10) -> dict:
    """Show webhook delivery history for a trigger — HTTP status codes,
    response times, retry counts, errors. Use to verify webhooks are
    actually delivering.

    Returns up to `limit` most-recent execution rows (default 10, max 200),
    each with: fired_at, http_status, attempt_count, response_time_ms,
    error (if any), tool_name, target_url, and the settlement reference
    (settled_tx) once the row has been rolled up via batch settle.

    USE WHEN: a user asks "did the alert actually go out?" / "why didn't
    Slack get pinged?" / "is the trigger working?" / "show me the last
    few fires." Soft-deleted triggers can still be queried — useful for
    forensic audits after a misclick + restore."""
    return await _call_forge("GET", f"/v1/triggers/{trigger_id}/executions",
                             params={"limit": limit})


# ── Tool 10: restore_automation ──────────────────────────────────────────────

@mcp.tool
async def restore_automation(trigger_id: str) -> dict:
    """Restore a previously soft-deleted automation trigger within its 30-day
    recovery window. Re-enables the trigger so it evaluates against
    incoming /v1/normalize calls again.

    Returns the restored trigger row plus `restored: true` and the
    `restored_at` timestamp. 410 (Gone) if the trigger was deleted more
    than 30 days ago and is past the restorable window. 409 if the
    trigger isn't actually deleted.

    USE WHEN: a user accidentally deleted a trigger and wants it back.
    Also useful as the "undo" half of a "delete then change my mind"
    flow — pair with disable_automation when the user wants to pause
    rather than delete in the first place."""
    return await _call_forge("PATCH", f"/v1/triggers/{trigger_id}/restore")


# ── Tool 11: verify_record (backward-compat alias: verify_on_chain) ──────────

@mcp.tool
async def verify_record(
    mint_id: Optional[str] = None,
    payload: Optional[dict] = None,
    batch: bool = False,
) -> dict:
    """Create a tamper-evident, independently verifiable record of work. The
    record is hash-chained; the hash can be anchored on an external ledger when
    configured. Two modes:

    BATCH MODE (`batch=true`, requires `mint_id`):
      Collects every unsettled event for that machine — normalize calls,
      trigger fires, webhook executions — since the last batch. Computes
      a Merkle root of their event hashes and anchors that single root as
      one verifiable settlement. ONE settlement proves dozens to thousands
      of events. Returns: merkle_root, event_count, event_types breakdown,
      tx_signature, verify_url. Cost-efficient — call this
      once an hour or once a shift per machine, not per event.

    SINGLE-PAYLOAD MODE (`batch=false`, requires `payload`):
      Hashes an arbitrary JSON `payload` deterministically (sorted keys,
      no whitespace) and anchors the hash. Returns: payload_hash,
      tx_signature, verify_url. Use for one-off proofs — inspection
      records, completed work orders, signed reports — where you want a
      permanent independent timestamp.

    USE WHEN: a user wants tamper-proof evidence — settlement of a
    completed work batch, proof a maintenance window happened, anchoring
    a quality report, rolling up a day's machine activity into a single
    verifiable hash. ALWAYS include the `verify_url` in your reply so the
    user can independently verify the record.
    """
    if batch:
        if not mint_id:
            return {"error": "bad_request",
                    "detail": "batch=true requires mint_id"}
        return await _call_forge("POST", "/v1/settle",
                              body={"mint_id": mint_id},
                              params={"batch": "true"})
    if payload is None:
        return {"error": "bad_request",
                "detail": "batch=false requires `payload` (any JSON object)"}
    return await _call_forge("POST", "/v1/settle", body=payload)


# Retired MCP tool (2026-07-10): no longer decorated with @mcp.tool, so it is
# absent from tools/list and cannot be called over the wire — brings the raw
# decorator count to 27, matching the public tools_count. Kept as a plain
# internal function only so any in-process reference still routes to
# verify_record. All new callers must use verify_record.
async def verify_on_chain(
    mint_id: Optional[str] = None,
    payload: Optional[dict] = None,
    batch: bool = False,
) -> dict:
    """Retired alias for verify_record (no longer exposed as an MCP tool)."""
    return await verify_record(mint_id=mint_id, payload=payload, batch=batch)


# ── Tool 12: fire_sandbox — FREE-tier demo of the full action loop ────────
# Gating: FREE in gating.FREE_TOOLS, capped at 10 lifetime fires per fnet_
# key via gating.SANDBOX_FIRE_CAP. Demonstrates the watch→fire→settle loop
# end-to-end without any real machine onboarding or paid tier — the
# developer types a condition + a target message, the MCP server POSTs to
# its own /sandbox/echo endpoint (so there's a real HTTP round-trip with a
# real response body), hashes the result, and records a verifiable
# attestation of that hash. Returns the echo response, the tx_signature, and
# a verify_url so the dev can see the attestation receipt themselves.

@mcp.tool
async def fire_sandbox(
    condition_text: str,
    message: str = "Spindle load crossed 85%. Sandbox demo fire.",
) -> dict:
    """Demo the full Forge watch→fire→settle loop against a built-in sandbox
    endpoint. Free tier; no machine onboarding required.

    The MCP server POSTs `{message, condition: condition_text, ts}` to its
    own /sandbox/echo route — a real HTTP round-trip with a real response
    body — then hashes the response and records a verifiable attestation of
    it. Returns the echo body, the tx_signature, and a verify_url.

    USE WHEN: a developer is evaluating Forge and wants to feel the full
    loop (a webhook actually fires, a real settlement actually records, the
    verification link actually resolves) without onboarding any machines or
    paying for the Pro tier. 10 fires lifetime per fnet_ key.

    Args:
        condition_text: A plain-English description of the condition the
            sandbox is simulating, e.g. "Spindle load crossed 85%".
        message: The payload text the sandbox webhook receives. Defaults
            to a representative example.
    """
    import hashlib, json as _json
    import datetime as _dt
    sandbox_url = "https://mcp.foundrynet.io/sandbox/echo"
    payload = {
        "condition": condition_text,
        "message":   message,
        "ts":        _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }
    # Build the payload deterministically so the hash is reproducible.
    payload_json = _json.dumps(payload, sort_keys=True, separators=(",", ":"))

    # 1) Fire the sandbox webhook — real HTTP, real response.
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            wr = await client.post(sandbox_url, content=payload_json,
                                   headers={"Content-Type": "application/json"})
        echo_status = wr.status_code
        echo_body = wr.text
    except Exception as e:
        return {"error": "sandbox_webhook_failed",
                "detail": f"{type(e).__name__}: {e}"}

    # 2) Hash the action+inputs+outputs deterministically.
    canonical = _json.dumps(
        {"action": "sandbox_fire", "inputs": payload,
         "outputs": {"status": echo_status, "body": echo_body[:500]}},
        sort_keys=True, separators=(",", ":"),
    )
    payload_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # 3) Settle via /v1/settle (single-payload mode).
    settle = await _call_forge("POST", "/v1/settle",
                               body={"payload_hash": payload_hash,
                                     "action": "sandbox_fire"})
    return {
        "sandbox_echo": {"status": echo_status, "body_preview": echo_body[:240]},
        "payload_hash": payload_hash,
        "tx_signature": settle.get("tx_signature"),
        "verify_url":   settle.get("verify_url"),
        "note": (
            "Demo loop verified — the verify_url is a real attestation anchor. "
            "Lifetime cap 10/key. Upgrade for unlimited + real-machine "
            "automations at https://forge.foundrynet.io/pricing"
        ),
    }


# ── Tool 13: correct_mapping ─────────────────────────────────────────────────

def _feedback_mapping_id(source_field: str, oem_hint: Optional[str]) -> str:
    """Replicate forge-prod `_mapping_id` so a correction can be filed even when
    the caller didn't retain the mapping_id from normalize_telemetry. Must stay
    byte-identical to api.py:_mapping_id (sha256 of 'field|oem', lowered)."""
    import hashlib
    key = f"{(source_field or '').strip().lower()}|{(oem_hint or '').strip().lower()}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


@mcp.tool
async def correct_mapping(
    source_field: str,
    confirmed_canonical: str,
    original_canonical: str,
    oem: Optional[str] = None,
    mapping_id: Optional[str] = None,
    sample_value: Optional[str] = None,
    confidence: Optional[float] = None,
) -> dict:
    """Teach Forge the RIGHT canonical field for a source column that
    normalize_telemetry mapped wrong (or abstained on). Each correction is
    recorded as a corpus-improvement signal the retrainer uses to fix the
    mapping for everyone — so every agent interaction makes normalization better.

    USE WHEN: you or the user can see normalize_telemetry returned the wrong
    canonical for a field (e.g. it mapped an oil-pressure column to a tire-
    pressure field), or it abstained on a field whose meaning you know.

    - source_field: the raw column name exactly as it appeared in your data.
    - confirmed_canonical: the canonical field it SHOULD map to.
    - original_canonical: what normalize_telemetry actually returned (pass the
      `canonical` from that field's entry; use "abstained" if it abstained).
    - oem: the OEM you passed to normalize_telemetry (improves aggregation).
    - mapping_id: optional — the `mapping_id` from the normalize_telemetry field
      entry. If omitted it is derived deterministically from (source_field, oem).

    Returns {ok, feedback_id, action:"correct"}. Corrections feed an offline
    retrain (they don't hot-patch the live corpus), so noisy feedback can't
    poison other users' mappings.
    """
    mid = mapping_id or _feedback_mapping_id(source_field, oem)
    body: dict = {
        "source_field":        source_field,
        "original_canonical":  original_canonical or "abstained",
        "confirmed_canonical": confirmed_canonical,
    }
    if oem is not None:          body["oem_hint"] = oem
    if sample_value is not None: body["sample_value"] = sample_value
    if confidence is not None:   body["confidence"] = confidence
    return await _call_forge("POST", f"/v1/feedback/{mid}/correct", body=body)


# ── Tool 14: get_coverage ────────────────────────────────────────────────────

@mcp.tool
async def get_coverage(oem: Optional[str] = None) -> dict:
    """Ask Forge what it can normalize BEFORE you try: the recognized OEM
    verticals (CNC / robot / vehicle / AMR), the canonical-field families, and
    the field list per family. Optionally pass an `oem` to see which vertical it
    resolves to and whether the cross-vertical gate will engage.

    USE WHEN: starting a new integration, or deciding whether to call
    normalize_telemetry — confirm the machine's OEM and your fields are in
    coverage. Unknown OEMs still normalize (the gate just disables itself), so
    absence here is a soft signal, not a hard block.
    """
    params = {"oem": oem} if oem else None
    return await _call_forge("GET", "/v1/coverage", params=params)


# ── Tool 15: predict ─────────────────────────────────────────────────────────

@mcp.tool
async def predict(
    time_series: list[float],
    canonical_field: Optional[str] = None,
    horizon: int = 24,
    frequency: Optional[int] = None,
) -> dict:
    """Forecast the next `horizon` readings of a canonical telemetry series using
    TimesFM (Google's time-series foundation model). Returns a point forecast
    plus quantile uncertainty bands (q0.1 … q0.9) — no per-machine training
    required. The kernel already normalizes raw OEM telemetry into canonical FCS
    fields; this predicts where a field is headed next.

    Args:
      time_series      historical canonical values, oldest→newest (≥16 recommended)
      canonical_field  the FCS field the series represents (e.g. "spindle_load_pct"),
                       carried through for labeling/provenance
      horizon          number of steps to predict (1–256, default 24)
      frequency        accepted for forward-compat; TimesFM 2.5 auto-detects cadence

    USE WHEN: a user wants to know where a metric is trending — "what will spindle
    load look like over the next 2 hours", "project coolant temperature", "forecast
    throughput". For threshold/failure questions use predict_breach or
    remaining_life instead. PREMIUM (Pro tier) — runs ML inference (~$0.05/call
    once metered billing is active).
    """
    body: dict = {"time_series": time_series, "horizon": horizon}
    if canonical_field is not None: body["canonical_field"] = canonical_field
    if frequency is not None:       body["frequency"] = frequency
    return await _call_forge("POST", "/v1/predict", body=body)


# ── Tool 16: predict_breach ──────────────────────────────────────────────────

@mcp.tool
async def predict_breach(
    time_series: list[float],
    threshold: float,
    canonical_field: Optional[str] = None,
    direction: str = "above",
    horizon: int = 96,
    mint_id: Optional[str] = None,
    settle: bool = False,
) -> dict:
    """Predict whether — and when — a canonical series will cross a threshold.
    This is the parametric-insurance primitive: it answers "will this machine's
    <field> exceed <threshold> within the forecast window, and how soon?".

    Returns will_breach, estimated_steps_to_breach, a confidence, and a
    quantile-derived breach_window {earliest, latest}. Every result carries a
    deterministic data_hash so the prediction is cryptographically provable. Pass
    a caller-owned `mint_id` to write an audit event tying the prediction to a
    specific machine; add `settle=true` to anchor it as a verifiable settlement
    for an insurance-grade, tamper-evident record.

    Args:
      time_series      historical canonical values, oldest→newest (≥16 recommended)
      threshold        the value to test for a crossing (e.g. 95.0 for 95% load)
      canonical_field  FCS field the series represents (e.g. "spindle_load_pct")
      direction        "above" (default) or "below" — which side is the breach
      horizon          steps to look ahead (1–256, default 96)
      mint_id          caller-owned machine to anchor provenance to (optional)
      settle           if true and mint_id is owned, record a verifiable settlement (costs a fee)

    USE WHEN: a user asks if/when a limit will be hit — "will spindle load breach
    95% this shift", "is coolant temp going to exceed 35°C", "alert me before
    pressure drops below 2 bar". PREMIUM (Pro tier), ~$0.05/call.
    """
    body: dict = {"time_series": time_series, "threshold": threshold,
                  "direction": direction, "horizon": horizon, "settle": settle}
    if canonical_field is not None: body["canonical_field"] = canonical_field
    if mint_id is not None:         body["mint_id"] = mint_id
    return await _call_forge("POST", "/v1/predict_breach", body=body)


# ── Tool 17: remaining_life ──────────────────────────────────────────────────

@mcp.tool
async def remaining_life(
    time_series: list[float],
    failure_threshold: float,
    canonical_field: Optional[str] = None,
    direction: str = "above",
    horizon: int = 96,
    mint_id: Optional[str] = None,
    settle: bool = False,
) -> dict:
    """Estimate a machine's remaining useful life before a failure threshold is
    crossed, with a maintenance recommendation. A maintenance-planning reframing
    of predict_breach: same TimesFM forecast, expressed as time-to-failure.

    Returns remaining_steps (None if no failure forecast), remaining_useful_life_pct
    (headroom to the threshold), failure_predicted, failure_window, a trend, and a
    recommendation — one of immediate_maintenance / schedule_maintenance / monitor
    / healthy. Same provenance + optional verifiable settlement as predict_breach.

    Args:
      time_series        historical canonical values, oldest→newest (≥16 recommended)
      failure_threshold  the value whose crossing constitutes failure
      canonical_field    FCS field the series represents (e.g. "bearing_vibration_mm_s")
      direction          "above" (default) or "below" — failure side
      horizon            steps to look ahead (1–256, default 96)
      mint_id / settle   optional provenance / verifiable settlement (see predict_breach)

    USE WHEN: a user asks about maintenance timing or equipment health runway —
    "how long until this bearing needs service", "remaining life on the spindle",
    "should I schedule maintenance now". PREMIUM (Pro tier), ~$0.05/call.
    """
    body: dict = {"time_series": time_series, "failure_threshold": failure_threshold,
                  "direction": direction, "horizon": horizon, "settle": settle}
    if canonical_field is not None: body["canonical_field"] = canonical_field
    if mint_id is not None:         body["mint_id"] = mint_id
    return await _call_forge("POST", "/v1/remaining_life", body=body)


# ── Tool 18: predict_batch ───────────────────────────────────────────────────

@mcp.tool
async def predict_batch(machines: list[dict]) -> dict:
    """Predict for an entire FLEET in one call instead of one request per machine.
    A 200-machine factory shouldn't make 200 round-trips — pass them all here and
    get back a scored fleet overview plus per-machine predictions.

    Args:
      machines  list (≤100) of objects, each:
                  { id, canonical_field?, values:[...], threshold?, direction? }
                Supply a `threshold` to get a breach prediction for that machine;
                omit it to get a plain forecast. Per-machine validation errors are
                returned inline — one bad machine never fails the whole batch.

    Returns a fleet_summary (total/analyzed/at_risk, fleet_health_score 0–100,
    fleet_risk_level, a top-5 priority_maintenance queue) and the per-machine
    results, plus an attestation hash over the fleet summary.

    USE WHEN: a user wants fleet-wide foresight — "score all my CNCs", "which
    machines are about to breach", "rank my fleet by maintenance urgency".
    PREMIUM (Pro tier) — $0.02 per machine in the batch.
    """
    return await _call_forge("POST", "/v1/predict_batch", body={"machines": machines})


# ── Tool 19: fleet_health ────────────────────────────────────────────────────

@mcp.tool
async def fleet_health(machines: list[dict]) -> dict:
    """Roll a fleet of machine predictions up into a single health dashboard: a
    fleet health score, a critical/elevated/moderate/healthy risk distribution,
    per-canonical-field risk rollups, and a maintenance priority queue with a
    plain-English recommendation.

    Args:
      machines  same shape as predict_batch — list (≤100) of
                { id, canonical_field?, values:[...], threshold?, direction? }.
                Machines with a `threshold` are bucketed by steps-to-breach
                (critical <6, elevated <24, moderate otherwise); the rest count
                as healthy.

    USE WHEN: your agent needs to concentrate on where fleet risk is — "how
    healthy is my fleet", "give me the maintenance queue", "where's my risk
    concentrated". For raw per-machine numbers use predict_batch. PREMIUM (Pro
    tier) — $0.50 per fleet assessment.
    """
    return await _call_forge("POST", "/v1/fleet_health", body={"machines": machines})


# ── Tool 20: detect_anomalies ────────────────────────────────────────────────

@mcp.tool
async def detect_anomalies(
    values: list[float],
    canonical_field: Optional[str] = None,
    sensitivity: float = 2.0,
) -> dict:
    """Flag anomalies in a time series WITHOUT running a full forecast — z-score +
    IQR outlier detection plus trend and rate-of-change (accelerating/steady/
    decelerating). No TimesFM inference, so it's faster and cheaper than predict
    and works on short series (≥4 points). Cross-references the canonical field's
    known/derived normal range when one is available.

    Args:
      values           the series to scan (≥4 points)
      canonical_field  FCS field the series represents (enables normal-range context)
      sensitivity      z-score threshold (default 2.0 ≈ 95%); higher = fewer flags

    Returns anomaly_count, per-anomaly detail (index, value, z_score, deviation,
    severity: critical/warning/minor), summary statistics, and an attestation hash.

    USE WHEN: real-time monitoring or a spot check — "is this reading abnormal",
    "any outliers in the last hour", "flag spikes in vibration". For 'where is it
    headed' use predict; for 'will it cross X' use predict_breach. PREMIUM (Pro
    tier) — $0.02/call (no ML inference).
    """
    body: dict = {"values": values, "sensitivity": sensitivity}
    if canonical_field is not None:
        body["canonical_field"] = canonical_field
    return await _call_forge("POST", "/v1/anomaly", body=body)


# ── Tool 21: machine_intelligence ────────────────────────────────────────────

@mcp.tool
async def machine_intelligence(
    machine_id: str,
    telemetry: dict,
    oem: Optional[str] = None,
    thresholds: Optional[dict] = None,
) -> dict:
    """Complete machine intelligence from raw telemetry in ONE call: normalize the
    field names (when `oem` is given), detect anomalies on every field, forecast
    and predict threshold breaches where there's enough history, compute an overall
    health score + letter grade (A–F), and assemble a maintenance queue — all
    attested. This is the full stack: normalize → anomaly → forecast → breach
    → score → recommend, behind a single endpoint and a single payment.

    Args:
      machine_id  identifier for the machine being analyzed
      telemetry   { field_name: [values], ... } — one series per field
      oem         OEM hint (e.g. "Fanuc", "Siemens") — enables field-name
                  normalization to canonical FCS fields; omit to treat field
                  names as already canonical
      thresholds  optional { field_or_canonical: threshold } — any field with a
                  threshold also gets a breach prediction that feeds the health
                  score and maintenance queue

    Returns per-field analysis (canonical_field, anomalies, frequency, forecast,
    breach_prediction), an overall_health_score (0–100) + health_grade, an
    anomaly_summary, a sorted maintenance_queue, and an attestation hash.

    USE WHEN: a user hands you a machine's raw telemetry and wants everything —
    "analyze this machine", "full health report", "what's wrong and what's coming".
    PREMIUM (Pro tier) — $0.25/call (premium full-stack analysis).
    """
    body: dict = {"machine_id": machine_id, "telemetry": telemetry}
    if oem is not None:        body["oem"] = oem
    if thresholds is not None: body["thresholds"] = thresholds
    return await _call_forge("POST", "/v1/machine_intelligence", body=body)


# ── Tool 22: prediction_accuracy ─────────────────────────────────────────────

@mcp.tool
async def prediction_accuracy() -> dict:
    """Report how well the kernel's predictions have matched reality: total and
    evaluated prediction counts, breach-prediction accuracy %, forecast mean
    absolute error, and accuracy broken down by canonical field.

    FREE — this is a trust signal. Check it BEFORE deciding to pay for a
    prediction: "87% breach accuracy across 500 predictions" is the best evidence
    that the paid forecast is worth buying. Accuracy improves over time as more
    predictions are tracked and verified against actuals (each is logged with a
    tamper-evident hash).

    USE WHEN: a user (or you, on their behalf) wants to gauge how much to trust the
    forecasts before spending on predict / predict_breach / machine_intelligence.
    """
    return await _call_forge("GET", "/v1/prediction_accuracy")


# ── Operations capabilities: OEE, energy, shift reports, diagnostics ─────────
# These proxy the REST capabilities that already run on forge-prod
# (capabilities.py). They are the stickiest daily-operations surface, so they
# belong on the MCP gateway too, not just REST.

@mcp.tool
async def calculate_oee(machine_id: str, period: str = "shift") -> dict:
    """Overall Equipment Effectiveness (OEE = Availability × Performance ×
    Quality) for one machine over a period, computed from telemetry the kernel
    already collects. Returns the three-factor breakdown, a letter grade, and an
    honest `available:false` with a reason when there isn't enough data.

    Args:
      machine_id  the machine's id (e.g. "DEMO-FANUC-01")
      period      "shift" (default), "day", or "week"

    USE WHEN: your agent needs to report how a machine is performing, locate
    where the losses are, or produce a single number for a line. FREE — OEE is
    the metric that embeds Forge in daily operations.
    """
    return await _call_forge("GET", f"/v1/oee/{machine_id}", params={"period": period})


@mcp.tool
async def fleet_oee(period: str = "shift") -> dict:
    """Fleet-wide OEE: per-machine cards plus a fleet-average OEE, worst
    performers surfaced first.

    Args:
      period  "shift" (default), "day", or "week"

    USE WHEN: your agent needs to assess the whole floor in one call and
    surface the worst performers ("how is the plant running this shift?"). FREE.
    """
    return await _call_forge("GET", "/v1/oee/fleet", params={"period": period})


@mcp.tool
async def energy_consumption(machine_id: str, period: str = "shift") -> dict:
    """Energy consumption and cost for a machine over a period, derived from the
    cumulative energy_kwh counter, with baseline comparison and anomaly
    detection when a baseline exists.

    Args:
      machine_id  the machine's id
      period      "shift" (default), "day", or "week"

    USE WHEN: your agent needs to compute what a machine costs to run, or catch
    an energy anomaly (a spike vs the rolling baseline).
    """
    return await _call_forge("GET", f"/v1/energy/{machine_id}", params={"period": period})


@mcp.tool
async def shift_report(which: str = "current") -> dict:
    """A shift handover report across the fleet: OEE, energy, alerts, and actions
    per machine, plus an AI-generated narrative summary. Auto-generated at each
    shift change, no spreadsheet required.

    Args:
      which  "current" (so-far this shift, default), "last" (the most recent
             completed shift), or "recent" (the last few reports)

    USE WHEN: your agent needs to generate a shift handover across the fleet,
    or a written summary of what happened, without a spreadsheet. FREE.
    """
    path = {"current": "/v1/reports/shift/current",
            "last":    "/v1/reports/shift/last",
            "recent":  "/v1/reports/shift/recent"}.get(which, "/v1/reports/shift/current")
    return await _call_forge("GET", path)


@mcp.tool
async def diagnose_machine(
    machine_id: str,
    event_time: Optional[str] = None,
    symptom: Optional[str] = None,
) -> dict:
    """Automated root-cause analysis for a machine event: correlates the
    telemetry around the event (3σ anomaly detection + timeline) and reasons over
    it to name the most likely cause, the evidence, and a recommended action.

    Args:
      machine_id  the machine's id
      event_time  ISO 8601 timestamp of the event (defaults to now)
      symptom     what was observed, e.g. "machine stopped" or "vibration spike"

    USE WHEN: something went wrong and your agent needs a first-pass root cause
    to reason from. PREMIUM ($0.25/call) — runs LLM reasoning over the telemetry.
    """
    body: dict = {}
    if event_time is not None: body["event_time"] = event_time
    if symptom is not None:    body["symptom"] = symptom
    return await _call_forge("POST", f"/v1/diagnose/{machine_id}", body=body)


# ── Tool 28 (meta): get_agent_card ───────────────────────────────────────────
# NOT counted in the headline "27 MCP tools" — it's a meta/credentials tool.

@mcp.tool
async def get_agent_card(agent_id: Optional[str] = None) -> dict:
    """Retrieve an agent's identity card — capabilities, trust scores, governance
    constraints, and verified work history. Trust scores are COMPUTED from the
    kernel's attested history, not self-reported, so they can't be inflated.

    USE WHEN your agent needs to present its credentials to a facility operator,
    or to evaluate another agent's qualifications before coordinating work.

    Args:
      agent_id  the connected agent's id. Omit to get the built-in Forge
                Intelligence card (the kernel's own credentials + NASA benchmark).
    """
    return await _call_forge("GET", f"/v1/agents/{agent_id or 'builtin'}/card")


@mcp.tool
async def list_agents(capability: Optional[str] = None,
                      min_trust_score: Optional[float] = None,
                      machine_id: Optional[str] = None) -> dict:
    """Discover other agents connected to this kernel — their capabilities, trust
    scores, and machine access. Trust is COMPUTED from attested history, not
    self-reported, so it can't be gamed.

    USE WHEN your agent needs to find another agent with a specific capability to
    coordinate with or delegate work to — e.g. a monitoring agent that detected a
    bearing fault finding a maintenance agent qualified to fix it. Compare the
    returned cards (trust, jobs, first-fix rate) before selecting one.

    Args:
      capability       keyword filter on capabilities (e.g. "bearing",
                       "vibration", "maintenance"). Substring match.
      min_trust_score  only return agents at/above this trust score (0.0-1.0).
      machine_id       only return agents that have accessed this machine.
    """
    params: dict = {}
    if capability:
        params["capability"] = capability
    if min_trust_score is not None:
        params["min_trust_score"] = min_trust_score
    if machine_id:
        params["machine_id"] = machine_id
    return await _call_forge("GET", "/v1/agents/discover", params=params)


# ── Tool 29: health_index ────────────────────────────────────────────────────

@mcp.tool
async def health_index(machine_id: str, period: str = "shift") -> dict:
    """Compute a composite health index (0-1) for a machine by fusing ALL
    available sensor readings against a healthy baseline. USE WHEN your agent
    needs to assess overall machine health from multiple sensors simultaneously —
    especially for detecting gradual degradation that no single sensor threshold
    would catch (the failure mode univariate predict_breach misses).

    Returns the current health score (1.0 = healthy, 0.0 = failed), trend
    (declining / stable / improving), degradation rate, estimated remaining
    useful life in steps, and the top factors driving the decline.
    """
    return await _call_forge("GET", f"/v1/health_index/{machine_id}")


# ── Health route (mounted on the SSE app via FastMCP custom_route) ──────────

@mcp.custom_route("/sandbox/echo", methods=["POST"])
async def sandbox_echo(request: Request) -> JSONResponse:
    """Sandbox webhook target for fire_sandbox tool. Returns the received
    JSON body back with a 200 + an `echoed_at` timestamp. Open / unauthed —
    only the fire_sandbox tool calls it during normal flow, but no creds are
    exposed even if it's hit directly."""
    import datetime as _dt
    try:
        body = await request.json()
    except Exception:
        body = {"raw": (await request.body()).decode("utf-8", errors="replace")[:500]}
    return JSONResponse({
        "ok":         True,
        "echoed_at":  _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "received":   body,
    })


@mcp.custom_route("/health", methods=["GET"])
async def health(request: Request) -> JSONResponse:
    """Health check for Railway + load balancers. Reports config presence
    without ever leaking the API key value."""
    return JSONResponse({
        "status":             "ok",
        "service":            "foundrynet-mcp",
        # Registry-derived; the single source of truth other surfaces read from.
        "tools_count":        len(await mcp.list_tools()),
        "forge_base_url":     FORGE_BASE_URL,
        "key_configured":     bool(FOUNDRYNET_API_KEY),
        "transport":          "streamable-http",
        "gating":             "per_client_fnet_2tier",
        "supabase_configured": bool(os.environ.get("SUPABASE_URL")
                                    and os.environ.get("SUPABASE_SERVICE_KEY")),
        "pricing_url":        os.environ.get("MCP_PRICING_URL", "https://forge.foundrynet.io/pricing"),
    })


@mcp.custom_route("/ping", methods=["GET"])
async def ping(request: Request) -> JSONResponse:
    """Liveness for hosted runtimes that probe /ping (mcp-proxy etc.)."""
    return JSONResponse({"status": "ok"})


# ── /.well-known/mcp* — public discovery endpoints ──────────────────────────
# Auth-free metadata that MCP crawlers / hubs (glama.ai, smithery, mcp.so,
# pulsemcp, awesome-mcp-servers) pull to enumerate this server without a
# registry round-trip. Payload schema follows the de-facto well-known/mcp
# layout used across those directories. Schema rebased 2026-05-28 to the
# canonical spec — adds schema_version, tagline, auth{}, pricing{}, docs_url,
# logo_url; renames `url`+`transport`{} → `server_url`+`transport`. Cache
# allowed at the edge (5 min) since payload only changes on a redeploy.
# Static payload — never reads env or DB, so it can't leak secrets.

@mcp.custom_route("/.well-known/mcp/server-card.json", methods=["GET"])
async def server_card(request: Request) -> JSONResponse:
    """Full MCP server card — the per-server metadata directories consume.

    Schema rebased 2026-05-28 to camelCase per the emerging well-known/mcp
    convention: `version` (was `schema_version`), `serverUrl` (was
    `server_url`). Added full `tools[]` array — directories like glama,
    smithery, and pulsemcp surface per-tool descriptions on the listing
    page when this is present. One-liners only; the verbose docstrings live
    in each tool's `@mcp.tool` decorator and are returned via tools/list."""
    # Derive the count from the live registry so it can never drift from the
    # actual set of @mcp.tool-decorated tools returned by tools/list.
    _tc = len(await mcp.list_tools())
    return JSONResponse(
        {
            "version":   "1.0",
            "name":      "FoundryNet Forge",
            "tagline":   "Plain English in. Autonomous action out.",
            "description": (
                "Watch any signal across 18 OEM families — Fanuc, Siemens, "
                "Haas, DMG Mori, Mazak, Okuma, Doosan, Makino, ABB, KUKA, "
                "Universal Robots, Yaskawa, Stäubli, Trumpf, Bystronic, "
                "Bosch Rexroth — backed by 18,785+ canonical field mappings. "
                "When a condition matches, Forge fires the webhook or alert "
                "you wired (Slack, Teams, PagerDuty, your MES, your own "
                "endpoint) and records a tamper-evident attestation of the "
                "action. The agent watches; you stay in the loop."
            ),
            # Smithery (and MCP-canonical) — lets the publish skip its scan.
            "serverInfo": {"name": "Forge by Foundry Labs", "version": "3.4.4"},
            "serverUrl": "https://mcp.foundrynet.io/mcp",
            "transport": "streamable-http",
            "auth": {
                "type":       "api_key",
                "header":     "Authorization",
                "prefix":     "Bearer",
                "signup_url": "https://forge.foundrynet.io/",
            },
            # Ready-to-paste install snippets so directory crawlers and
            # first-run users get the auth header correctly. Without the
            # `--header Authorization:Bearer …` line, mcp-remote opens the
            # SSE stream unauthed and every tool call comes back missing_api_key.
            "installations": {
                "claude_desktop": (
                    '{\n'
                    '  "mcpServers": {\n'
                    '    "foundrynet-forge": {\n'
                    '      "command": "npx",\n'
                    '      "args": ["-y", "mcp-remote",\n'
                    '               "https://mcp.foundrynet.io/mcp",\n'
                    '               "--header", "Authorization:Bearer ${FNET_KEY}"],\n'
                    '      "env": { "FNET_KEY": "fnet_…  (free key at forge.foundrynet.io/)" }\n'
                    '    }\n'
                    '  }\n'
                    '}'
                ),
                "cursor": (
                    '{\n'
                    '  "mcpServers": {\n'
                    '    "foundrynet-forge": {\n'
                    '      "command": "npx",\n'
                    '      "args": ["-y", "mcp-remote",\n'
                    '               "https://mcp.foundrynet.io/mcp",\n'
                    '               "--header", "Authorization:Bearer ${FNET_KEY}"],\n'
                    '      "env": { "FNET_KEY": "fnet_…" }\n'
                    '    }\n'
                    '  }\n'
                    '}'
                ),
                "claude_code": (
                    "claude mcp add foundrynet-forge -- "
                    "npx -y mcp-remote "
                    "https://mcp.foundrynet.io/mcp "
                    "--header \"Authorization:Bearer ${FNET_KEY}\""
                ),
            },
            "tools_count": _tc,
            "tools": [
                {"name": "identify_machine",
                 "description": "Provision a stable machine identity (mint_id) for an OEM/model/serial machine. Idempotent."},
                {"name": "normalize_telemetry",
                 "description": "Give an agent semantic understanding of machine data from any OEM: translate raw vendor telemetry into canonical FCS fields across 18 OEM families and 18,000+ field mappings."},
                {"name": "query_machine_history",
                 "description": "Read normalized operational history for a machine with field projection, time-range filters, and summary mode."},
                {"name": "create_automation",
                 "description": "Parse a plain-English instruction into a structured trigger — preview only, requires explicit activation."},
                {"name": "activate_automation",
                 "description": "Activate a parsed trigger so it fires its registered actions when the condition matches canonical telemetry."},
                {"name": "list_automations",
                 "description": "List the active trigger automations configured for a machine, with their conditions and actions."},
                {"name": "disable_automation",
                 "description": "Pause an active trigger without deleting it; configuration and history are preserved."},
                {"name": "delete_automation",
                 "description": "Soft-delete a trigger with a 30-day restore window; past execution rows remain for audit."},
                {"name": "restore_automation",
                 "description": "Restore a soft-deleted trigger inside its 30-day recovery window."},
                {"name": "query_webhook_history",
                 "description": "Webhook delivery history for a trigger — HTTP status, retries, response times, and attestation signatures."},
                {"name": "verify_record",
                 "description": "Create a tamper-evident, independently verifiable record of work (hash-chained; optionally anchored). Returns a record hash and a verify URL."},
                {"name": "fire_sandbox",
                 "description": "FREE-tier demo: fires a sample condition at the built-in /sandbox/echo endpoint, captures the response, and records a tamper-evident attestation. Demonstrates the full watch→fire→settle loop end-to-end. Lifetime cap: 10 fires per fnet_ key — no credit card required."},
                {"name": "correct_mapping",
                 "description": "FREE: teach Forge the right canonical field when normalize_telemetry mapped a column wrong or abstained. Each correction is a corpus-improvement signal feeding an offline retrain."},
                {"name": "get_coverage",
                 "description": "FREE: schema introspection — recognized OEM verticals (CNC/robot/vehicle/AMR) and canonical-field families, so an agent can check coverage before calling normalize_telemetry."},
                {"name": "predict",
                 "description": "PREMIUM: forecast the next N readings of a canonical telemetry series via TimesFM — point forecast plus quantile uncertainty bands, no per-machine training."},
                {"name": "predict_breach",
                 "description": "PREMIUM: the parametric-insurance primitive — predict whether/when a canonical series crosses a threshold, with a quantile breach window and a provable data_hash (optionally attested)."},
                {"name": "remaining_life",
                 "description": "PREMIUM: estimate remaining useful life before a failure threshold, with a maintenance recommendation (immediate/schedule/monitor/healthy) and the same attestation provenance as predict_breach."},
                {"name": "predict_batch",
                 "description": "PREMIUM: fleet-scale prediction — score up to 100 machines in one call, returning a fleet health score, at-risk count, and a top-5 maintenance priority queue. $0.02/machine."},
                {"name": "fleet_health",
                 "description": "PREMIUM: fleet health dashboard — a critical/elevated/moderate/healthy risk distribution, per-field risk rollups, and a maintenance queue with a plain-English recommendation. $0.50/assessment."},
                {"name": "detect_anomalies",
                 "description": "PREMIUM: statistical anomaly detection (z-score + IQR + trend/acceleration) with no ML inference — fast, cheap, real-time monitoring on series as short as 4 points. $0.02/call."},
                {"name": "machine_intelligence",
                 "description": "PREMIUM: the full stack in one call — normalize field names, detect anomalies, forecast, predict breaches, score health (A–F grade), and build a maintenance queue, all attested. $0.25/call."},
                {"name": "prediction_accuracy",
                 "description": "FREE: trust signal — reports tracked prediction accuracy (breach accuracy %, forecast MAE, per-field breakdown) so an agent can gauge forecast quality before paying."},
                {"name": "calculate_oee",
                 "description": "FREE: Overall Equipment Effectiveness (Availability × Performance × Quality) for one machine over a shift/day/week, with a letter grade and honest availability when data is thin."},
                {"name": "fleet_oee",
                 "description": "FREE: fleet-wide OEE — per-machine cards plus a fleet-average, worst performers first. One call for the whole floor."},
                {"name": "energy_consumption",
                 "description": "FREE: energy consumption and cost per machine from the cumulative energy counter, with baseline comparison and anomaly detection."},
                {"name": "shift_report",
                 "description": "FREE: shift handover report across the fleet — OEE, energy, alerts, and actions per machine plus an AI-generated narrative summary (current/last/recent)."},
                {"name": "diagnose_machine",
                 "description": "PREMIUM: automated root-cause analysis — correlates telemetry around an event (3σ anomaly + timeline) and reasons over it to name the likely cause, evidence, and recommended action. $0.25/call."},
                {"name": "health_index",
                 "description": "Composite multi-sensor health index (0-1) for a machine with trend and per-field contributors — surfaces slow degradation a single-threshold check misses."},
                {"name": "get_agent_card",
                 "description": "Return the calling agent's identity card: usage-derived trust scores, query/action counts, and attestation summary. Meta/credentials tool."},
                {"name": "list_agents",
                 "description": "Discover other agents connected to this kernel, filtered by capability, minimum trust score, and machine access. For agent-to-agent coordination and work delegation."},
            ],
            "categories": [
                "industrial", "manufacturing", "iot",
                "automation", "attestation",
            ],
            # Pay-per-use metered billing (Stripe Meter Events — wired in
            # billing.py). No flat monthly tier; the bill is whatever you
            # actually consume. Calculator examples below are for a single
            # machine at the named sample cadence; usage scales linearly with
            # machine count and inversely with sample interval.
            "pricing": {
                "model":     "metered",
                "free_tier": "100 tool calls/month, read-only tools — no card",
                "paid_from": "Pay-per-use — see examples",
                "examples": [
                    {"scenario": "1 CNC sampled every 30 seconds", "estimate_usd_per_month": 13},
                    {"scenario": "1 CNC sampled every 10 seconds", "estimate_usd_per_month": 40},
                    {"scenario": "1 CNC sampled every 1 second",   "estimate_usd_per_month": 260},
                ],
                "pricing_url": "https://forge.foundrynet.io/pricing",
            },
            "docs_url": "https://foundrynet.io/docs",
            "logo_url": "https://foundrynet.io/logo.png",
        },
        headers={"Cache-Control": "public, max-age=300"},
    )


@mcp.custom_route("/.well-known/mcp", methods=["GET"])
async def mcp_endpoints(request: Request) -> JSONResponse:
    """Discovery list — the entry point a crawler dereferences first to
    enumerate which MCP servers this origin exposes (we expose one)."""
    return JSONResponse(
        {
            "endpoints": [{
                "url":       "https://mcp.foundrynet.io/mcp",
                "transport": "streamable-http",
                "name":      "FoundryNet Forge MCP",
            }],
        },
        headers={"Cache-Control": "public, max-age=300"},
    )



@mcp.custom_route("/.well-known/mcp.json", methods=["GET"])
async def wellknown_mcp_json(request: Request) -> JSONResponse:
    """Flat machine-discovery card (emerging standard) for AI clients/crawlers.
    Advertises both auth schemes (raw Bearer key + OAuth client-credentials) and
    links the OAuth metadata so AgentCore/Foundry can auto-configure. tools_count
    and free_tools derive from the live registry / gating source of truth so the
    card can never drift from what the server actually enforces."""
    endpoint = "https://mcp.foundrynet.io/mcp"
    return JSONResponse({
        "name": "Forge by Foundry Labs",
        "short_name": "foundrynet-forge",
        "description": ("Industrial AI infrastructure. MCP tools for cross-OEM "
                        "equipment normalization, prediction, and governance. "
                        "18 OEM families, 189 canonical fields."),
        "version": "3.4.4",
        "url": endpoint,
        "endpoint": endpoint,
        "transport": ["streamable-http"],
        "auth": {
            "schemes": ["bearer", "oauth2-client-credentials"],
            "oauth_metadata": "/.well-known/oauth-authorization-server",
        },
        "tools_count": len(await mcp.list_tools()),
        "free_tools": sorted(FREE_TOOLS),
        "pricing": {"model": "per-query", "free_tier": True},
        "pricing_url": "https://forge.foundrynet.io/pricing",
        "docs_url": "https://forge.foundrynet.io/docs",
        "attestation": {"enabled": True, "protocol": "attestation"},
        "network": {"name": "FoundryNet Data Network", "servers": 17,
                    "homepage": "https://foundrynet.io"},
        "provider": {"name": "Foundry Labs", "url": "https://foundrynet.io"},
    }, headers={"Cache-Control": "public, max-age=300"})


@mcp.custom_route("/.well-known/agent-card.json", methods=["GET"])
async def wellknown_agent_card(request: Request) -> JSONResponse:
    """A2A agent card — how other agents discover Forge's identity + tools."""
    return JSONResponse({
        "name": "Forge by Foundry Labs",
        "description": ("Cross-OEM industrial telemetry normalization, runtime kernel, "
                        "and machine identity for industrial equipment. 18 OEM families, "
                        "189 canonical fields."),
        "url": "https://mcp.foundrynet.io/mcp",
        "version": "3.4.4",
        "capabilities": {"tools": ["normalize", "identify", "query_corpus",
                                   "coverage", "health_check"]},
        "provider": {"name": "Foundry Labs", "url": "https://foundrynet.io"},
        "network": "FoundryNet Data Network",
        "attestation": {"protocol": "attestation",
                        "verified_outputs": True},
        "protocols": {"mcp": {"endpoint": "https://mcp.foundrynet.io/mcp",
                              "transport": "streamable-http"}},
        "contact": "forge@foundrynet.io",
    }, headers={"Cache-Control": "public, max-age=300"})


# ── A2A (Google Agent-to-Agent) ─────────────────────────────────────────────
# Native A2A so any A2A-compatible framework can discover and call Forge:
#   GET  /.well-known/agent.json  — the spec's canonical discovery path (our
#                                   existing /.well-known/agent-card.json stays)
#   POST /a2a/tasks               — receive a task, map skill_id -> kernel call
#   GET  /a2a/agents              — discover agents on this kernel, A2A-shaped
# NOTE: custom routes bypass GatingMiddleware (it only gates MCP tools/call), so
# these enforce auth explicitly via resolve_bearer. CAVEAT: _call_forge runs as
# the server's own FOUNDRYNET_API_KEY, so premium skills execute under the
# server identity and are NOT metered per-caller here — wire per-tier gating
# before promoting the premium A2A skills heavily. (Tracked as a follow-up.)

# skill_id -> (kernel method, path builder, body/params builder from A2A params)
def _a2a_auth(request: "Request") -> Optional[dict]:
    """Return the caller's identity dict (resolve_bearer) or None if the
    Authorization: Bearer <forge key | oauth JWT> is missing/invalid."""
    authz = request.headers.get("authorization", "") or ""
    token = authz[7:].strip() if authz[:7].lower() == "bearer " else ""
    return resolve_bearer(token) if token else None


async def _a2a_dispatch(skill_id: str, params: dict) -> Optional[dict]:
    """Map an A2A skill_id to the same kernel call its MCP tool makes.
    Returns None for an unknown skill."""
    params = params or {}
    if skill_id == "normalize_telemetry":
        body: dict = {"data": params.get("data", {})}
        for k in ("machine_id", "oem", "model", "serial", "site"):
            if params.get(k) is not None:
                body[k] = params[k]
        return await _call_forge("POST", "/v1/normalize", body=body)
    if skill_id == "predict_failure":
        body = {"time_series": params.get("time_series", []),
                "threshold": params.get("threshold"),
                "direction": params.get("direction", "above"),
                "horizon": params.get("horizon", 96),
                "settle": bool(params.get("settle", False))}
        if params.get("canonical_field") is not None:
            body["canonical_field"] = params["canonical_field"]
        if params.get("mint_id") is not None:
            body["mint_id"] = params["mint_id"]
        return await _call_forge("POST", "/v1/predict_breach", body=body)
    if skill_id == "fleet_intelligence":
        return await _call_forge("POST", "/v1/fleet_health",
                                 body={"machines": params.get("machines", [])})
    if skill_id == "diagnose":
        mid = params.get("machine_id")
        if not mid:
            return {"error": "machine_id is required for the diagnose skill"}
        body = {}
        for k in ("event_time", "symptom"):
            if params.get(k) is not None:
                body[k] = params[k]
        return await _call_forge("POST", f"/v1/diagnose/{mid}", body=body)
    if skill_id == "agent_trust":
        qp: dict = {}
        for k in ("capability", "min_trust_score", "machine_id"):
            if params.get(k) is not None:
                qp[k] = params[k]
        return await _call_forge("GET", "/v1/agents/discover", params=qp)
    return None


@mcp.custom_route("/.well-known/agent.json", methods=["GET"])
async def wellknown_a2a_agent_json(request: "Request") -> JSONResponse:
    """A2A Agent Card at the spec's canonical path. Public (discovery)."""
    return JSONResponse({
        "name": "Forge by Foundry Labs",
        "description": ("Industrial AI infrastructure. Connects AI agents to industrial "
                        "equipment through 14 protocols. Cross-OEM normalization, "
                        "physics-validated readings, health index, failure prediction, "
                        "and agent trust scoring."),
        "url": "https://mcp.foundrynet.io",
        "version": "3.4.4",
        "capabilities": {"streaming": True, "pushNotifications": False,
                         "stateTransitionHistory": True},
        "skills": [
            {"id": "normalize_telemetry", "name": "Normalize Equipment Telemetry",
             "description": ("Translate raw machine data from any OEM into a universal "
                             "schema. 14 protocols, 18 manufacturers."),
             "tags": ["industrial", "iot", "normalization", "manufacturing"],
             "examples": ["Normalize Fanuc CNC spindle data",
                          "Translate Siemens PLC readings to universal schema",
                          "Map unknown equipment tags automatically"]},
            {"id": "predict_failure", "name": "Predict Equipment Failure",
             "description": ("Forecast when a machine component will breach a critical "
                             "threshold. TimesFM-powered."),
             "tags": ["prediction", "maintenance", "reliability"],
             "examples": ["Predict bearing failure from vibration trend",
                          "Estimate remaining useful life",
                          "Forecast temperature breach timeline"]},
            {"id": "fleet_intelligence", "name": "Fleet Health Intelligence",
             "description": ("Cross-vendor fleet monitoring with health index, OEE, "
                             "energy tracking, and trend-first ranking."),
             "tags": ["fleet", "monitoring", "oee", "health"],
             "examples": ["Get health status across all machines",
                          "Compare OEE across vendors", "Identify declining equipment"]},
            {"id": "diagnose", "name": "Root Cause Diagnosis",
             "description": ("AI-powered diagnosis of equipment issues in plain English "
                             "with recommended actions."),
             "tags": ["diagnosis", "root-cause", "maintenance"],
             "examples": ["Diagnose why vibration is increasing",
                          "Identify cause of temperature spike",
                          "Explain bearing degradation pattern"]},
            {"id": "agent_trust", "name": "Agent Trust Scoring",
             "description": ("Verified trust scores for connected agents computed from "
                             "attested operational data. Discover agents by capability "
                             "and trust threshold."),
             "tags": ["trust", "identity", "governance", "a2a"],
             "examples": ["Find maintenance agents with >0.85 trust",
                          "Get trust score breakdown for an agent",
                          "Compare agent performance on this equipment"]},
        ],
        "authentication": {
            "schemes": ["bearer", "oauth2"],
            "oauth2": {"tokenUrl": "https://mcp.foundrynet.io/oauth/token",
                       "grantTypes": ["client_credentials"],
                       "discoveryUrl": "https://mcp.foundrynet.io/.well-known/oauth-authorization-server"}},
        "protocols": {
            "mcp": {"endpoint": "https://mcp.foundrynet.io/mcp",
                    "transport": "streamable-http", "version": "2025-06-18"},
            "rest": {"endpoint": "https://forge.foundrynet.io",
                     "docs": "https://forge.foundrynet.io/docs"}},
        "provider": {"organization": "Foundry Labs", "url": "https://foundrynet.io",
                     "contact": "forge@foundrynet.io"},
    }, headers={"Cache-Control": "public, max-age=300"})


@mcp.custom_route("/a2a/tasks", methods=["POST"])
async def a2a_create_task(request: "Request") -> JSONResponse:
    """Receive a task from another A2A agent and map it to a kernel call.
    Requires a valid Forge key or OAuth JWT (Authorization: Bearer ...)."""
    if _a2a_auth(request) is None:
        return JSONResponse(
            {"error": "unauthorized",
             "error_description": "Authorization: Bearer <Forge API key or OAuth JWT> required"},
            status_code=401, headers={"WWW-Authenticate": 'Bearer realm="foundrynet-a2a"'})
    try:
        body = await request.json()
    except Exception:
        body = {}
    skill_id = str(body.get("skill_id") or "").strip()
    params = body.get("params") or {}
    if not skill_id:
        return JSONResponse({"error": "skill_id is required"}, status_code=400)
    result = await _a2a_dispatch(skill_id, params)
    if result is None:
        return JSONResponse({"error": f"Unknown skill: {skill_id}"}, status_code=400)
    failed = isinstance(result, dict) and bool(result.get("error") or result.get("detail"))
    import uuid as _uuid
    return JSONResponse({
        "task_id": str(_uuid.uuid4()),
        "status": "failed" if failed else "completed",
        "skill_id": skill_id,
        "result": result,
    }, status_code=200)


@mcp.custom_route("/a2a/agents", methods=["GET"])
async def a2a_list_agents(request: "Request") -> JSONResponse:
    """Discover agents connected to this kernel, in A2A shape. Requires auth."""
    if _a2a_auth(request) is None:
        return JSONResponse(
            {"error": "unauthorized",
             "error_description": "Authorization: Bearer <Forge API key or OAuth JWT> required"},
            status_code=401, headers={"WWW-Authenticate": 'Bearer realm="foundrynet-a2a"'})
    qp: dict = {}
    cap = request.query_params.get("capability")
    mt = request.query_params.get("min_trust_score")
    mid = request.query_params.get("machine_id")
    if cap:
        qp["capability"] = cap
    if mt:
        try:
            qp["min_trust_score"] = float(mt)
        except ValueError:
            pass
    if mid:
        qp["machine_id"] = mid
    discovered = await _call_forge("GET", "/v1/agents/discover", params=qp)
    # The kernel returns the agent list; relay it and add A2A-shaped cards.
    agents = []
    if isinstance(discovered, dict):
        agents = discovered.get("agents") or discovered.get("data") or []
    elif isinstance(discovered, list):
        agents = discovered
    a2a_agents = []
    for a in agents:
        if not isinstance(a, dict):
            continue
        caps = a.get("capabilities") or []
        a2a_agents.append({
            "name": a.get("name", ""),
            "description": a.get("description", ""),
            "capabilities": caps,
            "trust_score": a.get("trust_score"),
            "url": f"https://mcp.foundrynet.io/a2a/agents/{a.get('id')}",
            "skills": [{"id": c, "name": str(c).replace('_', ' ').title()} for c in caps],
        })
    return JSONResponse({"agents": a2a_agents, "count": len(a2a_agents)})


# ── OAuth 2.0 client-credentials (machine-to-machine) ───────────────────────
# AWS Bedrock AgentCore Gateway and Azure AI Foundry expect a standard OAuth
# client-credentials flow: POST the API key as client_secret, get a short-lived
# JWT, present it as a Bearer token. The gating middleware accepts BOTH that JWT
# and the raw key (gating.resolve_bearer), so this is purely additive.

@mcp.custom_route("/oauth/token", methods=["POST"])
async def oauth_token(request: Request) -> JSONResponse:
    """RFC 6749 §4.4 token endpoint. Reads client_id/client_secret from the
    form body (client_secret_post) or a Basic auth header (client_secret_basic).
    client_secret IS the caller's Forge API key. Returns a 1-hour JWT."""
    # Body params (client_secret_post) — OAuth clients send form-urlencoded,
    # but accept JSON too for hand-rolled callers.
    ctype = request.headers.get("content-type", "")
    try:
        data = await request.json() if "application/json" in ctype else dict(await request.form())
    except Exception:
        data = {}
    grant_type    = str(data.get("grant_type") or "").strip()
    client_id     = str(data.get("client_id") or "").strip()
    client_secret = str(data.get("client_secret") or "").strip()

    # Basic auth (client_secret_basic): Authorization: Basic base64(id:secret)
    authz = request.headers.get("authorization", "")
    if authz[:6].lower() == "basic " and not client_secret:
        try:
            cid, _, csec = base64.b64decode(authz[6:].strip()).decode("utf-8").partition(":")
            client_id = client_id or cid.strip()
            client_secret = csec.strip()
        except Exception:
            pass

    if grant_type != "client_credentials":
        return JSONResponse(
            {"error": "unsupported_grant_type",
             "error_description": "only grant_type=client_credentials is supported"},
            status_code=400)
    if not oauth_enabled():
        # Signing not configured — don't imply the key is bad.
        return JSONResponse(
            {"error": "temporarily_unavailable",
             "error_description": "OAuth token issuance is not configured on this server"},
            status_code=503)
    if not client_secret:
        return JSONResponse(
            {"error": "invalid_request",
             "error_description": "client_secret (your Forge API key) is required"},
            status_code=400)

    resp = issue_access_token(client_id, client_secret)
    if resp is None:
        return JSONResponse(
            {"error": "invalid_client",
             "error_description": "client_secret is not a valid Forge API key"},
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="foundrynet-mcp"'})
    # RFC 6749 §5.1: token responses must not be cached.
    return JSONResponse(resp, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_metadata(request: Request) -> JSONResponse:
    """RFC 8414 authorization-server metadata — AgentCore / Foundry dereference
    this to auto-discover the token endpoint and supported grant types. This is
    a machine-to-machine server, so there is no interactive authorization
    endpoint (response_types_supported is empty)."""
    return JSONResponse(
        {
            "issuer":                                 OAUTH_ISSUER,
            "token_endpoint":                         f"{OAUTH_ISSUER}/oauth/token",
            "grant_types_supported":                  ["client_credentials"],
            "token_endpoint_auth_methods_supported":  ["client_secret_post", "client_secret_basic"],
            "response_types_supported":               [],
            "scopes_supported":                       ["mcp"],
        },
        headers={"Cache-Control": "public, max-age=300"},
    )


# ── Entrypoint ───────────────────────────────────────────────────────────────

def build_dual_app():
    """Serve BOTH transports from one app:
      • Streamable HTTP at /mcp   — modern clients + Smithery's hosted gateway
      • legacy SSE at /sse (+ /messages) — existing mcp-remote configs keep working
    The streamable-http app is primary (carries /mcp + every custom_route, incl. the
    gating middleware); we graft only the two SSE transport routes onto it and chain
    both lifespans so each transport's session manager starts. New users get /mcp;
    pre-existing /sse configs (published since May) don't break."""
    import contextlib
    main_app = mcp.http_app(transport="http", path="/mcp")   # /mcp + custom routes
    sse_app = mcp.http_app(transport="sse", path="/sse")      # /sse + /messages
    for r in sse_app.routes:
        if getattr(r, "path", None) in ("/sse", "/messages"):
            main_app.router.routes.append(r)
    main_life, sse_life = main_app.router.lifespan_context, sse_app.router.lifespan_context

    @contextlib.asynccontextmanager
    async def _dual_lifespan(app):
        async with main_life(app):
            async with sse_life(app):
                yield
    main_app.router.lifespan_context = _dual_lifespan
    return main_app


if __name__ == "__main__":
    import uvicorn
    logger.info(
        f"FoundryNet MCP starting on 0.0.0.0:{PORT} "
        f"(forge={FORGE_BASE_URL}, key_configured={bool(FOUNDRYNET_API_KEY)}) "
        f"— dual transport: /mcp (streamable-http) + /sse (legacy)"
    )
    uvicorn.run(build_dual_app(), host="0.0.0.0", port=PORT, log_level="warning")
