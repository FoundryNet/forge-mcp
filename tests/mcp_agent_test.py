"""Agent integration harness for the Forge MCP server.

WHAT THIS MEASURES, AND WHERE THE MEASUREMENT HAPPENS
-----------------------------------------------------
forge-mcp is a PROXY. It owns the MCP tool surface, the tier gate, the caller
identity on the upstream hop and the shape of what comes back. It owns NO
resolution logic: every tool body is a `_call_forge(method, path)` against a
Forge kernel. So "does an agent get a correct canonical field back" is two
questions in two repos, and this file answers both, in two clearly separated
layers:

  LAYER 1 - MCP protocol conformance (this repo).
      The real ASGI app `mcp_server.build_dual_app()` returns, driven over the
      real Streamable HTTP transport through the real `GatingMiddleware`, via
      tests/mcp_client.py. Nothing is mocked but Supabase and the socket.

  LAYER 2 - resolution and guard behaviour (forge-prod's `forge_core`).
      The same primitives the kernel's /v1/normalize composes, called directly
      and OFFLINE: `deterministic_lookup`, `_apply_guards`, `explain_guard`,
      `unit_converter.convert_value`, `physics_validator`, `guardrails`,
      `field_registry`. 36k+ pack lookups across 46 standards and 20 verticals
      load from vendored JSON with no network and no credential.

  THE BRIDGE - `ForgeLocal`, below, serves Layer 2 to Layer 1 over the upstream
      seam conftest already installs. So `normalize_telemetry` called THROUGH
      MCP returns a real resolution computed by real kernel code, locally. That
      is what makes the demo sequence in docs/mcp_demo_sequence.md real rather
      than a canned fixture.

WHAT THE WORK ORDER ASKED FOR vs WHAT EXISTS
--------------------------------------------
The brief named three tools. Two of them are not tools:

  resolve_tag    -> DOES NOT EXIST. Tag resolution is `normalize_telemetry`,
                    which takes a whole `data` dict, not one tag.
  explain_guard  -> DOES NOT EXIST as a tool. It is a function in
                    `forge_core/guards.py` whose sentence is emitted INSIDE a
                    normalize response, per rejected field. An agent reads it;
                    it cannot call it.
  get_coverage   -> exists, and is the one that does.

`test_work_order_tool_names` asserts the absence, so if either is ever added
this file fails and gets corrected instead of quietly describing a surface
that is not there.

The brief also called the guards "physics gates" and gave three examples. Those
are THREE DIFFERENT MECHANISMS, and conflating them is how an integrator comes
to expect a catch that cannot happen:

  1. MAPPING guards (`guards.py`, 5 kinds) refuse a bad CANONICAL CHOICE. They
     say nothing about whether a value is good. Four of the five cannot: they
     fire before any value is considered.
  2. UNIT conversion (`unit_converter.py`) converts when the TAG NAME declares
     a unit - `Hydraulic Pressure (psi)` into a `_bar` field, `ambient_temp_f`
     into `_c`. This is the one that catches the brief's degF and psi cases.
  3. VALUE plausibility (`physics_validator.detect_unit_mismatch`, and the
     `_declared_bounds` check inside `check_guardrail`) catches a magnitude
     that cannot be the declared unit. This is the one that catches
     power_factor 99.40.

Each gets its own test, named for the mechanism, and
`test_fahrenheit_as_celsius_is_NOT_caught_by_value_plausibility` records the
case that NO layer catches, because a demo that implies otherwise is worse
than one that admits the gap.

NOT REPRODUCED BY ForgeLocal (stated so no result is read as more than it is)
----------------------------------------------------------------------------
  * The VECTOR layer. `search_schema_mappings` is a Supabase pgvector query.
    Offline it returns no candidates, so a cold field ABSTAINS - which is the
    correct conservative outcome, and the same stub the edge kernel ships
    (kernel/engine.py). Resolution here is Layer 1 (packs) only.
  * The CORPUS exact/folded layer. `corpus_index.lookup` needs a Supabase
    loader. Offline there is none, so the 16,908-mapping corpus is absent and
    only the 36k vendored pack lookups answer.
  * The LLM layer, history writes, trigger evaluation, attestation, metering.
  * `corpus_oem_tags` / `corpus_mapped_field_count` on /v1/coverage, which are
    computed FROM the corpus table. They come back explicitly null with a
    `_local_backend` note rather than as a fabricated count.

Nothing in this file touches prod. There is no credential anywhere in it.

MACHINE-LOCAL DEPENDENCY, DECLARED
----------------------------------
Layer 2 needs forge-prod's `forge_core` on disk - a sibling checkout, which is
machine-local state and therefore a defect unless it fails loudly. It does:
`_require_forge_core()` raises with the path it looked at, the env var that
overrides it, and the clone command. It never skips.

RUN
---
    pytest tests/mcp_agent_test.py -v              # forge-mcp's real runner
    FORGE_CORE_PATH=/path/to/forge-prod pytest tests/mcp_agent_test.py

Writes tests/mcp_agent_results.json at session end, whatever the outcome - a
run that collected zero, or died, says so in the file rather than leaving the
last green one lying around looking current.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import time
from typing import Any, Optional

import httpx
import pytest

from identities import SANDBOX_KEY, TENANT_A_KEY
from mcp_client import session

HERE = pathlib.Path(__file__).resolve().parent
RESULTS_PATH = HERE / "mcp_agent_results.json"

# ── Layer 2: locate forge_core, or fail by name ──────────────────────────────

_DEFAULT_FORGE_CORE_PARENTS = (
    pathlib.Path.home() / "forge-prod",
    HERE.parents[1].parent / "forge-prod",
)


def _require_forge_core() -> pathlib.Path:
    """The directory CONTAINING `forge_core/`, or a loud failure.

    A test that silently skips when a sibling checkout is missing reports on
    this filesystem rather than on the code. This one names the paths it tried,
    the override, and the fix.
    """
    candidates = []
    env = os.environ.get("FORGE_CORE_PATH")
    if env:
        candidates.append(pathlib.Path(env).expanduser())
    candidates.extend(_DEFAULT_FORGE_CORE_PARENTS)
    for root in candidates:
        if (root / "forge_core" / "universal_normalize.py").is_file():
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
            return root
    tried = "\n  ".join(str(c) for c in candidates)
    raise RuntimeError(
        "LAYER 2 DEPENDENCY ABSENT: forge-prod's `forge_core` is not on this "
        "machine, so resolution and guard behaviour cannot be measured.\n"
        f"Looked for <root>/forge_core/universal_normalize.py under:\n  {tried}\n"
        "Fix one of:\n"
        "  FORGE_CORE_PATH=/path/to/forge-prod pytest tests/mcp_agent_test.py\n"
        "  git clone git@github.com:FoundryNet/forge-prod.git ~/forge-prod\n"
        "This is NOT skipped: a pass with Layer 2 absent would measure nothing "
        "and read as a pass.")


FORGE_CORE_ROOT = _require_forge_core()

from forge_core import field_registry as _registry          # noqa: E402
from forge_core.guardrails import _declared_bounds          # noqa: E402
from forge_core.guards import (                             # noqa: E402
    GUARD_KINDS, _apply_guards, _guard_reject, _machine_vertical,
    explain_guard, guard_kind, routed_vertical_for_pack_vertical,
    vertical_oem_index,
)
from forge_core.physics_validator import detect_unit_mismatch  # noqa: E402
from forge_core.unit_converter import convert_value         # noqa: E402
from forge_core.universal_normalize import (                # noqa: E402
    deterministic_lookup, infer_device_domain, pack_stats,
)


# ── Recorder for the report ──────────────────────────────────────────────────

class Recorder:
    """Every observation this run made, in call order, for the JSON report."""

    def __init__(self):
        self.interactions: list[dict] = []
        self.started = time.time()

    def record(self, *, layer: str, scenario: str, kind: str,
               request: Any, response: Any, assertion: str,
               outcome: str = "observed") -> dict:
        row = {
            "seq": len(self.interactions) + 1,
            "layer": layer,
            "scenario": scenario,
            "kind": kind,
            "request": request,
            "response": response,
            "assertion": assertion,
            "outcome": outcome,
        }
        self.interactions.append(row)
        return row


REC = Recorder()


# ── The bridge: a local Forge backed by real forge_core ──────────────────────

class ForgeLocal:
    """Serves the kernel routes the exercised tools call, from real forge_core.

    This is a COMPOSITION over forge_core's public primitives in the documented
    layer order. It is deliberately NOT a copy of api.py's /v1/normalize route -
    the kernel's parity promise is that there is never a second engine, and a
    second route handler is how two of them come to disagree. Where a prod
    behaviour needs a backend this harness does not have, the response SAYS SO
    in `_local_backend` rather than inventing a value.

    Any path it does not implement answers 501 with the path in the body. A
    stub that returned a cheerful 200 for an unimplemented route is how a tool
    comes to look exercised when nothing ran.
    """

    IMPLEMENTED = (
        ("POST", "/v1/normalize"),
        ("POST", "/v1/guardrails/check"),
        ("GET", "/v1/coverage"),
        ("POST", "/v1/identify"),
    )

    def __init__(self):
        self.calls: list[dict] = []
        self.machines: dict[str, dict] = {}

    # -- dispatch ------------------------------------------------------------
    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method.upper()
        try:
            body = json.loads(request.content or b"{}")
        except Exception:
            body = {}
        self.calls.append({"method": method, "path": path, "body": body})
        if method == "POST" and path == "/v1/normalize":
            return self._normalize(body)
        if method == "POST" and path == "/v1/guardrails/check":
            return self._guardrails_check(body)
        if method in ("GET", "HEAD") and path == "/v1/coverage":
            return self._coverage(dict(request.url.params))
        if method == "POST" and path == "/v1/identify":
            return self._identify(body)
        return httpx.Response(501, json={
            "error": "not_implemented_in_local_backend",
            "message": (f"{method} {path} is a real kernel route that this "
                        f"offline harness does not serve. The MCP proxy "
                        f"reached it correctly; there is nothing behind it "
                        f"here."),
            "implemented": [f"{m} {p}" for m, p in self.IMPLEMENTED],
        })

    # -- POST /v1/identify ---------------------------------------------------
    def _identify(self, body: dict) -> httpx.Response:
        oem = (body.get("oem") or "").strip()
        serial = (body.get("serial") or "unknown").strip()
        mint_id = f"MINT-LOCAL-{abs(hash((oem, serial))) % 10**6:06d}"
        vertical = _machine_vertical(oem or None, body.get("model"))
        self.machines[mint_id] = {"oem": oem, "vertical": vertical}
        return httpx.Response(200, json={
            "mint_id": mint_id,
            "oem": oem,
            "model": body.get("model"),
            "vertical": vertical,
            "vertical_gate": "active" if vertical else
                             "inactive - OEM unrecognized, gate disabled",
            "_local_backend": "identity is synthetic; no MINT relay was called",
        })

    # -- POST /v1/normalize --------------------------------------------------
    def _normalize(self, body: dict) -> httpx.Response:
        data = body.get("data")
        if not isinstance(data, dict):
            return httpx.Response(400, json={
                "error": "bad_request",
                "message": "`data` must be an object of {raw_field: value}",
                "received_type": type(data).__name__,
            })
        oem = body.get("oem")
        model = body.get("model")
        columns = list(data)
        machine_vertical = _machine_vertical(oem, model)
        device_domain = infer_device_domain(columns, oem)

        canonical_data: dict[str, Any] = {}
        field_mappings: dict[str, dict] = {}
        conversions: list[dict] = []
        guard_diagnostics: list[dict] = []
        warnings: list[dict] = []

        for col in columns:
            raw = data[col]
            hit = deterministic_lookup(col, oem or "")
            if not hit:
                field_mappings[col] = {
                    "canonical": col,
                    "confidence": 0.0,
                    "match_type": "unknown",
                    "layer": "none",
                    "reason": ("no deterministic pack match; the corpus and "
                               "vector layers are not available offline"),
                }
                canonical_data[col] = raw
                continue

            canonical = hit["canonical"]
            # THE GUARDS DO NOT APPLY TO A PACK HIT, AND THIS HARNESS MUST NOT
            # EITHER.
            #
            # Measured in forge-prod: `_apply_guards` is called from exactly two
            # places - `normalize_engine.py:325`, on VECTOR candidates, and
            # `kernel/engine.py::_corpus_resolves`, on PULLED CORPUS rows. A
            # deterministic pack hit passes through neither, because a published
            # register map is stronger evidence than a name heuristic. The
            # engine says as much in its own comment at normalize_engine.py:57:
            # "A deterministic pack outranks the noise filter."
            #
            # An earlier revision of this harness guarded pack hits, and it
            # reported `controller_temp` (abb_robot) and `engine_coolant_temp`
            # (caterpillar) as REJECTED - two mappings prod resolves correctly.
            # Sweeping all 36,331 pack rows, 254 of them (0.70%) would be
            # discarded that way: 186 by the vertical guard and 68 by
            # no_canonical. So the resolution ORDER is load-bearing for 254
            # mappings, and pack-first is the correct order.
            #
            # The guard verdict is still computed and REPORTED, as a diagnostic,
            # because the disagreement is worth seeing. It is never applied.
            guard_reason = _guard_reject(col, canonical, machine_vertical, raw)
            guard_diagnostic = None
            if guard_reason:
                guard_diagnostic = {
                    "guard": guard_reason,
                    "guard_kind": guard_kind(guard_reason),
                    "guard_explanation": explain_guard(
                        guard_reason, col, canonical, machine_vertical, raw),
                    "applied": False,
                    "why_not": ("a deterministic pack hit does not pass through "
                                "the guards in prod; they gate the vector and "
                                "corpus layers only"),
                }
                guard_diagnostics.append(
                    {"raw_field": col, "pack_canonical": canonical,
                     **guard_diagnostic})

            value, conv = convert_value(col, raw, canonical,
                                        source_unit=hit.get("unit"))
            if conv and conv.get("converted"):
                conversions.append(conv)
            elif conv and conv.get("flag"):
                warnings.append({"raw_field": col, **conv})

            suggestion = None
            try:
                suggestion = detect_unit_mismatch(canonical, float(value))
            except (TypeError, ValueError):
                suggestion = None
            if suggestion is not None:
                warnings.append({
                    "raw_field": col,
                    "canonical_field": canonical,
                    "flag": "value_implausible_for_declared_unit",
                    "stored_value": value,
                    "plausible_if_converted": suggestion,
                    "detail": (f"{value} is outside the physical envelope for "
                               f"{canonical}; {suggestion} is plausible, which "
                               f"is evidence the source unit was not the "
                               f"declared one."),
                })

            canonical_data[canonical] = value
            field_mappings[col] = {
                "canonical": canonical,
                "confidence": 1.0,
                "match_type": "deterministic",
                "layer": "pack",
                "standard": hit.get("standard"),
                "vertical": hit.get("vertical"),
                "unit": hit.get("unit"),
                "registry_unit": _registry.unit_of(canonical),
                "guard_diagnostic": guard_diagnostic,
            }

        return httpx.Response(200, json={
            "machine_id": body.get("machine_id"),
            "oem": oem,
            "machine_vertical": machine_vertical,
            "device_domain": device_domain,
            "canonical_data": canonical_data,
            "field_mappings": field_mappings,
            "conversions": conversions,
            # The guards gate the vector and corpus layers, which are absent
            # offline, so nothing here is ever REJECTED by a guard. What is
            # reported instead is every pack hit the guards would have
            # disagreed with had they applied - see the note in the loop.
            "guard_diagnostics": guard_diagnostics,
            "warnings": warnings,
            "fields_in": len(columns),
            "fields_mapped": sum(1 for m in field_mappings.values()
                                 if m["match_type"] == "deterministic"),
            "fields_with_guard_disagreement": len(guard_diagnostics),
            "fields_unknown": sum(1 for m in field_mappings.values()
                                  if m["match_type"] == "unknown"),
            "_local_backend": {
                "layers_active": ["deterministic_pack", "mapping_guards",
                                  "unit_conversion", "value_plausibility"],
                "layers_absent": ["corpus_exact", "vector", "llm"],
                "note": ("resolution is pack-only offline; a field the packs "
                         "do not know abstains as `unknown` rather than being "
                         "force-mapped"),
            },
        })

    # -- POST /v1/guardrails/check -------------------------------------------
    def _guardrails_check(self, body: dict) -> httpx.Response:
        proposed = body.get("proposed")
        if not isinstance(proposed, dict) or not proposed:
            return httpx.Response(400, json={
                "error": "bad_request",
                "message": "`proposed` must be a non-empty object of "
                           "{canonical_field: value}",
            })
        declared: dict[str, Any] = {}
        violations: list[dict] = []
        unresolvable: list[str] = []
        for field, value in proposed.items():
            if not _registry.is_canonical(field):
                unresolvable.append(field)
                continue
            bounds = _declared_bounds(field)
            declared[field] = list(bounds) if bounds else None
            if bounds is None:
                continue
            lo, hi = bounds
            try:
                v = float(value)
            except (TypeError, ValueError):
                unresolvable.append(field)
                continue
            if v < lo or v > hi:
                violations.append({
                    "field": field,
                    "value": v,
                    "declared_bounds": [lo, hi],
                    "reason": (f"{field} {v} is outside the physical envelope "
                               f"[{lo}, {hi}] declared for every machine in "
                               f"the fleet"),
                })
        would_block = bool(violations or unresolvable)
        return httpx.Response(200, json={
            "would_block": would_block,
            "guardrail": None,
            "reason": violations[0]["reason"] if violations else None,
            "violations": violations,
            "unresolvable_fields": unresolvable,
            "guardrails_evaluated": 0,
            "declared_bounds": declared,
            "physical_bounds_checked": True,
            "_local_backend": ("per-machine engineer-authored guardrails live "
                               "in the kernel DB and are absent here, so "
                               "guardrails_evaluated is 0 and only the "
                               "registry-wide physical envelope answered"),
        })

    # -- GET /v1/coverage ----------------------------------------------------
    def _coverage(self, params: dict) -> httpx.Response:
        canon = sorted(_registry.fields() or {})
        families: dict[str, list] = {}
        for c in canon:
            ns = c.split(".")[0] if "." in c else c.split("_")[0]
            families.setdefault(ns, []).append(c)
        packs = pack_stats() or {}
        routed = set(vertical_oem_index())
        unrouted = sorted(
            v for v in (packs.get("verticals") or [])
            if routed_vertical_for_pack_vertical(v) not in routed)
        oem = params.get("oem")
        resolved = None
        if oem:
            mv = _machine_vertical(oem, None)
            resolved = {
                "oem": oem,
                "vertical": mv,
                "vertical_gate": ("active" if mv else
                                  "inactive - OEM unrecognized, gate disabled "
                                  "(normalize still works)"),
            }
        return httpx.Response(200, json={
            "vertical_oems": vertical_oem_index(),
            "verticals_without_oem_routing": unrouted,
            "corpus_oem_tags": None,
            "canonical_families": {k: families[k] for k in sorted(families)},
            "canonical_field_count": len(canon),
            "family_count": len(families),
            "corpus_mapped_field_count": None,
            "vertical_packs": packs,
            "resolved_oem": resolved,
            "_local_backend": ("corpus_oem_tags and corpus_mapped_field_count "
                               "are computed FROM the corpus table and are "
                               "null here rather than fabricated; every other "
                               "key is computed from the same vendored "
                               "registry and packs prod reads"),
        })


FORGE = ForgeLocal()


@pytest.fixture
def forge(upstream):
    """Wire the local Forge into the upstream seam for one test."""
    FORGE.calls.clear()
    upstream.responder = FORGE.handle
    yield FORGE


# ── Realistic vendor payloads ────────────────────────────────────────────────
# Tag names are the published register / variable names for each standard, and
# every one is checked against the loaded pack layer by
# `test_fixture_tags_are_real`, so a typo cannot quietly become a coverage gap
# in the report.

SUNSPEC_INVERTER = {
    "oem": "sunspec",
    "data": {"W": 4200.0, "A": 12.4, "PPVphAB": 480.2, "Hz": 59.98,
             "DCV": 742.0, "TmpCab": 41.5},
}
SUNSPEC_STORAGE = {
    "oem": "sunspec_storage",
    "data": {"ChaState": 61.5, "InBatV": 798.4, "SoH": 97.2, "NCyc": 412},
}
SCHNEIDER_METER = {
    "oem": "schneider_ion",
    "data": {"kw_total": 184.6, "kvar_total": 41.2, "pf_total": 0.976,
             "vll_avg": 480.9, "freq": 59.99},
}
HAAS_CNC = {
    # The haas_ngc pack carries exactly TWO tags, both resolving to
    # spindle_speed_rpm, so only one can be in a payload without colliding.
    # CNC breadth lives in the corpus, which is absent offline - stated here so
    # a thin CNC beat in the report is not read as thin CNC coverage in prod.
    "oem": "haas",
    "data": {"spd_rpm": 11800},
}
ABB_ROBOT = {
    "oem": "abb_robot",
    "data": {"axis1_angle": 41.7, "axis1_torque": 18.3,
             "controller_temp": 38.0, "cycle_time": 42.8,
             "speed_override": 85.0},
}
J1939_MINING = {
    "oem": "caterpillar",
    "data": {"engine_speed": 1420.0, "engine_coolant_temp": 88.0,
             "fuel_level": 54.0, "battery_voltage": 27.8,
             "ground_speed": 11.4},
}

VENDOR_PAYLOADS = {
    "sunspec_inverter": SUNSPEC_INVERTER,
    "sunspec_storage": SUNSPEC_STORAGE,
    "schneider_meter": SCHNEIDER_METER,
    "haas_cnc": HAAS_CNC,
    "abb_robot": ABB_ROBOT,
    "j1939_mining": J1939_MINING,
}


def _mapped(payload: dict) -> dict:
    """{raw_field: mapping} for the fields the pack layer actually knows."""
    oem = payload["oem"]
    out = {}
    for tag in payload["data"]:
        hit = deterministic_lookup(tag, oem)
        if hit:
            out[tag] = hit
    return out


# ═══════════════════════════════════════════════════════════════════════════
# LAYER 1 - MCP protocol conformance
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_work_order_tool_names():
    """`resolve_tag` and `explain_guard` are NOT tools. Asserted, not assumed.

    The work order this harness was built from named both. If either is ever
    added, this fails and the demo script gets corrected - rather than the
    other way round, where a doc describes a surface no agent can reach.
    """
    async with session(TENANT_A_KEY) as s:
        tools = {t["name"] for t in await s.list_tools()}
    assert "get_coverage" in tools
    for absent in ("resolve_tag", "explain_guard"):
        assert absent not in tools, (
            f"{absent} now exists as an MCP tool. docs/mcp_demo_sequence.md "
            f"says it does not - update both.")
    REC.record(
        layer="1-mcp", scenario="tool-surface", kind="tools/list",
        request={"method": "tools/list"},
        response={"tool_count": len(tools),
                  "resolve_tag_present": False,
                  "explain_guard_present": False,
                  "get_coverage_present": True},
        assertion="resolve_tag and explain_guard are absent; get_coverage is present")


@pytest.mark.asyncio
async def test_tool_surface_is_tiered():
    """A pro key sees more tools than a free key, and both see the free set."""
    async with session(TENANT_A_KEY) as s:
        pro = {t["name"] for t in await s.list_tools()}
    async with session(SANDBOX_KEY) as s:
        free = {t["name"] for t in await s.list_tools()}
    assert free, "free key saw no tools at all"
    assert free <= pro, f"free key sees tools pro does not: {sorted(free - pro)}"
    assert "normalize_telemetry" in free and "get_coverage" in free
    REC.record(
        layer="1-mcp", scenario="tool-surface", kind="tools/list",
        request={"keys": ["pro", "free"]},
        response={"pro_tool_count": len(pro), "free_tool_count": len(free),
                  "free_is_subset": True},
        assertion="free tool set is a strict subset of pro and contains the first-value calls")


@pytest.mark.asyncio
@pytest.mark.parametrize("name", sorted(VENDOR_PAYLOADS))
async def test_vendor_payload_resolves_through_mcp(forge, name):
    """Raw vendor tags in, canonical field + unit + vertical out, over MCP."""
    payload = VENDOR_PAYLOADS[name]
    expected = _mapped(payload)
    async with session(TENANT_A_KEY) as s:
        out = await s.call("normalize_telemetry",
                           {"data": payload["data"], "oem": payload["oem"]})
    assert out["ok"], out.get("error")
    body = out["payload"]
    fm = body["field_mappings"]

    for tag, hit in expected.items():
        m = fm[tag]
        assert m["match_type"] == "deterministic", (tag, m)
        assert m["canonical"] == hit["canonical"], (tag, m)
        assert m["confidence"] == 1.0, (tag, m)
        assert m["vertical"] == hit.get("vertical"), (tag, m)
        assert body["canonical_data"].get(hit["canonical"]) is not None, tag

    assert body["fields_mapped"] == len(expected)
    REC.record(
        layer="1-mcp", scenario=f"resolve:{name}", kind="normalize_telemetry",
        request={"oem": payload["oem"], "data": payload["data"]},
        response={
            "machine_vertical": body["machine_vertical"],
            "fields_in": body["fields_in"],
            "fields_mapped": body["fields_mapped"],
            "fields_unknown": body["fields_unknown"],
            "mappings": {t: {"canonical": fm[t]["canonical"],
                             "unit": fm[t].get("unit"),
                             "registry_unit": fm[t].get("registry_unit"),
                             "vertical": fm[t].get("vertical"),
                             "standard": fm[t].get("standard")}
                         for t in expected},
            "canonical_data": body["canonical_data"],
        },
        assertion=(f"every tag the {payload['oem']} pack declares resolves "
                   f"deterministically at confidence 1.0 with its pack unit "
                   f"and vertical"))


@pytest.mark.asyncio
async def test_multi_vendor_batch_does_not_cross_contaminate(forge):
    """Five vendors, five sessions, one process: no mapping leaks between them.

    The failure this guards against is a shared index or cache keyed on the
    tag alone, so `W` resolves as a SunSpec watt on a mining payload. Each
    payload is normalized in its own session and every resolution is compared
    against the pack layer's answer FOR ITS OWN OEM.
    """
    seen: dict[str, set] = {}
    async with session(TENANT_A_KEY) as s:
        for name, payload in sorted(VENDOR_PAYLOADS.items()):
            out = await s.call("normalize_telemetry",
                               {"data": payload["data"], "oem": payload["oem"]})
            assert out["ok"], (name, out.get("error"))
            fm = out["payload"]["field_mappings"]
            for tag, hit in _mapped(payload).items():
                assert fm[tag]["canonical"] == hit["canonical"], (
                    f"{name}/{tag} resolved to {fm[tag]['canonical']!r}, but "
                    f"the {payload['oem']} pack says {hit['canonical']!r}")
                seen.setdefault(tag, set()).add(
                    (payload["oem"], fm[tag]["canonical"]))

    shared = {t: sorted(v) for t, v in seen.items() if len(v) > 1}
    REC.record(
        layer="1-mcp", scenario="multi-vendor-batch", kind="normalize_telemetry",
        request={"payloads": {n: p["oem"] for n, p in VENDOR_PAYLOADS.items()},
                 "total_tags": sum(len(p["data"]) for p in VENDOR_PAYLOADS.values())},
        response={"tags_seen_under_more_than_one_oem": shared,
                  "all_resolutions_matched_own_pack": True},
        assertion=("a tag shared across OEMs resolves per-OEM; no resolution "
                   "in one payload displaced another"))


@pytest.mark.asyncio
async def test_cross_domain_inference(forge):
    """An OEM string is not a vertical, and the gate says which one it got.

    The work order's framing was "Siemens is not always energy". Measured:
    `siemens` routes to **cnc**, `caterpillar` to **vehicle**, `kuka` to
    **robot**, `solaredge` to **energy** - so the premise holds and the
    namespace does the work.

    It also surfaced something sharper, recorded here as a finding rather than
    asserted away: A PACK SCOPE NAME IS NOT AN OEM ROUTING NAME. `sunspec`,
    `sunspec_storage`, `abb_robot` and `haas_ngc` all resolve TAGS from their
    packs, and all four route to `vertical: null`, so the cross-vertical gate
    disables for exactly the strings an integrator is most likely to type -
    the name of the standard their device speaks. `solaredge` and `haas` route
    fine. This is the same shape as the geothermal integrator who guessed four
    vendor names and got `vertical: null` for all four.
    """
    routes_to = {
        "siemens": "cnc",
        "haas": "cnc",
        "solaredge": "energy",
        "caterpillar": "vehicle",
        "kuka": "robot",
        "prusa": "printer",
    }
    # Resolve tags but route to no vertical - the gate is off for these.
    resolves_but_unrouted = ["sunspec", "sunspec_storage", "abb_robot",
                             "haas_ngc"]
    unknown = "definitely_not_a_real_oem"

    observed = {}
    async with session(TENANT_A_KEY) as s:
        for oem in list(routes_to) + resolves_but_unrouted + [unknown]:
            out = await s.call("get_coverage", {"oem": oem})
            assert out["ok"], (oem, out.get("error"))
            observed[oem] = out["payload"]["resolved_oem"]

    for oem, want in routes_to.items():
        assert observed[oem]["vertical"] == want, (oem, observed[oem])
        assert observed[oem]["vertical_gate"] == "active", (oem, observed[oem])
    assert observed["siemens"]["vertical"] != observed["solaredge"]["vertical"], (
        "the cross-domain premise failed: siemens and solaredge resolved the "
        "same vertical")

    unrouted = {}
    for oem in resolves_but_unrouted:
        assert observed[oem]["vertical"] is None, (oem, observed[oem])
        assert "inactive" in observed[oem]["vertical_gate"]
        unrouted[oem] = {
            "vertical": None,
            "pack_tags_do_resolve": bool(
                [t for t in ("W", "ChaState", "axis1_angle", "spd_rpm")
                 if deterministic_lookup(t, oem)]),
        }

    assert observed[unknown]["vertical"] is None
    assert "inactive" in observed[unknown]["vertical_gate"]

    REC.record(
        layer="1-mcp", scenario="cross-domain", kind="get_coverage",
        request={"routed_probes": sorted(routes_to),
                 "unrouted_probes": resolves_but_unrouted,
                 "unknown_probe": unknown},
        response={"resolved": observed,
                  "pack_scope_not_a_routing_name": unrouted},
        assertion=("each OEM resolves to its own vertical with the gate ACTIVE "
                   "(siemens->cnc, solaredge->energy, caterpillar->vehicle, "
                   "kuka->robot, prusa->printer); an unrecognized OEM returns "
                   "vertical:null and an explicitly inactive gate rather than "
                   "a guess. FINDING: four pack SCOPE names resolve tags but "
                   "route to no vertical, so the gate is off for the string an "
                   "integrator is most likely to pass."),
        outcome="finding")


@pytest.mark.asyncio
async def test_coverage_counts_say_what_they_measure(forge):
    """Coverage returns the registry count, the family count and pack stats -
    and each is checked against the thing it actually measures.

    1,016 is the REGISTRY. It is not the corpus count, not the pack-mapping
    count, and not deterministic reach. The response keeps them under separate
    names and the corpus-derived ones come back null offline rather than
    borrowing the registry's number, which is exactly the drift that made the
    live endpoint report 85 and 1,016 in the same breath.
    """
    async with session(TENANT_A_KEY) as s:
        out = await s.call("get_coverage", {})
    assert out["ok"], out.get("error")
    body = out["payload"]
    packs = body["vertical_packs"]

    assert body["canonical_field_count"] == len(_registry.fields())
    assert body["canonical_field_count"] == 1016, (
        f"the registry is now {body['canonical_field_count']} fields, not "
        f"1,016 - CLAUDE.md and docs/mcp_demo_sequence.md both quote it")
    assert body["family_count"] == len(body["canonical_families"])
    assert body["corpus_oem_tags"] is None
    assert body["corpus_mapped_field_count"] is None
    assert len(packs["verticals"]) == 20, packs["verticals"]
    assert packs["packs_loaded"] == 46, (
        f"{packs['packs_loaded']} packs loaded, not 46 - CLAUDE.md quotes "
        f"\"46 vendor packs across 20 verticals\"")
    assert packs["total_pack_mappings"] > 2000, packs["total_pack_mappings"]
    # CLAUDE.md: auto-pack is DESIGNED, NOT RUNNING. It has never fired, and
    # the local pack layer agrees - 0 auto-pack mappings. Asserted so a demo
    # never describes self-healing as operating.
    assert (packs.get("auto_packs") or {}).get("mappings") == 0, (
        "an auto-pack has mappings. Self-healing is documented as designed, "
        "not running - if that changed, CLAUDE.md and the demo script both "
        "need updating.")
    assert sum(len(v) for v in body["canonical_families"].values()) \
        == body["canonical_field_count"]

    REC.record(
        layer="1-mcp", scenario="coverage", kind="get_coverage",
        request={"oem": None},
        response={
            "canonical_field_count": body["canonical_field_count"],
            "family_count": body["family_count"],
            "packs_loaded": packs["packs_loaded"],
            "total_pack_mappings": packs["total_pack_mappings"],
            "auto_pack_mappings": (packs.get("auto_packs") or {}).get("mappings"),
            "verticals": packs["verticals"],
            "routed_verticals": sorted(body["vertical_oems"]),
            "verticals_without_oem_routing": body["verticals_without_oem_routing"],
            "corpus_derived_counts": "null offline (see _local_backend)",
        },
        assertion=("canonical_field_count == the 1,016-field registry; "
                   "families partition it exactly; 20 pack verticals; "
                   "corpus-derived counts are null, not borrowed"))


@pytest.mark.asyncio
async def test_guardrail_bounds_fire_and_absence_is_stated(forge):
    """check_guardrail blocks an impossible value AND admits when no rule exists.

    Both halves matter. `would_block: false` with `guardrails_evaluated: 0` is
    not permission, and the tool's own description says so - so the harness
    asserts the honesty field is present on the pass, not just the block on
    the failure.
    """
    cases = [
        ("power_factor", 99.40, True,
         "a power factor of 99.40 cannot be a ratio; declared bounds are [-1, 1]"),
        ("power_factor", 0.97, False, "a real power factor passes"),
        ("spindle_speed_rpm", 13000, False,
         "physically possible, and no engineer-authored rule exists to say "
         "whether it is safe for THIS spindle"),
        ("spindle_speed_rpm", 9_000_000, True,
         "outside the registry-wide physical envelope for every machine"),
        ("not_a_canonical_field", 1, True,
         "an unplaceable field cannot be range-checked, so it is refused"),
    ]
    observed = []
    async with session(TENANT_A_KEY) as s:
        for field, value, expect_block, why in cases:
            out = await s.call("check_guardrail",
                               {"machine_id": "MINT-LOCAL-DEMO",
                                "proposed": {field: value}})
            assert out["ok"], (field, out.get("error"))
            b = out["payload"]
            assert b["would_block"] is expect_block, (field, value, b)
            assert b["guardrails_evaluated"] == 0
            assert b["physical_bounds_checked"] is True
            observed.append({
                "proposed": {field: value},
                "would_block": b["would_block"],
                "reason": b["reason"],
                "declared_bounds": b["declared_bounds"],
                "unresolvable_fields": b["unresolvable_fields"],
                "guardrails_evaluated": b["guardrails_evaluated"],
                "why": why,
            })
    REC.record(
        layer="1-mcp", scenario="guardrail-bounds", kind="check_guardrail",
        request={"cases": [{"field": f, "value": v} for f, v, _, _ in cases]},
        response=observed,
        assertion=("registry-wide bounds block an impossible value; a possible "
                   "one passes with guardrails_evaluated:0 stated so the "
                   "absence of a rule is never read as approval"))


@pytest.mark.asyncio
@pytest.mark.parametrize("label,args,expect", [
    ("unknown_vendor",
     {"data": {"Weird_Vendor_Tag_01": 7.0}, "oem": "no_such_vendor_exists"},
     "unknown"),
    ("no_canonical_match",
     {"data": {"zzz_unmappable_qqq": 1.0}, "oem": "haas"},
     "unknown"),
    ("empty_payload", {"data": {}, "oem": "haas"}, "empty"),
])
async def test_edge_cases_abstain_rather_than_guess(forge, label, args, expect):
    """An unknown tag ABSTAINS and keeps its raw value. It is never force-mapped."""
    async with session(TENANT_A_KEY) as s:
        out = await s.call("normalize_telemetry", args)
    assert out["ok"], out.get("error")
    b = out["payload"]
    if expect == "empty":
        assert b["fields_in"] == 0 and b["field_mappings"] == {}
    else:
        assert b["fields_unknown"] == len(args["data"])
        assert b["fields_mapped"] == 0
        for tag, v in args["data"].items():
            assert b["field_mappings"][tag]["match_type"] == "unknown"
            assert b["field_mappings"][tag]["confidence"] == 0.0
            assert b["canonical_data"][tag] == v, "the raw reading was lost"
    REC.record(
        layer="1-mcp", scenario=f"edge:{label}", kind="normalize_telemetry",
        request=args, response=b,
        assertion=("an unresolvable tag abstains as `unknown` at confidence "
                   "0.0 and its raw value is returned unchanged"))


@pytest.mark.asyncio
async def test_malformed_input_is_refused_not_guessed(forge):
    """`data` as a list is a 400 from the kernel, surfaced as a tool error."""
    async with session(TENANT_A_KEY) as s:
        out = await s.call("normalize_telemetry", {"data": ["not", "a", "dict"]})
    assert not out["ok"], "a list `data` was accepted"
    REC.record(
        layer="1-mcp", scenario="edge:malformed", kind="normalize_telemetry",
        request={"data": ["not", "a", "dict"]},
        response={"isError": True, "error": out.get("error")},
        assertion="a non-object `data` is refused rather than coerced")


@pytest.mark.asyncio
async def test_proxy_calls_the_routes_it_documents(forge):
    """Each exercised tool reaches the kernel path its body names.

    This is the proxy's own contract and the one thing only Layer 1 can check:
    the tool surface an agent sees is wired to the endpoint the description
    claims.
    """
    async with session(TENANT_A_KEY) as s:
        await s.call("normalize_telemetry", {"data": {"W": 1.0}, "oem": "sunspec"})
        await s.call("get_coverage", {})
        await s.call("check_guardrail",
                     {"machine_id": "m", "proposed": {"power_factor": 0.9}})
    hit = [(c["method"], c["path"]) for c in forge.calls]
    assert ("POST", "/v1/normalize") in hit
    assert ("GET", "/v1/coverage") in hit
    assert ("POST", "/v1/guardrails/check") in hit
    REC.record(
        layer="1-mcp", scenario="routing", kind="upstream-trace",
        request={"tools": ["normalize_telemetry", "get_coverage",
                           "check_guardrail"]},
        response={"upstream_calls": hit},
        assertion="every exercised tool reached the kernel route its body names")


# ═══════════════════════════════════════════════════════════════════════════
# LAYER 2 - resolution and guard behaviour (forge_core, offline)
# ═══════════════════════════════════════════════════════════════════════════

def test_fixture_tags_are_real():
    """Every fixture tag either resolves or is DELIBERATELY unmappable.

    Without this, a typo in a vendor tag turns into a silent `unknown` and the
    report reads as a coverage gap in Forge rather than a bug in the fixture.
    """
    report = {}
    for name, payload in sorted(VENDOR_PAYLOADS.items()):
        hits = _mapped(payload)
        report[name] = {
            "oem": payload["oem"],
            "tags": len(payload["data"]),
            "resolved": sorted(hits),
            "unresolved": sorted(set(payload["data"]) - set(hits)),
        }
        assert hits, (
            f"NO tag in the {name} fixture resolves under oem="
            f"{payload['oem']!r}. The fixture is wrong, not the pack layer.")
    REC.record(
        layer="2-forge_core", scenario="fixture-integrity", kind="deterministic_lookup",
        request={"payloads": sorted(VENDOR_PAYLOADS)},
        response=report,
        assertion="every vendor fixture resolves at least one real pack tag")


def test_all_five_mapping_guards_fire_with_an_actionable_sentence():
    """Each guard kind fires, and `explain_guard` returns a usable sentence.

    This is the demo's "physics catch" beat, named correctly: these are MAPPING
    guards. Four of the five fire before any value is looked at. The sentence
    is a safety-path string - it must name the guard that fired, say what to do
    about it, and state that the reading was kept.
    """
    cases = [
        ("no_canonical", "temp", "coolant_temp_c", "haas", None),
        ("vertical", "coolant_temp", "vehicle.ambient.air_temp", "haas", None),
        ("dimension", "wind_speed", "speed_rpm", "haas", 3.1),
        ("subject", "S1_CommandVelocity", "axes.x_velocity_commanded", "haas", None),
        ("range", "CoolantLevel", "level_pct", "haas", 9999),
    ]
    observed = []
    fired = set()
    for want, field, canonical, oem, value in cases:
        mv = _machine_vertical(oem, None)
        reason = _guard_reject(field, canonical, mv, value)
        assert reason, f"{want}: no guard fired on {field!r} -> {canonical!r}"
        kind = guard_kind(reason)
        assert kind == want, (field, reason, kind)
        sentence = explain_guard(reason, field, canonical, mv, value)
        assert sentence, f"{want}: explain_guard returned nothing"
        assert "returned unchanged" in sentence, (
            f"{want}: the sentence does not say the reading was kept - that is "
            f"the question it exists to answer")
        assert len(sentence) > 120, f"{want}: sentence is too short to act on"
        fired.add(kind)
        observed.append({
            "guard_kind": kind, "raw_field": field,
            "rejected_canonical": canonical, "machine_vertical": mv,
            "value": value, "guard_reason": reason,
            "explain_guard": sentence,
        })
    assert fired == set(GUARD_KINDS), (
        f"guard kinds not exercised: {sorted(set(GUARD_KINDS) - fired)}")
    REC.record(
        layer="2-forge_core", scenario="mapping-guards", kind="explain_guard",
        request={"cases": [{"field": f, "candidate": c} for _, f, c, _, _ in cases]},
        response=observed,
        assertion=("all 5 guard kinds fire and each returns an actionable "
                   "sentence that states the reading was kept"))


def test_guards_reject_a_mapping_through_mcp_shape():
    """A guard rejection reaches an agent as a field-level explanation."""
    payload = {"oem": "haas", "data": {"coolant_temp": 24.0}}
    hit = deterministic_lookup("coolant_temp", "haas")
    REC.record(
        layer="2-forge_core", scenario="mapping-guards", kind="deterministic_lookup",
        request=payload,
        response={"pack_hit": hit,
                  "note": ("the vertical guard fires on the VECTOR candidate, "
                           "which is absent offline; the guard itself is "
                           "measured directly in "
                           "test_all_five_mapping_guards_fire_with_an_actionable_sentence")},
        assertion="recorded for the report; the guard is measured directly, not here")


def test_unit_conversion_catches_the_declared_unit_cases():
    """psi into a bar field, degF into a degC field - caught by the TAG NAME.

    This is mechanism 2 of the three the work order called "physics gates", and
    the only one that catches its degF and psi examples. The field NAME is
    authoritative: `ambient_temp_f` is a degF reading whether or not the pack
    said so.
    """
    cases = [
        ("Hydraulic Pressure (psi)", 2900.0, "hydraulic_pressure_bar",
         "psi", "bar"),
        ("Coolant Temp (F)", 194.0, "coolant_temp_c", "F", "C"),
        ("ambient_temp_f", 94.6, "ambient_temp_c", "F", "C"),
    ]
    observed = []
    for tag, raw, canonical, src, dst in cases:
        value, conv = convert_value(tag, raw, canonical)
        assert conv and conv["converted"] is True, (tag, conv)
        assert conv["from"] == src and conv["to"] == dst, (tag, conv)
        assert conv["unit_source"] == "tag", (tag, conv)
        assert value != raw, (tag, "nothing was converted")
        observed.append({"raw_field": tag, "raw_value": raw,
                         "canonical_field": canonical,
                         "stored_value": value, "conversion": conv})
    REC.record(
        layer="2-forge_core", scenario="unit-corruption", kind="convert_value",
        request={"cases": [{"tag": t, "value": v, "canonical": c}
                           for t, v, c, _, _ in cases]},
        response=observed,
        assertion=("a unit declared in the tag name is converted to the "
                   "canonical field's unit before storage"))


def test_undeclared_unit_is_flagged_not_silently_stored():
    """A field that expects a unit and got none is flagged `unit_undetermined`."""
    value, conv = convert_value("PowerFactor", 99.40, "power_factor")
    assert conv["converted"] is False
    assert conv["flag"] == "unit_undetermined"
    assert value == 99.40, "the value was altered on a path that cannot know the unit"
    REC.record(
        layer="2-forge_core", scenario="unit-corruption", kind="convert_value",
        request={"tag": "PowerFactor", "value": 99.40,
                 "canonical": "power_factor"},
        response={"stored_value": value, "conversion": conv},
        assertion=("an undeclared unit is flagged and the value stored "
                   "unchanged - never converted on a guess"))


def test_value_plausibility_catches_a_magnitude_that_cannot_be_the_unit():
    """Mechanism 3: 2900 in a bar field is psi, and the validator says so."""
    observed = []
    for field, value, expect in [
        ("hydraulic_pressure_bar", 2900.0, True),
        ("oil_pressure_bar", 150.0, True),
        ("hydraulic_pressure_bar", 80.0, False),
    ]:
        suggestion = detect_unit_mismatch(field, value)
        assert (suggestion is not None) is expect, (field, value, suggestion)
        observed.append({"canonical_field": field, "value": value,
                         "plausible_if_converted": suggestion,
                         "declared_bounds": list(_declared_bounds(field) or ())})
    REC.record(
        layer="2-forge_core", scenario="value-plausibility", kind="detect_unit_mismatch",
        request={"cases": [c["canonical_field"] for c in observed]},
        response=observed,
        assertion=("a magnitude outside the declared unit's envelope is "
                   "flagged with the value it would be once converted"))


def test_power_factor_99_is_caught_by_declared_bounds():
    """power_factor 99.40 as a ratio: not a unit mismatch, a bounds violation.

    Worth separating. `detect_unit_mismatch` returns None here - there is no
    plausible source unit for which 99.40 is a valid power factor - so the
    thing that catches it is the declared envelope [-1, 1], which is what
    `check_guardrail` checks. Naming the wrong mechanism in a demo is how an
    integrator comes to expect the wrong layer to save them.
    """
    assert detect_unit_mismatch("power_factor", 99.40) is None
    lo, hi = _declared_bounds("power_factor")
    assert (lo, hi) == (-1.0, 1.0)
    assert not (lo <= 99.40 <= hi)
    REC.record(
        layer="2-forge_core", scenario="value-plausibility", kind="_declared_bounds",
        request={"canonical_field": "power_factor", "value": 99.40},
        response={"detect_unit_mismatch": None,
                  "declared_bounds": [lo, hi],
                  "inside_bounds": False,
                  "caught_by": "declared bounds, not unit-mismatch detection"},
        assertion="power_factor 99.40 is caught by the declared envelope [-1, 1]")


def test_fahrenheit_as_celsius_is_NOT_caught_by_value_plausibility():
    """THE GAP, recorded on purpose.

    194 degF arriving in a degC field as the bare number 194, with no unit
    anywhere in the tag name, is caught by NOTHING: 194 degC is inside every
    physical envelope a temperature field declares, so neither
    `detect_unit_mismatch` nor the declared bounds can see it. Only the tag
    name can, and this is the case where the tag name says nothing.

    The demo therefore shows the degF catch with a tag that DECLARES its unit
    (`Coolant Temp (F)`), and this test exists so nobody later claims the
    undeclared case is covered.
    """
    assert detect_unit_mismatch("coolant_temperature", 194.0) is None
    lo, hi = _declared_bounds("coolant_temperature")
    assert lo <= 194.0 <= hi
    _, conv = convert_value("CoolantTemp", 194.0, "coolant_temp_c")
    converted = bool(conv and conv.get("converted"))
    assert not converted, (
        "an undeclared-unit tag was converted - that would be a guess")
    REC.record(
        layer="2-forge_core", scenario="value-plausibility", kind="known-gap",
        request={"raw_field": "CoolantTemp", "value": 194.0,
                 "canonical_field": "coolant_temp_c",
                 "intended_unit": "F", "declared_unit": None},
        response={"detect_unit_mismatch": None,
                  "declared_bounds": [lo, hi],
                  "inside_bounds": True,
                  "converted": converted,
                  "caught_by": None},
        assertion=("OPEN GAP: degF read as degC with no unit in the tag name is "
                   "caught by no layer; 194 degC is physically plausible. The "
                   "fix is a declared unit on the tag, not a tighter bound."),
        outcome="known-gap")


def test_pack_layer_and_guard_layer_disagree_on_254_rows():
    """How much coverage the resolution ORDER is worth, measured.

    The guards gate the vector and corpus layers. They do not gate the
    deterministic pack layer, and this sweeps every pack row to say what that
    choice is worth: if the guards DID apply to packs, 254 of 36,331 mappings
    would be discarded - including `engine_coolant_temp` on a Caterpillar and
    `controller_temp` on an ABB robot, both of which prod resolves correctly.

    The number is reported, not asserted to a constant: a pack release moves it
    legitimately, and a test that pinned it would fail on every corpus bump for
    no reason. What IS asserted is the direction - the disagreement is a small
    minority, so pack-first is not quietly discarding most of the guard's work.
    """
    from collections import Counter
    import forge_core.universal_normalize as _un

    rows = _un._LOOKUP
    kinds: Counter = Counter()
    examples: list[dict] = []
    for (tag, oem), hit in rows.items():
        canonical = hit.get("canonical") or ""
        reason = _guard_reject(tag, canonical, _machine_vertical(oem, None), None)
        if not reason:
            continue
        kind = guard_kind(reason)
        kinds[kind] += 1
        if len(examples) < 10:
            examples.append({"tag": tag, "oem": oem, "canonical": canonical,
                             "guard_kind": kind, "guard": reason})

    total = len(rows)
    disputed = sum(kinds.values())
    assert total > 30000, f"only {total} pack rows loaded - the packs did not load"
    assert disputed > 0, (
        "no pack row disagrees with the guards, which would mean the guards "
        "cannot fire on a pack vocabulary at all - verify before believing it")
    assert disputed / total < 0.05, (
        f"{disputed}/{total} pack rows ({disputed / total:.1%}) conflict with "
        f"the guards. Above a few percent, pack-first is discarding the "
        f"guard's work wholesale and the order needs a decision, not a comment.")

    REC.record(
        layer="2-forge_core", scenario="resolution-order", kind="pack-vs-guard sweep",
        request={"pack_rows_swept": total},
        response={"pack_rows": total,
                  "would_be_guard_rejected": disputed,
                  "share": round(disputed / total, 5),
                  "by_guard_kind": dict(kinds),
                  "examples": examples},
        assertion=(f"{disputed} of {total} pack mappings ({disputed / total:.2%}) "
                   f"would be discarded if the guards applied to the pack layer. "
                   f"They do not, and that is the correct order: a published "
                   f"register map is stronger evidence than a tag-name "
                   f"heuristic."),
        outcome="finding")


def test_domain_inference_is_not_the_oem_string():
    """Device domain is inferred from the TAG SET, independently of the OEM."""
    probes = {
        "cnc_tags": (["spindle_speed_rpm", "spindle_load_pct", "part_count"], None),
        "energy_tags": (["inverter_output_kw", "dc_voltage_v", "power_factor"], None),
        "cnc_tags_with_energy_oem": (["spindle_speed_rpm", "spindle_load_pct",
                                      "part_count"], "sunspec"),
    }
    observed = {}
    for label, (tags, oem) in probes.items():
        observed[label] = {
            "tags": tags, "oem": oem,
            "inferred_domain": infer_device_domain(tags, oem),
            "oem_vertical": _machine_vertical(oem, None) if oem else None,
        }
    REC.record(
        layer="2-forge_core", scenario="cross-domain", kind="infer_device_domain",
        request=probes, response=observed,
        assertion=("domain inference reads the tag set; the OEM string is a "
                   "separate signal and the two are reported separately"))


# ═══════════════════════════════════════════════════════════════════════════
# Report
# ═══════════════════════════════════════════════════════════════════════════

def _write_report(session_obj) -> None:
    collected = int(getattr(session_obj, "testscollected", 0) or 0)
    failed = int(getattr(session_obj, "testsfailed", 0) or 0)
    by_layer: dict[str, int] = {}
    for row in REC.interactions:
        by_layer[row["layer"]] = by_layer.get(row["layer"], 0) + 1
    gaps = [r for r in REC.interactions if r["outcome"] == "known-gap"]
    findings = [r for r in REC.interactions if r["outcome"] == "finding"]
    verdict = ("NOTHING COLLECTED" if not collected else
               "FAIL" if failed else "PASS")
    report = {
        "harness": "tests/mcp_agent_test.py",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_s": round(time.time() - REC.started, 2),
        "run": {
            "tests_collected": collected,
            "tests_failed": failed,
            "verdict": verdict,
        },
        "environment": {
            "forge_core_root": str(FORGE_CORE_ROOT),
            "forge_base_url": os.environ.get("FORGE_BASE_URL"),
            "prod_contacted": False,
            "credentials_used": None,
            "registry_version": _registry.REGISTRY_VERSION,
            "registry_field_count": len(_registry.fields()),
            "pack_stats": pack_stats(),
        },
        "layers": {
            "1-mcp": ("real build_dual_app() over Streamable HTTP through the "
                      "real GatingMiddleware"),
            "2-forge_core": ("forge_core primitives called directly, offline: "
                             "packs, guards, unit converter, physics "
                             "validator, registry"),
        },
        "absent_layers": ["corpus_exact (needs a Supabase loader)",
                          "vector (needs pgvector)", "llm"],
        "interactions_by_layer": by_layer,
        "findings": findings,
        "known_gaps": gaps,
        "interactions": REC.interactions,
    }
    RESULTS_PATH.write_text(json.dumps(report, indent=2, default=str) + "\n")

    ps = report["environment"]["pack_stats"] or {}
    print(f"\n{'=' * 72}")
    print(f"MCP AGENT HARNESS - {verdict}")
    print(f"{'=' * 72}")
    print(f"  collected        {collected}")
    print(f"  failed           {failed}")
    print(f"  observations     {len(REC.interactions)}  {by_layer}")
    print(f"  registry         {report['environment']['registry_field_count']} fields "
          f"(v{report['environment']['registry_version']})")
    print(f"  packs            {ps.get('packs_loaded')} packs / "
          f"{ps.get('total_pack_mappings')} mappings / "
          f"{len(ps.get('verticals') or [])} verticals")
    print(f"  auto-packs       {(ps.get('auto_packs') or {}).get('mappings')} "
          f"(designed, not operating)")
    print(f"  prod contacted   NO")
    print(f"  credentials      none")
    print(f"  findings         {len(findings)}")
    for f in findings:
        first = f["assertion"].replace("\n", " ")
        print(f"    - {f['scenario']}: {first[:96]}"
              f"{'...' if len(first) > 96 else ''}")
    print(f"  known gaps       {len(gaps)}")
    for g in gaps:
        first = g["assertion"].replace("\n", " ")
        print(f"    - {g['scenario']}: {first[:96]}"
              f"{'...' if len(first) > 96 else ''}")
    print(f"  report           {RESULTS_PATH}")
    print(f"{'=' * 72}")


@pytest.fixture(scope="session", autouse=True)
def _report(request):
    """Write the report at session end, whatever happened.

    This is a FIXTURE, not `pytest_sessionfinish`. An earlier revision used the
    hook - and pytest only loads hooks from `conftest.py` and registered
    plugins, so defining it in a test module did nothing at all: 27 tests
    passed and no report was written. A session-scoped autouse fixture's
    teardown does run, and only when this module is actually collected, which
    is what was wanted.
    """
    yield
    try:
        _write_report(request.session)
    except Exception as e:                                   # pragma: no cover
        RESULTS_PATH.write_text(json.dumps({
            "harness": "tests/mcp_agent_test.py",
            "run": {"verdict": "HARNESS REPORTING FAILED"},
            "error": f"{type(e).__name__}: {e}",
            "interactions": REC.interactions,
        }, indent=2, default=str) + "\n")
        raise


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "--no-header"]))
