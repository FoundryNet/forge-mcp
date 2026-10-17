# forge-mcp — HANDOFF

Repo: `github.com/FoundryNet/forge-mcp` · Railway service `162115b7-b420-4a02-8cff-ddad7be02dc2`
(`foundrynet-mcp`) · public endpoint `mcp.foundrynet.io/mcp` (Streamable HTTP, 32 tools, v3.4.4).

Deploy: **`cd ~/forge-mcp && git fetch origin && git checkout main && git pull --ff-only && ./deploy.sh`**

**⚠ CORRECTED 2026-10-16.** The line above used to read `railway up --service
162115b7-…` with the note "this repo has no deploy script and no build stamp, so
nothing can prove afterwards which commit is serving". **Both halves were false
when written.** `deploy.sh` and `stamp_build.py` landed on 2026-10-09 in #5 and
#7; the stamp is live on `mcp.foundrynet.io/health` under the same key names
forge-prod uses, and the script refuses a dirty tree, the wrong branch, a red
release gate and a wrong archive root, stamps before uploading, passes
`--service` explicitly, then polls `/health` until `commit_short` AND
`content_hash` match the stamp. A deploy here IS verifiable; use the script.
The claim had also reached the global CLAUDE.md, which is corrected too.

**That gap is CLOSED. Deployed 2026-10-17T01:00Z.** `/health` serves
`3269283`, `content_hash=sha256:3b87ff90fbe96716ada…`, `status=ok`, 32 tools,
36 files — verified by `deploy.sh`'s own poll and again by hand afterwards. It
had been serving `96f2b86` since 2026-10-09, so #9's tool-description
corrections and #10's harness are live for the first time. The local release
gate ran on the uploaded bytes before the upload: clean tree, deps in their
pins, imports with no env, 268/268 behavioural, version 3.4.4 agreeing across
`mcp_server.py` and `server.json`. Check `/health` before
assuming any merge here is serving.

---

## 2026-10-16 — agent integration harness

| item | status | files | deployed | verified |
|---|---|---|---|---|
| MCP agent test harness | **built, green** | `tests/mcp_agent_test.py` | n/a (test only) | 27/27 locally |
| Structured results | **written** | `tests/mcp_agent_results.json` | n/a | regenerated each run |
| Demo sequence | **written** | `docs/mcp_demo_sequence.md` | n/a | every value traced to the JSON |
| Full suite regression | **clean** | — | n/a | 268 passed, exit 0, 174s |

Local only. Nothing committed, nothing pushed, nothing deployed. **Prod was
never contacted and no credential was read** — `FORGE_BASE_URL` is
`https://forge.test.invalid` throughout and the upstream socket is an
`httpx.MockTransport`.

### What it measures

Two layers, because forge-mcp is a proxy that owns no resolution logic:

* **Layer 1 (this repo)** — the real `build_dual_app()` over real Streamable
  HTTP through the real `GatingMiddleware`, via `tests/mcp_client.py`. Tool
  surface, tiering, argument contracts, upstream routing, error shaping.
* **Layer 2 (forge-prod's `forge_core`)** — `deterministic_lookup`,
  `_apply_guards`, `explain_guard`, `unit_converter`, `physics_validator`,
  `guardrails`, `field_registry`, called directly and offline. 36,331 pack
  lookups / 46 packs / 20 verticals load from vendored JSON with no network.
* **The bridge** — `ForgeLocal` serves Layer 2 to Layer 1 over the upstream
  seam `tests/conftest.py` already installs, so a tool called *through MCP*
  returns a resolution computed by real kernel code.

`tests/mcp_agent_test.py` is pytest-collectable (`*_test.py`) and also runs as
`python3 tests/mcp_agent_test.py`. It writes its report from a session-scoped
autouse fixture, so a run that collects zero says `NOTHING COLLECTED` in the
file rather than leaving the last green one looking current.

### Machine-local dependency, declared

Layer 2 needs forge-prod's `forge_core` on disk. `_require_forge_core()` looks
at `$FORGE_CORE_PATH`, then `~/forge-prod`, then a sibling checkout, and
**raises at collection** naming every path it tried and the clone command. It
does not skip: a pass with Layer 2 absent would measure nothing and read as a
pass. Verified by running with `FORGE_CORE_PATH=/nonexistent HOME=/nonexistent`
— collection errors with the full message.

---

## Findings

### 1. The work order named two tools that do not exist

`resolve_tag` and `explain_guard` are not on the MCP surface.

* Tag resolution is `normalize_telemetry`, which takes a whole `data` dict.
* `explain_guard` is a function in `forge_core/guards.py`; its sentence is
  emitted **inside** a normalize response, per field. An agent reads it and
  cannot call it.

`test_work_order_tool_names` asserts both are absent, so if either is ever
added the test fails and the demo script gets corrected rather than the doc
quietly describing a surface no agent can reach.

The brief also called the guards "physics gates" and gave three examples that
belong to **three different layers**. Each now has its own test named for its
mechanism:

1. **Mapping guards** (`guards.py`, 5 kinds) refuse a bad canonical *choice*;
   four of five fire before any value is read.
2. **Unit conversion** (`unit_converter.py`) converts when the *tag name*
   declares a unit — this is what catches the °F and psi examples.
3. **Value plausibility** (`detect_unit_mismatch`, declared bounds) catches a
   magnitude that cannot be the declared unit — this is what catches
   `power_factor` 99.40.

### 2. A pack SCOPE name is not an OEM ROUTING name — the gate disables silently

`sunspec`, `sunspec_storage`, `abb_robot` and `haas_ngc` all resolve tags from
their own packs and all four route to `vertical: null`, so the cross-vertical
gate **disables** for them. `solaredge` and `haas` route fine.

So the gate is off for exactly the strings an integrator is most likely to
pass — the name of the standard their device speaks. With no gate, candidate
canonicals from every vertical compete on cosine alone, which is the mechanism
behind the geothermal brine inlet temperature reaching for
`vehicle.air_inlet_temp`. Same shape as the geothermal integrator who guessed
four vendor names and got `vertical: null` for all four.

Routing measured: `siemens`→cnc, `haas`→cnc, `solaredge`→energy,
`caterpillar`→vehicle, `kuka`→robot, `prusa`→printer. 7 routed verticals, 124
OEM strings; 12 pack verticals have no routing at all (`chemical`,
`cold_chain`, `condition_monitoring`, `data_center`, `food_beverage`, `hvac`,
`logistics`, `mining`, `pharma`, `pump`, `ups`, `water`), which `/v1/coverage`
does say out loud under `verticals_without_oem_routing`.

**Fixed in forge-prod, not here** — `guards._pack_route_map()` now derives
routing from what the packs declare, so all four route (`sunspec` and
`sunspec_storage` → energy, `abb_robot` → robot, `haas_ngc` → cnc) along with
154 other scopes. Routed OEM strings went 124 → 282.

`test_cross_domain_inference` deliberately does **not** pin the defect: it
records whatever those scopes resolve to and asserts only the invariant that
holds either way — a scope that routes must route to a real vertical with the
gate ACTIVE, one that does not must say so explicitly. Verified green against
both forge-prod `a14857b` (unrouted) and the fix (routed). The results JSON
carries `environment.forge_core_revision`, so a snapshot can be told from a
stale one.

### 3. Mapping guards do not apply to the pack layer, and that is worth 254 rows

`_apply_guards` is called from exactly two places in forge-prod:
`normalize_engine.py:325` (vector candidates) and
`kernel/engine.py::_corpus_resolves` (pulled corpus rows). A deterministic pack
hit passes through neither.

An early revision of this harness guarded pack hits and reported
`controller_temp` (abb_robot) and `engine_coolant_temp` (caterpillar) as
rejected — two mappings prod resolves correctly. Sweeping all 36,331 pack rows:
**254 (0.70%) would be discarded** that way — 186 by the vertical guard, 68 by
`no_canonical`. Pack-first is the correct order; a published register map is
stronger evidence than a tag-name heuristic.

`test_pack_layer_and_guard_layer_disagree_on_254_rows` reports the number and
asserts only the *direction* (< 5%), so a legitimate pack release does not fail
CI for no reason.

### 4. OPEN GAP — °F read as °C with no unit in the tag name is caught by nothing

```
"CoolantTemp": 194.0   (intended °F, no unit anywhere in the name)
  detect_unit_mismatch("coolant_temperature", 194.0) -> None
  declared bounds (-273.15, 3000.0)                  -> 194 is inside
  convert_value("CoolantTemp", 194.0, "coolant_temp_c") -> not converted
  caught_by: NOTHING
```

194 °C is physically plausible for a coolant sensor's envelope, so no value
layer can see it. Only the tag name can, and this is the case where the tag
name says nothing. **The fix is a declared unit on the tag, not a tighter
bound** — tightening the bound would reject real high-temperature readings.

Recorded under `known_gaps` in the results JSON and shown deliberately as Beat
7 of the demo. Beat 5 therefore uses `Coolant Temp (F)`, which *does* declare
its unit and *is* converted (194.0 → 90.0).

Related and already known: `detect_unit_mismatch` only looks at `200 < value
<= 1000` for temperature fields, so a °F reading between 100 and 200 — most of
the useful range for coolant and ambient — is outside its window by
construction.

### 5. A harness that could not report its own result (fixed before shipping)

The report was first written from `pytest_sessionfinish` defined in the test
module. pytest only loads hooks from `conftest.py` and registered plugins, so
it did nothing at all: **27 tests passed and no report file was written.** Now
a session-scoped autouse fixture, whose teardown does run and only when this
module is collected. Noted because it is the exact failure mode the standing
rule describes — a harness that cannot report its own failure is worse than no
harness.

---

## Counts this run measured

| number | what it measures |
|---|---|
| **1,016** | fields in the registry (`field_registry`, v1.1.0) |
| 282 | families the registry partitions into |
| **46** | vendor packs loaded |
| 2,380 | pack mappings loaded locally (prod reports 2,238 — different tree) |
| **20** | verticals shipping packs |
| 7 / 124 | verticals reachable by an OEM string / OEM strings that route |
| 36,331 | curated pack lookups in `_LOOKUP` (25,367 folded) |
| **0** | auto-pack mappings — self-healing is designed, has never fired |

Asserted in `test_coverage_counts_say_what_they_measure`: 1,016 and 46 and 20
are pinned to constants with a message naming CLAUDE.md, and `auto_packs` is
pinned at 0 so a demo can never drift into describing self-healing as
operating. Corpus-derived keys (`corpus_oem_tags`,
`corpus_mapped_field_count`) come back **null** offline rather than borrowing
the registry's number — the drift that made the live endpoint report 85 and
1,016 in the same breath.

---

## Layers the harness does not reach

Carried in the results JSON under `absent_layers`, and in the demo doc as its
own section, because every resolution in the report comes from a published
register map and that should not be oversold:

| layer | why absent |
|---|---|
| corpus exact/folded | `corpus_index.lookup` needs a Supabase loader |
| vector | `search_schema_mappings` is a pgvector query; cold fields abstain (same stub the edge kernel ships) |
| LLM mapper | needs an API key |
| history / triggers / metering / attestation | need the kernel DB and Stripe |

Consequence: `verify_record` and the attestation close are **not exercised**.
Demo that beat against a real environment or cite forge-prod's own coverage
(`docs/VERIFY_A_FORGE_RECORD.md`, `forge_core/proof_store.py`).

---

## Decisions needed

1. **Routing aliases for pack scope names** (finding 2) — should `sunspec`,
   `sunspec_storage`, `abb_robot`, `haas_ngc` route to
   energy/energy/robot/cnc? Product call, then a forge-prod change to
   `_machine_vertical`.
2. **Commit and push these three files?** Nothing is staged.
3. **CI**: should `tests/mcp_agent_test.py` run in forge-mcp's CI? It needs
   forge-prod checked out alongside, so it would need a second-checkout step
   or it will error at collection by design.
4. **The °F window** (finding 4) — leave `detect_unit_mismatch` as is and rely
   on declared units, or widen the temperature window? Widening trades a real
   catch for false positives on legitimate 100–200 °C readings.

No background processes were left running.
