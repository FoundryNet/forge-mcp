# Forge MCP — agent demo sequence

The exact calls an agent makes to show what Forge does, in order, with the
values each one actually returns. Every number and string below is copied from
`tests/mcp_agent_results.json`, produced by `tests/mcp_agent_test.py`. Re-run
the harness and re-read the report before presenting — nothing here is typed
from memory.

```
pytest tests/mcp_agent_test.py -v -s
```

---

## Before you start: three names that do not exist

The brief this demo was scoped from named tools that are not on the surface.
Say the right ones on camera.

| asked for | reality |
|---|---|
| `resolve_tag` | **Not a tool.** Resolution is `normalize_telemetry`, which takes a whole `data` dict, not one tag. |
| `explain_guard` | **Not a tool.** It is a function in `forge_core/guards.py`; its sentence is emitted *inside* a normalize response, per field. An agent reads it, it cannot call it. |
| `get_coverage` | Real, and the one that does pre-flight. |

`test_work_order_tool_names` asserts the first two are absent, so this table
cannot quietly go stale.

And the three things people call "the physics gate" are **three different
layers**. Naming the wrong one is how an integrator comes to expect a catch
that cannot happen:

1. **Mapping guards** (`guards.py`, 5 kinds) — refuse a bad *canonical choice*.
   Four of the five fire before any value is looked at.
2. **Unit conversion** (`unit_converter.py`) — converts when the *tag name*
   declares a unit. This is what catches °F and psi.
3. **Value plausibility** (`physics_validator.detect_unit_mismatch`, and the
   declared-bounds check in `check_guardrail`) — catches a *magnitude* that
   cannot be the declared unit. This is what catches `power_factor` 99.40.

---

## Beat 1 — pre-flight: ask what Forge knows before sending anything

```
get_coverage()
```

| key | value | what it measures |
|---|---|---|
| `canonical_field_count` | **1,016** | fields in the **registry** |
| `family_count` | 282 | families the registry partitions into |
| `vertical_packs.packs_loaded` | **46** | vendor packs |
| `vertical_packs.total_pack_mappings` | 2,380 | raw-tag → canonical rows in those packs |
| `vertical_packs.verticals` | **20** | verticals shipping packs |
| `vertical_oems` | 7 routed verticals, 124 OEM strings | OEM strings that route to a vertical |
| `verticals_without_oem_routing` | **12** | packs with no OEM string to pass |
| `corpus_oem_tags` | `null` offline | computed *from* the corpus table |

The 12 unrouted verticals are named in the response, not left as an
absence: `chemical`, `cold_chain`, `condition_monitoring`, `data_center`,
`food_beverage`, `hvac`, `logistics`, `mining`, `pharma`, `pump`, `ups`,
`water`. They ship packs; there is no OEM string to pass, so the
cross-vertical gate cannot engage for them.

**The line that matters:** these are four different numbers measuring four
different things, and the response keeps them under four names. 1,016 is the
registry. It is not the corpus count (16,908 mappings, MIT-public), not the
pack-mapping count (2,380 here), and not deterministic reach. The live endpoint
once reported 85 and 1,016 in the same breath because one of them was counting
corpus rows under the other's name.

Say also: **auto-pack mappings = 0.** Self-healing is designed and available,
and has never fired. `test_coverage_counts_say_what_they_measure` asserts that
zero, so the demo can never drift into describing it as operating.

---

## Beat 2 — happy path: six SunSpec registers an agent has never seen

```
normalize_telemetry(
    oem="sunspec",
    data={"W": 4200.0, "A": 12.4, "PPVphAB": 480.2,
          "Hz": 59.98, "DCV": 742.0, "TmpCab": 41.5})
```

| raw register | canonical | pack unit | registry unit | value in → out |
|---|---|---|---|---|
| `W` | `inverter_output_kw` | W | kW | 4200.0 → **4.2** |
| `A` | `line_current_a` | A | A | 12.4 → 12.4 |
| `PPVphAB` | `ac_voltage_ll_ab` | V | V | 480.2 → 480.2 |
| `Hz` | `grid_frequency_hz` | Hz | Hz | 59.98 → 59.98 |
| `DCV` | `dc_voltage_v` | V | V | 742.0 → 742.0 |
| `TmpCab` | `inverter_cabinet_temp_c` | C | C | 41.5 → 41.5 |

All six at `match_type: "deterministic"`, `confidence: 1.0`, from the published
`sunspec_inverter` register map.

**The line that matters:** `PPVphAB` is not a guessable name. Nothing in it
says "line-to-line voltage, phases A to B" to a model reading it cold, and
`W`/`A`/`Hz` are single letters that most pipelines discard as spreadsheet
noise — the engine has a specific carve-out so a published register map
outranks the noise filter, because those three are among the most important
registers in the solar vocabulary.

**And watch `W`.** 4200 → 4.2. The pack declares the register in watts, the
canonical field is kilowatts, and the conversion happened before storage. The
field *name* is authoritative: a value that lands in `inverter_output_kw` is
kilowatts, or it is a bug.

---

## Beat 3 — a second vendor, same schema, no contamination

```
normalize_telemetry(oem="schneider_ion",
    data={"kw_total": 184.6, "kvar_total": 41.2, "pf_total": 0.976,
          "vll_avg": 480.9, "freq": 59.99})
normalize_telemetry(oem="caterpillar",
    data={"engine_speed": 1420.0, "engine_coolant_temp": 88.0,
          "fuel_level": 54.0, "battery_voltage": 27.8, "ground_speed": 11.4})
```

Schneider's `freq` and SunSpec's `Hz` both land on `grid_frequency_hz`.
Schneider's `kw_total` and SunSpec storage's `W` both land on
`active_power_kw`. Different vendors, different register names, one field the
agent can reason over.

Meanwhile `W` under `oem="sunspec"` is `inverter_output_kw` and `W` under
`oem="sunspec_storage"` is `active_power_kw` — **the same tag, resolved
per-OEM**. `test_multi_vendor_batch_does_not_cross_contaminate` runs six
payloads from five vendors in one session and checks every resolution against
that payload's *own* pack, which is the failure it exists to catch: a shared
index keyed on the tag alone would make `W` mean whichever vendor spoke last.

---

## Beat 4 — the physics catch: a mapping guard refuses, and explains itself

This is the beat that sells the product, so run it on the right mechanism.
A **mapping guard** refuses a *candidate canonical*, not a value.

Send a CNC payload containing `coolant_temp`, where the only candidate the
resolver finds is `vehicle.ambient.air_temp`:

```
guard:      "vertical vehicle!=cnc"
guard_kind: "vertical"
```

and the sentence the agent reads:

> `'coolant_temp'` matched only `'vehicle.ambient.air_temp'`, which belongs to
> the vehicle vertical, and this machine is cnc. Forge refused rather than
> store a cnc reading in a vehicle field. **THIS IS A COVERAGE GAP, NOT A BAD
> READING**: the value is plausible and nothing about it was rejected. The
> reading is returned unchanged under `'coolant_temp'` and no value was altered
> or dropped. If `'coolant_temp'` has an equivalent on the cnc vertical, it is
> not aliased yet — that alias is the fix. If the machine really is vehicle,
> pass the matching `oem` so the right pack is used.

Then the dimension guard, which is the sharper one:

```
wind_speed -> speed_rpm
guard:      "dimension linear_speed!=rotational_speed"
```

> `'wind_speed'` looks like a linear_speed measurement and the only candidate
> `'speed_rpm'` measures rotational_speed. Mapping it would have stored a
> linear_speed value in a rotational_speed field, **which is a silent unit
> error — the kind nothing downstream can detect** — so Forge refused.

**The line that matters:** every branch says the reading was kept. The question
this string exists to answer is "did Forge just lose my data", and the answer is
no — abstaining keeps the raw value under its own name. Four of the five guards
say nothing at all about the value, because they fired on the *mapping*.

All five kinds — `no_canonical`, `vertical`, `dimension`, `subject`, `range` —
fire in `test_all_five_mapping_guards_fire_with_an_actionable_sentence`, which
also asserts each sentence contains "returned unchanged" and is long enough to
act on.

---

## Beat 5 — the unit-corruption catch (mechanism 2, the tag name)

```
"Hydraulic Pressure (psi)": 2900.0  ->  hydraulic_pressure_bar = 199.948
"Coolant Temp (F)":          194.0  ->  coolant_temp_c         =  90.0
"ambient_temp_f":             94.6  ->  ambient_temp_c         =  34.778
```

Each carries `conversion: {from, to, unit_source: "tag", converted: true}`.

**The line that matters:** the third row has no parentheses. A bare `_f`
suffix is a declared unit, and treating it as one is what took coverage on one
real dataset from 16.67% to 36.67% on identical data. The field *name* is
authoritative — convert or flag, never both.

### The honest half of this beat

```
"PowerFactor": 99.40  ->  power_factor = 99.40
                          flag: "unit_undetermined"
```

Not converted. `power_factor` expects a unit, neither the tag nor the pack
declared one, so the value is stored unchanged **and flagged**. Forge does not
convert on a guess.

---

## Beat 6 — the value-plausibility catch (mechanism 3, the magnitude)

```
check_guardrail(machine_id=..., proposed={"power_factor": 99.40})
  -> would_block: true
     reason: "power_factor 99.4 is outside the physical envelope
              [-1.0, 1.0] declared for every machine in the fleet"
```

Note which layer caught it: `detect_unit_mismatch("power_factor", 99.40)`
returns **`None`** — there is no plausible source unit for which 99.40 is a
valid power factor — so the thing that fires is the declared envelope, not
unit-mismatch detection. `test_power_factor_99_is_caught_by_declared_bounds`
pins that distinction.

And the magnitude case that *is* a unit mismatch:

```
detect_unit_mismatch("hydraulic_pressure_bar", 2900.0)  ->  199.948
detect_unit_mismatch("hydraulic_pressure_bar",   80.0)  ->  None
```

2900 in a bar field is psi, and the validator says what it would be once
converted.

---

## Beat 7 — the gap, said out loud

Show this. A demo that implies otherwise is worse than one that admits it.

```
"CoolantTemp": 194.0  (intended °F, no unit in the tag name)
  detect_unit_mismatch("coolant_temperature", 194.0) -> None
  declared bounds (-273.15, 3000.0)                  -> 194 is inside
  convert_value("CoolantTemp", 194.0, "coolant_temp_c") -> not converted
  caught_by: NOTHING
```

194 °C is physically plausible for a coolant sensor's envelope, so no value
layer can see it. **Only the tag name can, and this is the case where the tag
name says nothing.** The fix is a declared unit on the tag, not a tighter
bound — tightening the bound would reject real high-temperature readings.

`test_fahrenheit_as_celsius_is_NOT_caught_by_value_plausibility` records this
as a known gap in the report, so nobody later claims it is covered. It is the
reason Beat 5 uses `Coolant Temp (F)` and not `CoolantTemp`.

---

## Beat 8 — cross-domain: the OEM string is not the vertical

```
get_coverage(oem="siemens")      -> vertical: "cnc",     gate: active
get_coverage(oem="solaredge")    -> vertical: "energy",  gate: active
get_coverage(oem="caterpillar")  -> vertical: "vehicle", gate: active
get_coverage(oem="kuka")         -> vertical: "robot",   gate: active
get_coverage(oem="prusa")        -> vertical: "printer", gate: active
get_coverage(oem="nonsense")     -> vertical: null,      gate: inactive
```

Siemens is **cnc**, not energy. The canonical namespace does the work, and an
unrecognized OEM returns `vertical: null` with an explicitly inactive gate
rather than a guess — normalize still runs, but the cross-vertical gate cannot
engage, so candidates from every vertical compete on cosine alone. That is how
a geothermal brine inlet temperature once reached for `vehicle.air_inlet_temp`.

### Finding to disclose, not hide

**A pack SCOPE name is not an OEM ROUTING name.** These four resolve tags from
their packs and route to `vertical: null`:

```
sunspec, sunspec_storage, abb_robot, haas_ngc
```

`solaredge` and `haas` route fine. So the gate disables for exactly the strings
an integrator is most likely to type — the name of the standard their device
speaks. Same shape as the geothermal integrator who guessed four vendor names
and got `vertical: null` for all four. Recorded as a finding in the report.

---

## Beat 9 — abstention: what happens when Forge does not know

```
normalize_telemetry(oem="no_such_vendor", data={"Weird_Vendor_Tag_01": 7.0})
  -> match_type: "unknown", confidence: 0.0
     canonical_data: {"Weird_Vendor_Tag_01": 7.0}   # the raw value, kept
```

Never force-mapped. `fields_unknown` counts it, the reading survives under its
own name, and the agent can see the difference between "Forge mapped this" and
"Forge declined to guess". `normalize_telemetry` with `data` as a *list* is
refused outright rather than coerced.

---

## Beat 10 — the attestation close

Not exercised by this harness, and say why rather than skipping it silently:
`verify_record` writes, and this harness is read-only against a local backend
with no MINT relay. Demo it against a real environment, or state that the proof
path is covered by forge-prod's own suite (`docs/VERIFY_A_FORGE_RECORD.md`,
`forge_core/proof_store.py`).

---

## What the harness does *not* reach

State these if asked. Each is a real prod layer this offline run cannot
exercise, and the results JSON carries the same list under `absent_layers`:

| layer | why absent | consequence for the demo |
|---|---|---|
| corpus exact/folded | `corpus_index.lookup` needs a Supabase loader | the 16,908-mapping corpus is not consulted; resolution is pack-only |
| vector | `search_schema_mappings` is a pgvector query | a cold field abstains — the same stub the edge kernel ships |
| LLM mapper | needs an API key | no Layer-3 self-healing |
| history / triggers / metering / attestation | need the kernel DB and Stripe | `normalize_telemetry` returns a resolution but writes nothing |

So **every resolution in this demo comes from a published register map**, which
is the strongest evidence tier and the least impressive-sounding one. On a live
kernel the corpus and vector layers resolve substantially more. The flip side
is worth saying: these resolutions are deterministic and reproducible, with no
model in the path.

One more measured fact about resolution order: if the mapping guards applied to
the pack layer, **254 of 36,331 pack mappings (0.70%) would be discarded** —
186 by the vertical guard, 68 by `no_canonical`, including
`engine_coolant_temp` on a Caterpillar. They do not apply to packs, and that is
the correct order: a published register map is stronger evidence than a
tag-name heuristic.

---

## Recording checklist

1. `pytest tests/mcp_agent_test.py -v -s` — green, 27 collected, report written.
2. Read `tests/mcp_agent_results.json`; re-check every number you plan to say.
3. Beats 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 in order. 7 is not optional.
4. Say "46 vendor packs across 20 verticals". Never "18 OEM families", never
   "14 protocol adapters" (12 of 15 declared are usable).
5. Say the corpus is **MIT-public** at `github.com/FoundryNet/canonical-schema`.
   The moat is the per-vendor polarity/enum decoder tier, not the mappings.
6. Say self-healing is **available, not operating**. Auto-pack has never fired.
