"""Two tool descriptions told an agent something the kernel does not do.

Both found in an outside-in integrator eval against prod on 2026-10-15, by
reading the descriptions as a first-time agent would and then checking the
equivalent REST route.

check_guardrail
    Its example claimed {"spindle_speed_rpm": 13000} returns
        {"would_block": true, "guardrail": "Spindle overspeed protection",
         "reason": "spindle_speed_rpm 13000 > limit 12000"}
    On a freshly provisioned machine the real answer is the opposite:
        {"would_block": false, "guardrail": null, "violations": [],
         "guardrails_evaluated": 0,
         "declared_bounds": {"spindle_speed_rpm": [-50000.0, 50000.0]}}
    Guardrails are opt-in per machine and a new machine has none
    (GET /v1/guardrails -> {"count": 0}), so the only net is a registry-wide
    physical envelope of +/-50000 rpm. The description read as though Forge
    knows machine limits out of the box; it knows canonical-field possibility
    ranges. An agent trusting `would_block: false` as "safe" would command
    13000 rpm on a VF-2SS.

get_coverage
    Named "CNC / robot / vehicle / AMR" as THE recognized verticals -- four of
    twenty, omitting even `printer`, which has been in the published list all
    along, and the whole `energy` vertical, which is fully gated with 30+
    working OEM strings. An agent reading it would conclude Forge does not do
    solar, geothermal, water, mining, pharma, HVAC or data centre assets, all
    of which ship packs.

The fix in both cases is to stop restating the kernel's answer. The guardrail
description now explains the two layers and what `guardrails_evaluated: 0`
means; the coverage description names the RESPONSE KEYS and tells the agent to
read them.
"""
from __future__ import annotations

import inspect

import mcp_server


def _doc(name: str) -> str:
    fn = getattr(mcp_server, name)
    fn = getattr(fn, "fn", fn)          # unwrap FastMCP's tool wrapper
    return inspect.getdoc(fn) or ""


# ── check_guardrail ─────────────────────────────────────────────────────────

def test_check_guardrail_does_not_promise_a_block_it_will_not_deliver():
    doc = _doc("check_guardrail")
    assert "guardrails_evaluated" in doc, (
        "an agent cannot tell an empty envelope from a satisfied one without it")
    assert "OPT-IN" in doc or "opt-in" in doc, (
        "the description must say guardrails are per-machine and may not exist")
    assert "DO NOT read it as" in doc, (
        "would_block: false on an unguarded machine is not permission")


def test_check_guardrail_names_the_registry_envelope_as_such():
    doc = _doc("check_guardrail")
    assert "-50000" in doc and "50000" in doc, (
        "the +/-50000 rpm envelope is the thing that makes 13000 pass; say it")
    assert "not limits for" in doc or "not limits" in doc


def test_check_guardrail_still_documents_the_real_block_shape():
    """The corrected description must not lose the useful half."""
    doc = _doc("check_guardrail")
    assert '"would_block": true' in doc
    assert "Spindle overspeed protection" in doc
    assert "dry run" in doc
    assert "writes nothing" in doc


def test_check_guardrail_documents_the_fail_closed_unresolvable_path():
    doc = _doc("check_guardrail")
    assert "unresolvable_fields" in doc
    assert "REFUSED" in doc or "refused" in doc


# ── get_coverage ────────────────────────────────────────────────────────────

def test_get_coverage_no_longer_enumerates_four_of_twenty_verticals():
    """The phrase may still appear -- the corrected docstring quotes it to
    explain what was wrong -- but only as history, never as the live claim."""
    doc = _doc("get_coverage")
    assert "used to name" in doc, (
        "if the old list is quoted it must be marked as the former claim")
    assert "READ THE RESPONSE" in doc, (
        "the agent must be told to read the kernel's answer, not this text")
    # And it must not be offered as the answer in the opening sentence.
    opening = doc.split("\n\n", 1)[0]
    assert "CNC / robot / vehicle / AMR" not in opening
    assert "CNC/robot/vehicle/AMR" not in opening


def test_get_coverage_points_at_the_response_keys_instead():
    doc = _doc("get_coverage")
    for key in ("vertical_oems", "verticals_without_oem_routing",
                "canonical_families", "vertical_packs"):
        assert key in doc, f"{key} is what the agent should read; name it"


def test_get_coverage_explains_what_an_unrecognized_oem_costs():
    """"Soft signal" was true but incomplete: with no gate, candidates from
    every vertical compete on cosine alone."""
    doc = _doc("get_coverage")
    assert "soft signal" in doc
    assert "not a free one" in doc or "cosine" in doc


# ── the tool catalogue blurb repeated the same claim ───────────────────────

def test_the_tool_catalogue_blurb_is_corrected_too():
    src = inspect.getsource(mcp_server)
    assert "recognized OEM verticals (CNC/robot/vehicle/AMR)" not in src, (
        "the catalogue entry still names four verticals")
