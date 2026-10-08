"""Minimal valid arguments for every tool, so the whole surface can be swept.

Derived from the live registry's `required` lists (see
`test_tool_surface.test_every_tool_has_sweep_arguments`, which fails if a tool
is added, renamed, or gains a required argument and nobody updated this file).
A sweep that silently skips tools is how a surface comes to be "fully tested"
with a third of it never called.
"""
from __future__ import annotations

TS = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]

ARGS: dict[str, dict] = {
    "activate_automation": {"machine_id": "m-1", "name": "n", "condition": {"field": "spindle_load_pct", "op": ">", "value": 80},
                            "actions": [{"type": "webhook", "url": "https://x.invalid"}]},
    "calculate_oee": {"machine_id": "m-1"},
    "check_guardrail": {"machine_id": "m-1", "proposed": {"spindle_speed_rpm": 1000}},
    "correct_mapping": {"source_field": "sf", "confirmed_canonical": "cc",
                        "original_canonical": "oc"},
    "create_automation": {"mint_id": "m-1", "instruction": "do a thing"},
    "delete_automation": {"trigger_id": "t-1"},
    "detect_anomalies": {"values": TS},
    "diagnose_machine": {"machine_id": "m-1"},
    "disable_automation": {"trigger_id": "t-1"},
    "energy_consumption": {"machine_id": "m-1"},
    "fire_sandbox": {"condition_text": "temp > 80"},
    "fleet_health": {"machines": [{"machine_id": "m-1"}]},
    "fleet_oee": {},
    "get_agent_card": {},
    "get_coverage": {},
    "health_index": {"machine_id": "m-1"},
    "identify_machine": {"oem": "haas", "model": "VF-2", "serial": "s-1"},
    "list_agents": {},
    "list_automations": {"machine_id": "m-1"},
    "list_guardrails": {"machine_id": "m-1"},
    "machine_intelligence": {"machine_id": "m-1", "telemetry": {"spindle_load_pct": 50}},
    "normalize_telemetry": {"data": {"SpindleSpeed": 1200}},
    "predict": {"time_series": TS},
    "predict_batch": {"machines": [{"machine_id": "m-1", "time_series": TS}]},
    "predict_breach": {"time_series": TS, "threshold": 100.0},
    "prediction_accuracy": {},
    "query_machine_history": {"mint_id": "m-1"},
    "query_webhook_history": {"trigger_id": "t-1"},
    "remaining_life": {"time_series": TS, "failure_threshold": 100.0},
    "restore_automation": {"trigger_id": "t-1"},
    "shift_report": {},
    "verify_record": {"payload": {"action": "test", "result": "ok"}},
}
