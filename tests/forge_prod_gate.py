"""forge-prod's REAL free-tier gate, lifted out of its source at test time.

The parity question is "does the free tier mean the same thing over REST and
over MCP". The honest way to answer it is to ask the function forge-prod
actually gates on — `_endpoint_to_billing_meter` — not a hand-copied list of
names. A tool is free on REST by that function returning None for its path; the
`_FREE_TOOL_NAMES` list is only prod's human-readable echo of that, and an echo
is exactly the thing that drifts.

So: parse `forge-prod/api.py`, pull out the gate functions and the two
constants they close over, and execute just those. Nothing else in api.py is
imported — it wants a database, an app and a dozen env vars at import time, and
a parity test that needs prod's runtime is a parity test nobody runs.

If forge-prod is not on this machine the tests that need it SKIP loudly rather
than asserting against a stale copy. Set FORGE_PROD_API to point elsewhere.
"""
from __future__ import annotations

import ast
import os
import pathlib
from typing import Optional

WANTED_FUNCS = ("_path_to_meter", "_endpoint_to_billing_meter",
                "_sandbox_may_call", "_is_paid_for_metered")
WANTED_NAMES = ("_METER_EXACT_POST", "_FREE_TOOL_NAMES", "_SANDBOX_FREE_METERS",
                "_SANDBOX_FREE_TOOL_NAMES", "TOOL_COSTS")


def api_path() -> Optional[pathlib.Path]:
    p = os.environ.get("FORGE_PROD_API")
    cands = [pathlib.Path(p)] if p else []
    cands += [pathlib.Path.home() / "forge-prod" / "api.py"]
    for c in cands:
        if c.is_file():
            return c
    return None


class ForgeProdGate:
    """The extracted gate, plus provenance so a failure says where it came from."""

    def __init__(self, ns: dict, source: pathlib.Path, extracted: list):
        self._ns = ns
        self.source = source
        self.extracted = extracted

    def meter_for(self, method: str, path: str) -> Optional[str]:
        return self._ns["_endpoint_to_billing_meter"](method, path)

    def is_free_on_rest(self, method: str, path: str) -> bool:
        """Free to EVERY key: no meter at all, so no Stripe event and no 402."""
        return self.meter_for(method, path) is None

    def sandbox_may_call(self, method: str, path: str) -> bool:
        """What a cardless sandbox key may call: unmetered, or a meter on the
        sandbox allow-list (`normalize_call`)."""
        return self.is_free_on_rest(method, path) or self._ns["_sandbox_may_call"](method, path)

    @property
    def free_tool_names(self) -> list:
        return list(self._ns["_FREE_TOOL_NAMES"])

    @property
    def sandbox_free_tool_names(self) -> list:
        return list(self._ns["_SANDBOX_FREE_TOOL_NAMES"])

    @property
    def tool_costs(self) -> dict:
        return dict(self._ns["TOOL_COSTS"])


def load() -> Optional[ForgeProdGate]:
    src = api_path()
    if src is None:
        return None
    tree = ast.parse(src.read_text())
    keep: list = []
    found: list = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in WANTED_FUNCS:
            keep.append(node)
            found.append(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id in WANTED_NAMES:
                    keep.append(node)
                    found.append(t.id)
    missing = [n for n in WANTED_FUNCS + WANTED_NAMES if n not in found]
    if missing:
        raise AssertionError(
            f"forge-prod's gate no longer exposes {missing} at module level in "
            f"{src}. The parity test is measuring the wrong thing until this is "
            f"updated — fix it, do not delete it.")
    # Dependency order is source order, which is also definition order in api.py.
    mod = ast.Module(body=keep, type_ignores=[])
    ast.fix_missing_locations(mod)
    ns: dict = {"Optional": Optional}
    exec(compile(mod, str(src), "exec"), ns)  # noqa: S102 — our own source, read-only
    return ForgeProdGate(ns, src, found)
