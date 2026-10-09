"""Which REST endpoint each MCP tool actually calls, read from the code.

Extracted statically from `mcp_server.py`: for every `@mcp.tool` function, every
`_call_forge` / `_call_forge_raw` call site inside it, with its method literal
and its path (f-string segments collapsed to `{}`). Reading the call sites means
the map cannot drift from the proxy the way a hand-written table would — which
matters, because the whole point of the parity test is that two hand-maintained
lists disagreed.
"""
from __future__ import annotations

import ast
import pathlib

CALLERS = {"_call_forge", "_call_forge_raw"}


def _path_of(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        out = []
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                out.append(part.value)
            else:
                out.append("{}")
        return "".join(out)
    return None


def _is_tool(fn: ast.AST) -> bool:
    for d in getattr(fn, "decorator_list", []):
        if isinstance(d, ast.Attribute) and d.attr == "tool":
            return True
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr == "tool":
            return True
    return False


def routes(server_py: pathlib.Path | None = None) -> dict:
    """{tool_name: [(method, path), ...]} — may be empty for a tool that makes
    no kernel call (none do today; the parity test asserts that)."""
    server_py = server_py or (pathlib.Path(__file__).resolve().parents[1] / "mcp_server.py")
    tree = ast.parse(server_py.read_text())
    out: dict = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        if not _is_tool(node):
            continue
        calls = []
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            fn = sub.func
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", None)
            if name not in CALLERS or len(sub.args) < 2:
                continue
            method = sub.args[0].value if isinstance(sub.args[0], ast.Constant) else None
            path = _path_of(sub.args[1])
            if method and path:
                calls.append((method, path))
            elif isinstance(sub.args[1], ast.Name):
                # A path chosen from a dict at runtime (shift_report does this).
                calls.append((method or "GET", "@dynamic"))
        if calls:
            out[node.name] = calls
    return out


# Paths a tool selects at runtime from a literal dict. Listed here with the
# full set of possibilities, so the parity test covers every branch rather
# than skipping the tool. Asserted complete by the parity test.
DYNAMIC = {
    "shift_report": [("GET", "/v1/reports/shift/current"),
                     ("GET", "/v1/reports/shift/last"),
                     ("GET", "/v1/reports/shift/recent")],
}


def resolved_routes() -> dict:
    r = routes()
    for tool, calls in list(r.items()):
        if any(p == "@dynamic" for _, p in calls):
            assert tool in DYNAMIC, (
                f"{tool} builds its path at runtime and is not in toolroutes.DYNAMIC; "
                f"the parity measurement would silently skip it")
            r[tool] = [c for c in calls if c[1] != "@dynamic"] + DYNAMIC[tool]
    return r
