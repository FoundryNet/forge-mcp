"""A minimal MCP Streamable HTTP client, spoken over ASGI in-process.

Why not FastMCP's own in-memory client: the gating middleware's only input is
the `Authorization` header, which it reads with `get_http_headers()`. An
in-memory client never produces an HTTP request, so the gate would be bypassed
and every auth and tenancy assertion would be vacuous. These tests therefore go
over the real transport — the same POST /mcp a Smithery or Claude Desktop client
makes — with the app mounted on `httpx.ASGITransport`.

Lifespan is entered explicitly: the Streamable HTTP session manager starts in
the app's lifespan, and ASGITransport does not run it.
"""
from __future__ import annotations

import contextlib
import json
from typing import Any, Optional

import httpx

PROTOCOL_VERSION = "2025-06-18"


def _parse(resp: httpx.Response) -> Optional[dict]:
    """A Streamable HTTP reply is either a JSON body or an SSE stream carrying
    one `message` event. Accept both; return the first JSON-RPC envelope."""
    ctype = resp.headers.get("content-type", "")
    body = resp.text
    if "text/event-stream" in ctype:
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                payload = line[5:].strip()
                if payload:
                    return json.loads(payload)
        return None
    if not body.strip():
        return None
    return json.loads(body)


class MCPSession:
    """One MCP session against the in-process app, on one bearer token."""

    def __init__(self, client: httpx.AsyncClient, token: Optional[str],
                 path: str = "/mcp"):
        self._c = client
        self._token = token
        self._path = path
        self._sid: Optional[str] = None
        self._id = 0
        self.initialize_status: Optional[int] = None

    def _headers(self, extra: Optional[dict] = None) -> dict:
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
        }
        if self._token is not None:
            h["Authorization"] = f"Bearer {self._token}"
        if self._sid:
            h["Mcp-Session-Id"] = self._sid
        if extra:
            h.update(extra)
        return h

    async def _post(self, payload: dict) -> httpx.Response:
        return await self._c.post(self._path, json=payload, headers=self._headers())

    async def initialize(self) -> dict:
        self._id += 1
        resp = await self._post({
            "jsonrpc": "2.0", "id": self._id, "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "lane-d-harness", "version": "1"},
            },
        })
        self.initialize_status = resp.status_code
        self._sid = resp.headers.get("mcp-session-id") or resp.headers.get("Mcp-Session-Id")
        env = _parse(resp)
        # The initialized notification is required before tools/call.
        await self._c.post(self._path, json={
            "jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=self._headers())
        return env or {}

    @property
    def session_id(self) -> Optional[str]:
        return self._sid

    async def list_tools(self) -> list:
        self._id += 1
        resp = await self._post({"jsonrpc": "2.0", "id": self._id,
                                 "method": "tools/list", "params": {}})
        env = _parse(resp) or {}
        return (env.get("result") or {}).get("tools") or []

    async def call(self, name: str, arguments: Optional[dict] = None) -> dict:
        """Returns {'ok': bool, 'error': dict|None, 'result': dict|None, 'raw': env}.

        An MCP tool failure is a SUCCESSFUL JSON-RPC response carrying
        `result.isError = true`, with the gate's structured JSON payload as the
        content text. Protocol-level failures come back as `error`.
        """
        self._id += 1
        resp = await self._post({
            "jsonrpc": "2.0", "id": self._id, "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        })
        env = _parse(resp) or {}
        out: dict[str, Any] = {"raw": env, "http_status": resp.status_code,
                               "ok": False, "error": None, "result": None,
                               "cache_control": resp.headers.get("cache-control")}
        if "error" in env:
            out["error"] = env["error"]
            return out
        res = env.get("result") or {}
        out["result"] = res
        text = ""
        for block in res.get("content") or []:
            if block.get("type") == "text":
                text += block.get("text") or ""
        out["text"] = text
        if res.get("isError"):
            try:
                out["error"] = json.loads(text)
            except Exception:
                out["error"] = {"error": "unparsed", "message": text}
            return out
        out["ok"] = True
        try:
            out["payload"] = json.loads(text) if text else res.get("structuredContent")
        except Exception:
            out["payload"] = res.get("structuredContent")
        return out


@contextlib.asynccontextmanager
async def app_client():
    """The real ASGI app, lifespan entered, reachable over httpx."""
    import mcp_server

    app = mcp_server.build_dual_app()
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport,
                                     base_url="https://mcp.test.invalid",
                                     timeout=30.0) as client:
            yield client


@contextlib.asynccontextmanager
async def session(token: Optional[str], path: str = "/mcp"):
    async with app_client() as client:
        s = MCPSession(client, token, path=path)
        await s.initialize()
        yield s
