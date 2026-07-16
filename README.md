# Forge by Foundry Labs — Industrial Machine Intelligence

The cross-manufacturer industrial MCP server. Talk to any CNC, robot, or industrial
machine in natural language — machine identity, telemetry normalization across 18 OEM
families, plain-English automation, and tamper-evident work attestation.

Hosted MCP over Streamable HTTP. 30 tools wrap the Forge v1 API: provision a stable machine
identity, normalize raw OEM telemetry into a canonical schema, query operational history,
parse and activate plain-English automations, predict failures (TimesFM), score fleet health,
and record every state-changing action as a verifiable, tamper-evident attestation.

- **Website:** https://foundrynet.io/?utm_source=github&utm_medium=readme&utm_campaign=forge-mcp-readme
- **Docs:** https://foundrynet.io/docs?utm_source=github&utm_medium=readme&utm_campaign=forge-mcp-readme · **Free key:** https://foundrynet.io/signup?utm_source=github&utm_medium=readme&utm_campaign=forge-mcp-readme
- **MCP endpoint (Streamable HTTP):** `https://mcp.foundrynet.io/mcp`
- **Legacy SSE endpoint (still served):** `https://mcp.foundrynet.io/sse`
- **Health:** `https://mcp.foundrynet.io/health`
- **Server card:** `https://mcp.foundrynet.io/.well-known/mcp/server-card.json`

## What it does

It normalizes raw OEM telemetry from **18 manufacturer families** into one canonical
vocabulary with thousands of confirmed field mappings — so an agent writes against one set
of field names whether the machine is a Fanuc CNC, a KUKA arm, or a Universal Robots cobot.
On top of that it turns plain-English instructions into structured automations (review then
activate), and records every state-changing action as a tamper-evident attestation.

## Architecture

Pure HTTP proxy. Every tool is a thin wrapper around `https://forge.foundrynet.io/v1/*`
using a configured `fnet_` Bearer key. No state, no shared imports with `forge-prod` —
separate Railway service, separate dependencies (`fastmcp` + `httpx`).

```
Claude Desktop / agent
        │ Streamable HTTP (/mcp) — or legacy SSE (/sse)
        ▼
  foundrynet-mcp on Railway
        │ HTTPS + Bearer fnet_…
        ▼
  forge.foundrynet.io/v1/*
```

## Tools (30)

Identity & data: `identify_machine`, `normalize_telemetry`, `query_machine_history`,
`get_coverage`, `correct_mapping`. Automation: `create_automation`, `activate_automation`,
`list_automations`, `disable_automation`, `delete_automation`, `restore_automation`,
`query_webhook_history`. Prediction (TimesFM): `predict`, `predict_breach`, `remaining_life`,
`predict_batch`, `fleet_health`, `detect_anomalies`, `machine_intelligence`,
`prediction_accuracy`. Operations: `calculate_oee`, `fleet_oee`, `energy_consumption`,
`shift_report`, `diagnose_machine`, `health_index`. Agents: `get_agent_card`, `list_agents`.
Attestation: `verify_record`. Demo: `fire_sandbox` (the full watch → fire → settle loop, no card).

Free tier exposes the read-only tools; metered pay-per-use unlocks the premium prediction
and diagnostics tools (see https://forge.foundrynet.io/pricing?utm_source=github&utm_medium=readme&utm_campaign=forge-mcp-readme).

## Connect (Claude Desktop, Cursor, any MCP client)

```bash
claude mcp add --transport http foundrynet-forge \
  https://mcp.foundrynet.io/mcp \
  --header "Authorization: Bearer fnet_YOUR_KEY"
```

Or via `claude_desktop_config.json` with the `mcp-remote` bridge:

```json
{
  "mcpServers": {
    "foundrynet-forge": {
      "command": "npx",
      "args": ["-y", "mcp-remote",
               "https://mcp.foundrynet.io/mcp",
               "--header", "Authorization:Bearer ${FNET_KEY}"],
      "env": { "FNET_KEY": "fnet_…  (get a free key at foundrynet.io/signup)" }
    }
  }
}
```

Legacy SSE (`--transport sse` against `https://mcp.foundrynet.io/sse`) remains supported for
existing configs, but new integrations should use the Streamable HTTP `/mcp` endpoint above.

Get a free `fnet_` key at https://foundrynet.io/signup?utm_source=github&utm_medium=readme&utm_campaign=forge-mcp-readme (50 normalize calls, no card).

## Required environment (server-side)

| Var | Required | Default |
|---|---|---|
| `FOUNDRYNET_API_KEY` | Yes | — (server boots; tool calls return 401 until set) |
| `FORGE_BASE_URL` | No | `https://forge.foundrynet.io` |
| `PORT` | No | 8080 (Railway sets this automatically) |
| `REQUEST_TIMEOUT` | No | 30 (seconds) |

## Files

- `mcp_server.py` — the server (30 tools + `/health` + `/.well-known/mcp` routes)
- `gating.py` — per-client tier gating (Free vs Pro tool/quota enforcement)
- `server.json` — MCP registry metadata (name, description, keywords, remote endpoint)
- `smithery.yaml` — Smithery listing metadata
- `requirements.txt` — `fastmcp>=2.0`, `httpx>=0.27`
- `Procfile` — Railway start command (`web: python mcp_server.py`)

## License

Proprietary (commercial). © Foundry Labs LLC. Contact: forge@foundrynet.io
