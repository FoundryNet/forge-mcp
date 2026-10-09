# Forge by Foundry Labs — Industrial Machine Intelligence

The cross-manufacturer industrial MCP server. Talk to any CNC, robot, or industrial
machine in natural language — machine identity, telemetry normalization across 45
vendor packs in 19 verticals, plain-English automation, and tamper-evident work records.

Hosted MCP over Streamable HTTP. 32 tools wrap the Forge v1 API: provision a stable machine
identity, normalize raw OEM telemetry into a canonical schema, query operational history,
parse and activate plain-English automations, predict failures (TimesFM), score fleet health,
and record every state-changing action as a verifiable, tamper-evident work record.

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
activate), and records every state-changing action as a tamper-evident work record.

## Architecture

Pure HTTP proxy. Every tool is a thin wrapper around `https://forge.foundrynet.io/v1/*`.
No state, no shared imports with `forge-prod` — separate Railway service, separate
dependencies (`fastmcp` + `httpx`).

```
Claude Desktop / agent
        │ Streamable HTTP (/mcp) — or legacy SSE (/sse)
        │ Authorization: Bearer <the CALLER's Forge API key>
        ▼
  foundrynet-mcp on Railway
        │ gate: validate key → tier → cap → bind caller
        │ HTTPS, Authorization: Bearer <the SAME caller's key>
        │        X-Forge-Caller-Key-Id: <their forge_api_keys.id>
        ▼
  forge.foundrynet.io/v1/*  — scopes every row to that caller
```

**Tenancy.** The upstream call is made as the CALLER, not as this server. It used
to be made with the server's own `FOUNDRYNET_API_KEY` for every caller, with no
caller named: forge-prod scopes rows to the authenticated key's owner, so every
MCP tenant read and wrote inside one shared Forge account — and `fleet_oee`,
`shift_report`, `list_agents` and `prediction_accuracy` take no machine argument,
so they returned that whole account. The upstream hop now REFUSES to run when it
cannot name the caller: there is no fallback, because the only fallback is the
shared key. OAuth access tokens carry a key id but not a key, so they cannot be
presented upstream and are refused on tool calls with
`tenant_context_unavailable`.

`POST /a2a/tasks` and `GET /a2a/agents` go through the same gate function
(`gating.enforce_call`) as `tools/call`, by skill→tool mapping. They previously
authenticated the caller and then dispatched with no tier check, no cap and no
payment gate, which made the A2A route a free pass to the paid inference tools.

## Tests and the release gate

```
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest pytest-asyncio
.venv/bin/python -m pytest tests/ -q        # 229 checks
scripts/release_gate.sh                     # tree, deps, import, suite, version
```

The suite drives the real ASGI app over real Streamable HTTP through the real
gate; only Supabase and the upstream hop are substituted, and the upstream
substitute RECORDS requests, because what identity this server presents to
forge-prod is the thing most worth asserting. `tests/test_rest_mcp_parity.py`
measures free-tier parity against forge-prod's own `_endpoint_to_billing_meter`,
read out of its source at test time rather than copied.

CI runs the whole tree on every push and pull request
(`.github/workflows/release-gate.yml`, pinned to `ubuntu-24.04`). The 5 parity
checks SKIP there, loudly and with their reason printed, because forge-prod is a
separate private repo and is not on the runner — a visible skip beats a green
tick over a check that was quietly dropped.

## Deploying

```
cd ~/forge-mcp && git checkout main && git pull --ff-only && ./deploy.sh
```

Never `railway up` by hand. `deploy.sh` does seven things in order, and five of
them exist because of a specific way a deploy has gone wrong:

1. refuses a dirty tree or a branch that is not `main` — `railway up` uploads
   the WORKING TREE, so with uncommitted changes no commit describes what ships;
2. runs `scripts/release_gate.sh` and refuses if it is red. There is no override
   flag, deliberately;
3. takes a deploy lock (`~/.forge-mcp-deploy.lock`, atomic `mkdir`) so two
   concurrent deploys cannot race on the upload and on the verification;
4. refuses if `railway up` would archive the wrong directory. It archives the
   CLOSEST LINKED project directory from `~/.railway/config.json`, walking UP —
   not `$PWD`. This directory once inherited `$HOME`'s link, which names a
   DIFFERENT SERVICE;
5. runs `stamp_build.py`, which writes `build_info.json` (commit, dirty state,
   `content_hash` over the uploaded file set, build time);
6. `railway up --service 162115b7-…` — the id is explicit, because a bare
   `railway up` resolves the service from that same ancestor link;
7. polls `https://mcp.foundrynet.io/health` until `build.commit_short` AND
   `build.content_hash` both equal the stamp it just wrote, then asserts the
   status. Railway reporting SUCCESS only means the upload and build succeeded —
   a crash-looping new container leaves the OLD one serving and the deploy looks
   fine. `content_hash` is checked as well as the commit because `railway up`
   uploads a *tree*: the same commit with a different tree is a different
   deployment.

`/health` carries a `build` block using the same key names as forge-prod's, so
one verifier reads both services. When `build_info.json` is absent it says so in
words — `build_info.json absent — deploy did not run stamp_build.py`, with
`commit`, `content_hash` and `built_at` present and null — because a null that
looks like a missing field is indistinguishable from a stamped build.

## Tools (32)

Identity & data: `identify_machine`, `normalize_telemetry`, `query_machine_history`,
`get_coverage`, `correct_mapping`. Automation: `create_automation`, `activate_automation`,
`list_automations`, `disable_automation`, `delete_automation`, `restore_automation`,
`query_webhook_history`. Prediction (TimesFM): `predict`, `predict_breach`, `remaining_life`,
`predict_batch`, `fleet_health`, `detect_anomalies`, `machine_intelligence`,
`prediction_accuracy`. Operations: `calculate_oee`, `fleet_oee`, `energy_consumption`,
`shift_report`, `diagnose_machine`, `health_index`. Guardrails: `check_guardrail`,
`list_guardrails`. Agents on your kernel: `get_agent_card`,
`list_agents`. Work records: `verify_record`. Demo: `fire_sandbox` (the full watch → fire →
settle loop, no card).

`get_agent_card` and `list_agents` are scoped to the agents connected to your kernel instance
(their capabilities, trust scores, and machine access) and are included in your subscription —
there is no per-call charge. They are operational tools for coordinating agents on your own
equipment, not cross-platform discovery. For cross-platform agent trust across any framework,
see Assay (assay.foundrynet.io). `verify_record` creates a tamper-evident, hash-verified record
of completed work.

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
| `FOUNDRYNET_API_KEY` | No longer used on the tool path | Kept for the boot-time config report only; tool calls run as the caller's own key |
| `SUPABASE_URL` / `SUPABASE_SERVICE_KEY` | Yes for gating | unset = gating disabled, fail-open |
| `MCP_JWT_SECRET` | No | unset = OAuth token issuance disabled (503), key auth unaffected |
| `FORGE_BASE_URL` | No | `https://forge.foundrynet.io` |
| `PORT` | No | 8080 (Railway sets this automatically) |
| `REQUEST_TIMEOUT` | No | 120 (seconds) |

## Files

- `mcp_server.py` — the server (32 tools + `/health` + `/.well-known/mcp` routes)
- `gating.py` — per-client tier gating (Free vs Pro tool/quota enforcement)
- `server.json` — MCP registry metadata (name, description, keywords, remote endpoint)
- `smithery.yaml` — Smithery listing metadata
- `requirements.txt` — `fastmcp>=3.4.5,<4`, `httpx>=0.27`, `PyJWT>=2.14.0`, `supabase`, `stripe`
- `tests/` — the behavioural suite (auth, tenancy, parity, idempotency, cache scope)
- `scripts/release_gate.sh` — must be green on the exact commit before a deploy
- `deploy.sh` — the only path to production; gated, locked, stamped and verified
- `stamp_build.py` — writes `build_info.json`; what `/health`'s `build` block reports
- `Procfile` — Railway start command (stamps, then `python mcp_server.py`)
- `.github/workflows/release-gate.yml` — CI; the whole suite on push and PR

## License

Proprietary (commercial). © Foundry Labs LLC. Contact: foundrynet@proton.me
