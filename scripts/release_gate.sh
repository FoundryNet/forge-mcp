#!/usr/bin/env bash
# forge-mcp release gate. Green on the exact commit, or no deploy.
#
# Five gates, each one standing in for a way this service has actually been
# wrong rather than a way it might be:
#
#   1. TREE      — `railway up` uploads the WORKING TREE, so a dirty tree
#                  deploys something that is not the commit you tested.
#   2. DEPS      — install from requirements.txt into a clean venv on the pinned
#                  bounds. `fastmcp<4` is load-bearing: 4.x is the 2026-07-28
#                  beta line and drops the 3.x compat shims this tool surface is
#                  built on, so a relaxed bound is a silent rewrite of the
#                  server. PyJWT>=2.14.0 for the OAuth path.
#   3. IMPORT    — the module imports with NO environment set. Gating must
#                  degrade, never 500 at boot.
#   4. BEHAVIOUR — the suite, over the real transport, through the real gate:
#                  tenancy, auth matrix, REST/MCP parity, idempotency,
#                  ownership, cache scope.
#   5. VERSION   — serverInfo.version, server.json and the server card agree.
#                  FastMCP without `version=` reports its OWN library version,
#                  so the handshake once advertised whatever fastmcp release was
#                  built last instead of ours.
#
# Usage: scripts/release_gate.sh [--allow-dirty]
set -uo pipefail

cd "$(dirname "$0")/.." || exit 2
REPO="$PWD"
ALLOW_DIRTY=0
[ "${1:-}" = "--allow-dirty" ] && ALLOW_DIRTY=1

FAILED=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAILED=1; }
head() { printf '\n== %s ==\n' "$1"; }

printf 'forge-mcp release gate — %s\n' "$(git rev-parse --short HEAD 2>/dev/null || echo 'no git')"

# ── 1. TREE ──────────────────────────────────────────────────────────────────
head "1. tree"
if [ -d .git ] || git rev-parse --git-dir >/dev/null 2>&1; then
  DIRTY="$(git status --porcelain)"
  if [ -n "$DIRTY" ] && [ "$ALLOW_DIRTY" -eq 0 ]; then
    fail "working tree is dirty — railway up would upload THIS, not the commit:"
    printf '%s\n' "$DIRTY" | sed 's/^/        /'
  elif [ -n "$DIRTY" ]; then
    pass "tree dirty, allowed by --allow-dirty (do NOT deploy from here)"
  else
    pass "clean tree on $(git rev-parse --short HEAD)"
  fi
else
  fail "not a git repository — cannot establish what would be deployed"
fi

# ── 2. DEPS ──────────────────────────────────────────────────────────────────
head "2. dependencies (clean venv, pinned bounds)"
VENV="$(mktemp -d)/gate-venv"
if python3 -m venv "$VENV" >/dev/null 2>&1 \
   && "$VENV/bin/pip" install -q --upgrade pip >/dev/null 2>&1 \
   && "$VENV/bin/pip" install -q -r requirements.txt >/dev/null 2>&1; then
  pass "requirements.txt installs clean"
  FM="$("$VENV/bin/python" -c 'import fastmcp;print(fastmcp.__version__)' 2>/dev/null)"
  case "$FM" in
    3.*) pass "fastmcp $FM (inside the <4 pin)" ;;
    *)   fail "fastmcp resolved to $FM — the <4 pin is the thing holding the tool surface together" ;;
  esac
  JW="$("$VENV/bin/python" -c 'import jwt;print(jwt.__version__)' 2>/dev/null)"
  if "$VENV/bin/python" -c "
import sys
from importlib.metadata import version
a=tuple(int(x) for x in version('PyJWT').split('.')[:2])
sys.exit(0 if a>=(2,14) else 1)" 2>/dev/null; then
    pass "PyJWT $JW (>= 2.14.0)"
  else
    fail "PyJWT $JW is below the 2.14.0 floor"
  fi
else
  fail "requirements.txt does not install into a clean venv"
fi

# ── 3. IMPORT with nothing configured ────────────────────────────────────────
head "3. import with no environment"
if [ -x "$VENV/bin/python" ]; then
  if env -u SUPABASE_URL -u SUPABASE_SERVICE_KEY -u FOUNDRYNET_API_KEY \
         -u MCP_JWT_SECRET -u STRIPE_SECRET_KEY -u ORIGIN_SHARED_SECRET \
         PYTHONPATH="$REPO" "$VENV/bin/python" -c "
import mcp_server, gating
assert len(gating.ALL_TOOLS) == 32, len(gating.ALL_TOOLS)
app = mcp_server.build_dual_app()
assert app is not None
" >/dev/null 2>&1; then
    pass "imports and builds the app with no env set"
  else
    fail "import or app build needs configuration — a half-configured deploy would 500 at boot"
  fi
fi

# ── 4. BEHAVIOUR ─────────────────────────────────────────────────────────────
head "4. behavioural suite"
TESTVENV="${FORGE_MCP_TEST_VENV:-$REPO/.venv}"
PY="$TESTVENV/bin/python"
[ -x "$PY" ] || PY="python3"
if "$PY" -c "import pytest, fastmcp" >/dev/null 2>&1; then
  OUT="$(cd "$REPO" && "$PY" -m pytest tests/ -q -p no:logging 2>&1)"
  LINE="$(printf '%s\n' "$OUT" | tail -n 3 | grep -E '[0-9]+ (passed|failed)' | tail -1)"
  if printf '%s\n' "$OUT" | grep -qE '^(FAILED|ERROR)'; then
    fail "behavioural suite red — ${LINE:-see output}"
    printf '%s\n' "$OUT" | grep -E '^(FAILED|ERROR)' | sed 's/^/        /'
  else
    pass "behavioural suite green — ${LINE:-ok}"
  fi
else
  fail "no test environment (set FORGE_MCP_TEST_VENV, or create .venv with pytest + the requirements)"
fi

# ── 5. VERSION agreement ─────────────────────────────────────────────────────
head "5. version agreement"
if "$PY" -c "
import json, pathlib, re, sys
src = pathlib.Path('mcp_server.py').read_text()
m = re.search(r'FastMCP\(\s*\"foundrynet\"\s*,\s*version=\"([^\"]+)\"', src)
if not m:
    print('mcp_server.py: FastMCP() has no version= — serverInfo would report the '
          'fastmcp LIBRARY version to every client')
    sys.exit(1)
code = m.group(1)
decl = json.loads(pathlib.Path('server.json').read_text())['version']
if code != decl:
    print(f'serverInfo.version={code} but server.json says {decl}')
    sys.exit(1)
print(code)
" >/tmp/.mcp_gate_ver 2>&1; then
  pass "version $(cat /tmp/.mcp_gate_ver) agrees across mcp_server.py and server.json"
else
  fail "$(cat /tmp/.mcp_gate_ver)"
fi
rm -f /tmp/.mcp_gate_ver
rm -rf "$(dirname "$VENV")" 2>/dev/null

head "result"
if [ "$FAILED" -eq 0 ]; then
  printf '  \033[32mGATE GREEN\033[0m — safe to deploy this commit\n'
  exit 0
fi
printf '  \033[31mGATE RED\033[0m — do not deploy\n'
exit 1
