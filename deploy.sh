#!/usr/bin/env bash
# Deploy forge-mcp to Railway, stamped, and PROVE what landed.
#
#   ./deploy.sh              gate, lock, stamp, confirm, upload, verify
#   ./deploy.sh --yes        no interactive confirmation (CI / automation)
#   ./deploy.sh --no-verify  upload without waiting (you are on your own)
#
# It takes a DEPLOY LOCK ($HOME/.forge-mcp-deploy.lock, override
# FORGE_MCP_DEPLOY_LOCK) across stamp -> upload -> verify, and refuses to start
# if another deploy holds it. Released on every exit path. See section 1.
#
# A SEPARATE LOCK FROM forge-prod'S, deliberately. forge-prod uses
# $HOME/.forge-deploy.lock. These are two Railway services with two upload
# paths and two /health endpoints; sharing one lock would make a kernel deploy
# block an MCP deploy for no reason, and a shared lock that people learn to
# work around is worse than two honest ones.
#
# THREE INVARIANTS, all learned on the kernel and ported here BEFORE this
# service needed to learn them the same way.
#
# 1. ALWAYS STAMP FIRST. `railway up` uploads a working tree, so without this
#    /health can say nothing at all about what is running. Until stamp_build.py
#    existed, forge-mcp's /health carried NO commit and NO content hash: every
#    field it reported (tools_count, forge_base_url, the configuration
#    booleans) was true of every build this service has ever had. A deploy that
#    cannot identify itself is not a deploy you can roll back from, because you
#    cannot tell what to roll back to.
#
# 2. VERIFY AFTERWARDS, AND FAIL IF IT DOES NOT MATCH. Railway reporting
#    SUCCESS means the upload and build succeeded. It does not mean the process
#    answering /health is the one you just built: a healthcheck can pass on the
#    OLD container while the new one is still starting, and a crash-looping new
#    container leaves the old one serving indefinitely. The only proof is
#    /health reporting back the exact commit and content_hash this script just
#    stamped, so that is what this waits for, and it exits non-zero if it never
#    arrives.
#
#    content_hash is checked AS WELL AS the commit because `railway up` uploads
#    a TREE: the same commit with a different tree is a different deployment,
#    and a commit-only check waves that straight through.
#
# 3. THE ARCHIVE ROOT MUST BE THIS DIRECTORY. See section 3 -- this is the one
#    that would have uploaded $HOME to production.
set -uo pipefail

cd "$(dirname "$0")"

SERVICE=162115b7-b420-4a02-8cff-ddad7be02dc2     # foundrynet-mcp
PROJECT=4d8c76bb-c5fc-4eec-baa0-5e8f85579cbf     # insightful-gratitude
HEALTH=https://mcp.foundrynet.io/health
UA='User-Agent: curl/8.4.0'                      # Cloudflare 1010s a default UA
VERIFY_TIMEOUT_S=${VERIFY_TIMEOUT_S:-600}
POLL_EVERY_S=${POLL_EVERY_S:-15}

# The branch this service deploys from. A CONSTANT, not an environment lookup:
# `DEPLOY_BRANCH="${DEPLOY_BRANCH:-main}"` would be an override wearing a
# configuration costume -- point it at whatever branch you happen to be on and
# the check is gone.
readonly DEPLOY_BRANCH=main
# The gate. Also a constant, for the same reason: a GATE_SCRIPT env var would
# let a deploy point the check at `true`.
readonly GATE_SCRIPT=./scripts/release_gate.sh

ASSUME_YES=0
VERIFY=1
for a in "$@"; do
  case "$a" in
    --yes|-y)    ASSUME_YES=1 ;;
    --no-verify) VERIFY=0 ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
  esac
done

die() { printf '\033[31mFAIL\033[0m  %s\n' "$1" >&2; exit 1; }
ok()  { printf '\033[32mOK\033[0m    %s\n' "$1"; }

# ── 0. THE TREE AND THE BRANCH ──────────────────────────────────────────────
#
# A DIRTY TREE IS REFUSED, and that is not pedantry: `railway up` uploads the
# WORKING TREE, so with uncommitted changes there is no commit that describes
# what is being deployed and the gate's verdict in section 0b is about
# different bytes. Without this, every check below is bypassed by editing one
# file after running them.
#
# THE BRANCH IS CHECKED for the same reason the stamp exists: a deploy made
# from a feature branch is indistinguishable, from /health, from one made from
# main, and the SHA it reports resolves to nothing on the default branch for
# anybody reading it later.
if ! git rev-parse --git-dir >/dev/null 2>&1; then
  die "this is not a git repository, so there is no commit that could describe
      what would be deployed. Deploy from a clone of
      github.com/FoundryNet/forge-mcp."
fi

if [ -n "$(git status --porcelain)" ]; then
  git status --short >&2
  die "the working tree is DIRTY. railway up uploads the working tree, so
      there is no commit that describes what would be deployed and the release
      gate's verdict would be about different bytes. Commit, or deploy from a
      clean detached worktree:
        git worktree add -f --detach /tmp/forge-mcp-deploy origin/main"
fi

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
if [ "$CURRENT_BRANCH" != "$DEPLOY_BRANCH" ]; then
  die "on branch '${CURRENT_BRANCH:-<detached>}', not '$DEPLOY_BRANCH'. This
      service deploys from $DEPLOY_BRANCH only: a build stamped with a feature
      branch's SHA resolves to nothing for whoever reads /health next week.
      There is no flag to skip this. Merge first, or deploy a detached
      worktree of origin/$DEPLOY_BRANCH:
        git worktree add -f --detach /tmp/forge-mcp-deploy origin/$DEPLOY_BRANCH"
fi

DEPLOY_SHA=$(git rev-parse HEAD)
DEPLOY_SHORT=$(git rev-parse --short HEAD)
ok "clean tree on $DEPLOY_BRANCH at $DEPLOY_SHORT"

# ── 0b. THE RELEASE GATE MUST BE GREEN ON THESE EXACT BYTES ─────────────────
#
# WHY. forge-prod had a release gate that had been RED on main for days while
# deploys continued, because nothing connected the two: what the red was hiding
# was a safety state being read backwards in production. forge-mcp already HAD
# scripts/release_gate.sh -- five gates over tenancy, the auth matrix, REST/MCP
# parity, idempotency, ownership and cache scope -- and nothing in the deploy
# path ran it. A gate nobody runs is documentation.
#
# It is run HERE, on the tree that is about to be uploaded, rather than trusted
# from a CI run on some other commit. That is the stronger claim: CI tells you a
# commit was green, this tells you THESE BYTES are green, and `railway up`
# ships bytes.
#
# THERE IS NO OVERRIDE FLAG, DELIBERATELY. A --force-deploy is a flag somebody
# adds to get one release out and nobody ever removes, and the thing it
# disables is the gate that measures whether one tenant can read another's
# rows. To ship past a red gate, make the gate green.
[ -x "$GATE_SCRIPT" ] || [ -f "$GATE_SCRIPT" ] \
  || die "$GATE_SCRIPT is missing, so the release gate cannot be run. A deploy
      does not proceed on an unknown gate state, and there is no flag to skip
      this."

echo "running the release gate on $DEPLOY_SHORT ..."
if ! bash "$GATE_SCRIPT"; then
  die "the release gate is RED on $DEPLOY_SHORT. This deploy is refused and
      there is no override. If the gate looks red because a test is stale, fix
      the test in a commit and let the gate pass on it -- on 2026-10-08 a red
      gate on the kernel that looked stale was reporting a safety state being
      read backwards in production."
fi
ok "release gate green on $DEPLOY_SHORT"

# ── 1. TAKE THE DEPLOY LOCK ─────────────────────────────────────────────────
#
# WHY. `railway up` uploads a WORKING TREE, and this script proves what landed
# by polling /health until it reports the exact commit and content_hash it just
# stamped. Both of those break under a concurrent deploy:
#
#   * two uploads race and the later one wins, so the tree that ends up serving
#     is not necessarily the one that was gate-checked a moment earlier;
#   * step 5 then compares /health against ITS OWN stamp, so the loser either
#     times out claiming "the running build is still not the one just
#     uploaded" -- true, but for the wrong reason -- or, if both runs deployed
#     the same bytes, passes while having had no effect.
#
# `mkdir` is the lock because mkdir(2) is ATOMIC and fails if the directory
# exists: there is no check-then-act window, which `[ -e ]` followed by
# `mkdir -p` would have. Note `mkdir` WITHOUT -p, deliberately -- `mkdir -p`
# succeeds on an existing directory and would make the lock a no-op that still
# prints "lock taken".
LOCK_DIR="${FORGE_MCP_DEPLOY_LOCK:-$HOME/.forge-mcp-deploy.lock}"
HELD_BY_US=0

# Released on EVERY exit path, not just the happy one: a deploy that dies at
# the gate, at the stamp, on a failed upload or in verification must not leave
# the lock held, or one bad run blocks every later deploy until a human
# notices. The guard is HELD_BY_US -- without it, a run that FAILED to acquire
# the lock would delete the lock belonging to the deploy that is still running.
release_lock() {
  [ "$HELD_BY_US" -eq 1 ] || return 0
  rm -f "$LOCK_DIR/owner" 2>/dev/null
  rmdir "$LOCK_DIR" 2>/dev/null && echo "deploy lock released"
}
trap release_lock EXIT INT TERM

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  # Report WHO holds it and whether that process is still alive. A lock whose
  # holder is gone -- SIGKILL, a closed laptop -- is stale, and a human who
  # cannot tell the difference between "someone is mid-deploy" and "a lock was
  # orphaned three days ago" will eventually delete it without looking, which
  # is the same as not having a lock.
  #
  # It is NOT broken automatically, even when the PID is provably dead. An
  # auto-breaking lock is not a lock, and the failure it would permit is two
  # concurrent uploads into production.
  owner=$(cat "$LOCK_DIR/owner" 2>/dev/null || echo "unknown (no owner file)")
  held_pid=$(sed -n 's/^pid=//p' "$LOCK_DIR/owner" 2>/dev/null)
  #
  # `ps -p`, NOT `kill -0`. kill(2) fails with EPERM, not ESRCH, for a live
  # process owned by ANOTHER USER, and the shell cannot tell the two apart from
  # the exit status -- measured on the kernel against pid 1 (launchd,
  # root-owned, obviously alive): `kill -0 1` fails as a normal user, so the
  # script reported a RUNNING deploy as "STALE" and told the operator to
  # `rm -rf` a live lock. `ps -p` answers the question actually being asked.
  liveness="cannot tell (the lock names no pid)"
  if [ -n "$held_pid" ]; then
    if ps -p "$held_pid" >/dev/null 2>&1; then
      liveness="that process IS STILL RUNNING -- wait for it"
    else
      liveness="that process is NOT running, so this lock is STALE"
    fi
  fi
  die "the deploy lock is held, so another forge-mcp deploy is in progress.
      $LOCK_DIR
      $owner
      $liveness
      Concurrent deploys to one Railway service race: railway up uploads a
      working tree, the later upload wins, and this script's verification then
      compares /health against its own stamp and reports the wrong conclusion.
      If the lock is stale, remove it deliberately:
        rm -rf $LOCK_DIR"
fi
HELD_BY_US=1
printf 'pid=%s\nhost=%s\ncommit=%s\nstarted=%s\n' \
  "$$" "$(hostname)" "$DEPLOY_SHORT" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  > "$LOCK_DIR/owner"
ok "deploy lock taken ($LOCK_DIR, pid $$)"

# ── 2b. THE ARCHIVE ROOT MUST BE THIS DIRECTORY ─────────────────────────────
#
# WHY, measured 2026-10-09. `railway up` does NOT archive $PWD. It archives the
# CLOSEST LINKED PROJECT DIRECTORY from ~/.railway/config.json, walking UP the
# tree. This clone was not linked, so the nearest linked ancestor was $HOME --
# and three deploys hung at `Indexing...` for 18, 9 and 6 minutes walking the
# entire home directory, never reaching the network and never creating a
# deployment record. Proven by lsof on the live process: cwd was
# /Users/ryangordon/forge-prod while its open directories were
# ~/Downloads/... and then ~/Movies/CapCut/User.
#
# THE HANG WAS THE SAFE OUTCOME. Had one ever finished it would have uploaded
# ~/.railway/config.json, every .env on the machine and the archived lineage's
# unpushed secrets to Railway and served them as forge-prod. The same
# misconfiguration in ~/forge-mcp pointed at the WRONG SERVICE as well
# (market-data-mcp, not foundrynet-mcp), because an unlinked directory inherits
# the service of whichever ancestor is linked.
#
# This cannot be asserted from inside the repository: the link lives in mutable
# config OUTSIDE it. Which is exactly why the check belongs here, in the only
# path that ships. The failure it replaces is silent; this one names the
# directory that would have been uploaded and the command that fixes it.
ARCHIVE_ROOT=$(python3 - <<'PY'
import json, os
try:
    pr = json.load(open(os.path.expanduser("~/.railway/config.json"))).get("projects") or {}
except Exception:
    print(""); raise SystemExit
cwd, best = os.path.realpath(os.getcwd()), ""
for k in pr:
    rk = os.path.realpath(k)
    if cwd == rk or cwd.startswith(rk.rstrip("/") + "/"):
        if len(rk) > len(best):
            best = rk
print(best)
PY
)
if [ "$ARCHIVE_ROOT" != "$(pwd -P)" ]; then
  die "railway up would archive '${ARCHIVE_ROOT:-<nothing linked>}', not $(pwd -P).
      It uploads the CLOSEST LINKED project directory, not the current one, so
      this would tar an unrelated tree. On 2026-10-09 that was \$HOME: a silent
      18-minute hang which, had it completed, would have uploaded every .env on
      this machine and served them as production. This directory in particular
      inherited \$HOME's link to market-data-mcp -- the WRONG SERVICE. Link it
      first:
        railway link --project $PROJECT \\
          --environment production --service $SERVICE"
fi
ok "archive root is $(pwd -P)"

# ── 3. stamp ────────────────────────────────────────────────────────────────
python3 stamp_build.py || die "stamp_build.py failed; nothing was uploaded"

WANT_COMMIT=$(python3 -c 'import json;print(json.load(open("build_info.json"))["commit_short"])') \
  || die "build_info.json unreadable after stamping"
WANT_HASH=$(python3 -c 'import json;print(json.load(open("build_info.json"))["content_hash"])')
WANT_DIRTY=$(python3 -c 'import json;print(json.load(open("build_info.json"))["dirty"])')

[ -n "$WANT_COMMIT" ] || die "the stamp carries no commit"
[ -n "$WANT_HASH" ]   || die "the stamp carries no content_hash"

if [ "$WANT_DIRTY" = "True" ]; then
  # Section 0 refuses a dirty tree, so reaching here means stamp_build.py and
  # `git status` disagree. Say so rather than deploying something neither of
  # them describes.
  die "the stamp reports a DIRTY tree even though section 0 found the tree
      clean. stamp_build.py and git disagree about what would be uploaded, so
      content_hash describes bytes nobody has checked."
fi

# ── 4. confirm ──────────────────────────────────────────────────────────────
echo
if [ "$ASSUME_YES" -eq 0 ]; then
  read -r -p "Deploy the above to Railway production (foundrynet-mcp)? [y/N] " reply
  [[ "$reply" == "y" || "$reply" == "Y" ]] || { echo "aborted"; exit 1; }
fi

# ── 5. upload ───────────────────────────────────────────────────────────────
# --service IS EXPLICIT AND NON-NEGOTIABLE. A bare `railway up` resolves the
# service from the nearest linked ancestor, which for this directory was
# $HOME's link to market-data-mcp. Naming the id means a broken link map is a
# refusal in section 2b rather than a deploy of forge-mcp onto another service.
railway up --service "$SERVICE" --detach || die "railway up failed"
ok "uploaded"

[ "$VERIFY" -eq 1 ] || { echo "skipping verification (--no-verify)"; exit 0; }

# ── 6. verify what is actually serving ──────────────────────────────────────
echo
echo "waiting for /health to report commit=$WANT_COMMIT"
echo "                       content_hash=${WANT_HASH:0:26}…"

deadline=$(( $(date +%s) + VERIFY_TIMEOUT_S ))
got_commit=""; got_hash=""; last=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  body=$(curl -s -H "$UA" --max-time 20 "$HEALTH" 2>/dev/null)
  read -r got_commit got_hash <<<"$(printf '%s' "$body" | python3 -c '
import sys, json
try:
    b = (json.load(sys.stdin).get("build") or {})
except Exception:
    print("- -"); raise SystemExit
print((b.get("commit_short") or "-"), (b.get("content_hash") or "-"))
' 2>/dev/null)"
  got_commit=${got_commit:--}; got_hash=${got_hash:--}

  if [ "$got_commit" = "$WANT_COMMIT" ] && [ "$got_hash" = "$WANT_HASH" ]; then
    ok "live: commit=$got_commit content_hash=${got_hash:0:26}…"
    # forge-mcp's /health says status "ok" where forge-prod says "healthy".
    # Both are accepted so one verifier can read either service; anything else
    # -- "degraded", a 503 body, an error page -- fails.
    status=$(printf '%s' "$body" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("status","?"))' 2>/dev/null)
    case "$status" in
      ok|healthy) ok "status=$status" ;;
      *) die "the right build is serving but status=$status" ;;
    esac
    exit 0
  fi

  now="commit=$got_commit hash=${got_hash:0:20}"
  [ "$now" = "$last" ] || { echo "   serving $now"; last="$now"; }
  sleep "$POLL_EVERY_S"
done

echo >&2
echo "  wanted  commit=$WANT_COMMIT  content_hash=$WANT_HASH" >&2
echo "  serving commit=$got_commit  content_hash=$got_hash" >&2
if [ "$got_commit" = "-" ]; then
  die "after ${VERIFY_TIMEOUT_S}s /health reports no build stamp at all. The
      container that is serving did not ship build_info.json, which means it is
      not the build this script just made."
fi
die "after ${VERIFY_TIMEOUT_S}s the running build is still not the one just
      uploaded. Railway may report SUCCESS while the previous container keeps
      serving; check the build logs before assuming this deploy landed."
