"""deploy.sh must stamp first, and must fail when the wrong build is serving.

WHAT THIS PINS, and why forge-mcp needed it before it had been burned.

Until stamp_build.py and this script existed, `GET https://mcp.foundrynet.io/health`
carried NO build identity at all: no commit, no content hash, no build time.
Every field it did report -- tools_count, forge_base_url, the configuration
booleans -- was true of every build this service has ever had. So:

1. A deploy could not be verified, because there was nothing to compare
   against. forge-prod learned this on 2026-10-05, when a bare `railway up`
   left /health answering `build_info.json absent — deploy did not run
   stamp_build.py` with commit, content_hash and built_at all null, and
   production could not say what it was running. forge-mcp was in a worse
   state: it could not even say THAT.

2. Nothing checked afterwards. Railway reporting SUCCESS means the upload and
   build succeeded; it does not mean the process answering /health is the one
   just built. A crash-looping new container leaves the old one serving and the
   deploy looks fine.

3. `railway up` archives the CLOSEST LINKED project directory from
   ~/.railway/config.json, walking UP the tree -- not $PWD. On 2026-10-09
   ~/forge-mcp was unlinked, so the nearest linked ancestor was $HOME, whose
   link points at a DIFFERENT SERVICE (market-data-mcp). A deploy from here
   would have tarred the entire home directory and served it as foundrynet-mcp.

EVERY TEST HERE IS BEHAVIOURAL. The script is driven with `railway`, `curl`,
the stamp and the release gate replaced by shims, so each guard is exercised
rather than read. That matters specifically for the "there is no override flag"
property: a test that greps the source for the absence of a flag name passes
just as happily when the guard itself has been deleted. Those tests below drive
the real script with every plausible override env var and flag and assert it
still refuses.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOY = os.path.join(ROOT, "deploy.sh")

GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}

# What the stub stamp writes, and therefore what /health must report back.
STAMP_COMMIT = "abc1234de"
STAMP_HASH = "sha256:" + "f" * 64

GOOD = {"status": "ok",
        "service": "foundrynet-mcp",
        "build": {"commit_short": STAMP_COMMIT, "content_hash": STAMP_HASH}}


def _shim(path: str, body: str) -> None:
    with open(path, "w") as fh:
        fh.write("#!/usr/bin/env bash\n" + body + "\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP |
             stat.S_IXOTH)


def _flat(s: str) -> str:
    """Collapse whitespace: the failure messages are wrapped for the terminal,
    so asserting on a raw substring tests the line breaks rather than the text."""
    return " ".join(s.split())


def _sandbox(*, gate_exit=0, branch="main", stamp_body=None, link_dir=None,
             no_git=False):
    """Build a sandbox repo that deploy.sh can be driven inside.

    Returns (work, repo, binr). The sandbox is a REAL git repository, because
    deploy.sh reads HEAD, refuses a dirty tree and refuses a branch that is not
    `main`, and all three read git.
    """
    work = tempfile.mkdtemp(prefix="mcpdeploytest-")
    binr = os.path.join(work, "bin")
    os.makedirs(binr)
    repo = os.path.join(work, "repo")
    os.makedirs(os.path.join(repo, "scripts"))

    shutil.copy(DEPLOY, os.path.join(repo, "deploy.sh"))
    os.chmod(os.path.join(repo, "deploy.sh"), 0o755)

    # A stamp_build.py that writes a known stamp and nothing else.
    with open(os.path.join(repo, "stamp_build.py"), "w") as fh:
        fh.write(stamp_body if stamp_body is not None else (
            "import json\n"
            "json.dump({'commit_short': %r,\n"
            "           'content_hash': %r,\n"
            "           'dirty': False}, open('build_info.json', 'w'))\n"
            "print('  stamped')\n" % (STAMP_COMMIT, STAMP_HASH)))

    # The release gate. The REAL one builds a venv and runs 123 tests; what
    # deploy.sh must be measured on is what it does with the gate's VERDICT, so
    # the verdict is what is substituted. It logs its invocation, which is how
    # "the gate actually ran" is asserted rather than assumed.
    _shim(os.path.join(repo, "scripts", "release_gate.sh"),
          'echo "gate ran" >> "$PWD/gate.log"\n'
          'echo "  release gate stub"\n'
          f"exit {gate_exit}")

    # The artefacts a run produces must not make the tree dirty -- deploy.sh
    # refuses a dirty tree, and build_info.json is written BY the deploy.
    with open(os.path.join(repo, ".gitignore"), "w") as fh:
        fh.write("build_info.json\nrailway.log\ngate.log\n")

    if not no_git:
        genv = {**os.environ, **GIT_ENV}
        subprocess.run(["git", "init", "-q", "-b", branch], cwd=repo,
                       check=True, env=genv)
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True, env=genv)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo,
                       check=True, env=genv)

    # The archive-root guard reads ~/.railway/config.json, so HOME points at
    # the sandbox and a link map is written there. Without this every test in
    # this file would read the developer's REAL link map and the guard's verdict
    # would depend on whose machine the suite ran on.
    os.makedirs(os.path.join(work, ".railway"), exist_ok=True)
    link_root = repo if link_dir is None else link_dir
    with open(os.path.join(work, ".railway", "config.json"), "w") as fh:
        json.dump({"projects": ({} if link_root == "" else
                                {link_root: {"service": "svc"}})}, fh)
    return work, repo, binr


def _run(health_payload, *, args=("--yes",), timeout_s="6", poll_s="1",
         gate_exit=0, dirty=False, branch="main", link_dir=None,
         env_extra=None, stamp_body=None, no_git=False, sandbox=None):
    """Run deploy.sh in a sandbox whose curl returns `health_payload`."""
    if sandbox is None:
        work, repo, binr = _sandbox(gate_exit=gate_exit, branch=branch,
                                    stamp_body=stamp_body, link_dir=link_dir,
                                    no_git=no_git)
    else:
        work, repo, binr = sandbox

    _shim(os.path.join(binr, "railway"),
          'echo "railway $*" >> "$PWD/railway.log"; exit 0')
    payload = health_payload if isinstance(health_payload, str) \
        else json.dumps(health_payload)
    _shim(os.path.join(binr, "curl"), "cat <<'EOF'\n" + payload + "\nEOF")

    if dirty:
        with open(os.path.join(repo, "stamp_build.py"), "a") as fh:
            fh.write("# an uncommitted edit\n")

    env = {**os.environ, **GIT_ENV}
    env["PATH"] = binr + os.pathsep + env["PATH"]
    env["VERIFY_TIMEOUT_S"] = timeout_s
    env["POLL_EVERY_S"] = poll_s
    # THE LOCK IS SANDBOXED PER RUN. Without this every test in this file would
    # create and delete the REAL $HOME/.forge-mcp-deploy.lock, so running the
    # suite would block a live deploy -- and two tests in parallel would refuse
    # each other. `env_extra` can still override it to test contention.
    env["FORGE_MCP_DEPLOY_LOCK"] = os.path.join(work, "deploy.lock")
    env["HOME"] = work
    env.update(env_extra or {})
    r = subprocess.run(["bash", "./deploy.sh", *args], cwd=repo, env=env,
                       capture_output=True, text=True, timeout=180)
    r.lock_dir = env["FORGE_MCP_DEPLOY_LOCK"]
    r.work_dir = work
    return r, repo


def _uploaded(repo) -> bool:
    return os.path.exists(os.path.join(repo, "railway.log"))


def _stamped(repo) -> bool:
    return os.path.exists(os.path.join(repo, "build_info.json"))


# ── the happy path has to actually pass, or every other test is vacuous ─────
def test_a_matching_health_response_succeeds():
    r, repo = _run(GOOD)
    assert r.returncode == 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    assert "status=ok" in r.stdout
    assert _stamped(repo)


def test_it_stamps_before_it_uploads():
    r, repo = _run(GOOD)
    assert r.returncode == 0, r.stderr
    assert "railway up" in open(os.path.join(repo, "railway.log")).read()
    assert "stamped" in r.stdout


def test_it_names_the_service_explicitly_on_the_upload():
    """A bare `railway up` resolves the service from the nearest linked
    ancestor, which for ~/forge-mcp was $HOME's link to market-data-mcp. The
    id has to be on the command line, and it has to be forge-mcp's."""
    r, repo = _run(GOOD)
    assert r.returncode == 0, r.stderr
    log = open(os.path.join(repo, "railway.log")).read()
    assert "--service 162115b7-b420-4a02-8cff-ddad7be02dc2" in log, log


def test_a_failing_stamp_uploads_nothing():
    r, repo = _run(GOOD, stamp_body="import sys; sys.exit(3)\n")
    assert r.returncode != 0
    assert "nothing was uploaded" in _flat(r.stderr), r.stderr
    assert not _uploaded(repo), "railway was invoked despite the stamp failing"


def test_a_stamp_that_reports_dirty_refuses():
    """Section 0 already refused a dirty tree, so a stamp claiming dirty means
    stamp_build.py and git disagree about what would be uploaded."""
    r, repo = _run(GOOD, stamp_body=(
        "import json\n"
        "json.dump({'commit_short': 'abc1234de', 'content_hash': 'sha256:x',\n"
        "           'dirty': True}, open('build_info.json', 'w'))\n"))
    assert r.returncode != 0
    assert "stamp reports a DIRTY tree" in _flat(r.stderr), r.stderr
    assert not _uploaded(repo)


# ── the verification loop ───────────────────────────────────────────────────
def test_an_unstamped_health_response_fails_the_deploy():
    """The exact shape forge-prod returned on 2026-10-05, and the shape
    forge-mcp's own /health now returns when build_info.json is absent."""
    r, _ = _run({"status": "ok",
                 "service": "foundrynet-mcp",
                 "build": {"stamped": False,
                           "commit": None,
                           "commit_short": None,
                           "content_hash": None,
                           "built_at": None,
                           "note": "build_info.json absent — deploy did not run "
                                   "stamp_build.py"}})
    assert r.returncode != 0
    assert "no build stamp at all" in _flat(r.stderr), r.stderr


def test_a_health_response_with_no_build_block_at_all_fails():
    """What forge-mcp's /health looked like BEFORE this work: real fields, all
    of them true of every build ever made. A verifier must not read that as
    agreement."""
    r, _ = _run({"status": "ok", "service": "foundrynet-mcp",
                 "tools_count": 32, "transport": "streamable-http",
                 "forge_base_url": "https://forge.foundrynet.io"})
    assert r.returncode != 0
    assert "no build stamp at all" in _flat(r.stderr), r.stderr


def test_the_previous_build_still_serving_fails_the_deploy():
    r, _ = _run({"status": "ok",
                 "build": {"commit_short": "0000000ff",
                           "content_hash": "sha256:" + "0" * 64}})
    assert r.returncode != 0
    assert "still not the one just uploaded" in _flat(r.stderr)
    assert "0000000ff" in r.stderr and STAMP_COMMIT in r.stderr, \
        "the failure must print both what was wanted and what is serving"


def test_the_right_commit_with_the_wrong_content_hash_fails():
    """The case a commit check alone would wave through.

    `railway up` uploads a WORKING TREE. The same commit with a different tree
    is a different deployment, which is the entire reason content_hash exists.
    """
    r, _ = _run({"status": "ok",
                 "build": {"commit_short": STAMP_COMMIT,
                           "content_hash": "sha256:" + "a" * 64}})
    assert r.returncode != 0
    assert "still not the one just uploaded" in _flat(r.stderr)


def test_the_right_build_but_unhealthy_fails():
    r, _ = _run({"status": "degraded",
                 "build": {"commit_short": STAMP_COMMIT,
                           "content_hash": STAMP_HASH}})
    assert r.returncode != 0
    assert "status=degraded" in r.stderr


def test_forge_prods_healthy_is_also_accepted():
    """One verifier, two services. forge-mcp's /health says "ok" and
    forge-prod's says "healthy"; neither spelling may be the thing that fails
    a deploy."""
    r, _ = _run({"status": "healthy",
                 "build": {"commit_short": STAMP_COMMIT,
                           "content_hash": STAMP_HASH}})
    assert r.returncode == 0, r.stderr
    assert "status=healthy" in r.stdout


def test_an_unreachable_health_endpoint_fails_rather_than_passes():
    r, _ = _run("")                # curl returns nothing at all
    assert r.returncode != 0
    assert "no build stamp at all" in _flat(r.stderr)


def test_a_cloudflare_html_error_page_fails_rather_than_passes():
    """*.foundrynet.io is Cloudflare-fronted and 1010s a default user agent.
    A non-JSON body must not parse as agreement."""
    r, _ = _run("<html><title>Error 1010</title></html>")
    assert r.returncode != 0
    assert "no build stamp at all" in _flat(r.stderr)


def test_no_verify_skips_the_wait_but_still_stamps():
    r, repo = _run({"status": "ok", "build": {"commit_short": "nope"}},
                   args=("--yes", "--no-verify"))
    assert r.returncode == 0, r.stderr
    assert "skipping verification" in r.stdout
    assert _stamped(repo)


# ── the release gate ────────────────────────────────────────────────────────
# forge-mcp already HAD scripts/release_gate.sh -- five gates over tenancy, the
# auth matrix, REST/MCP parity, idempotency, ownership and cache scope -- and
# nothing in the deploy path ran it. A gate nobody runs is documentation.


def test_a_red_gate_refuses_the_deploy():
    r, repo = _run(GOOD, gate_exit=1)
    assert r.returncode != 0
    assert "release gate is RED" in _flat(r.stderr), r.stderr
    assert not _uploaded(repo), "railway was invoked despite a red gate"
    assert not _stamped(repo), \
        "the gate is checked BEFORE stamping, so nothing should be stamped"


def test_the_gate_actually_RAN():
    """The negative control for every gate test: a script that never invoked
    the gate would pass "a red gate refuses" only by accident of some other
    guard."""
    r, repo = _run(GOOD)
    assert r.returncode == 0, r.stderr
    assert os.path.exists(os.path.join(repo, "gate.log")), \
        "deploy.sh never ran the release gate"
    assert "release gate green" in r.stdout


def test_a_missing_gate_script_refuses():
    """An absent gate is not a green one."""
    work, repo, binr = _sandbox()
    os.remove(os.path.join(repo, "scripts", "release_gate.sh"))
    subprocess.run(["git", "commit", "-aqm", "drop the gate"], cwd=repo,
                   check=True, env={**os.environ, **GIT_ENV})
    r, repo = _run(GOOD, sandbox=(work, repo, binr))
    assert r.returncode != 0
    assert "cannot be run" in _flat(r.stderr), r.stderr
    assert not _uploaded(repo)


@pytest.mark.parametrize("code", [1, 2, 3, 77, 127])
def test_any_nonzero_gate_exit_refuses(code):
    """Only 0 is green. A gate that died on a missing interpreter (127) is not
    a gate that passed."""
    r, repo = _run(GOOD, gate_exit=code)
    assert r.returncode != 0, f"gate exit {code} was treated as green"
    assert not _uploaded(repo)


def test_a_red_gate_does_not_take_the_lock_at_all():
    """Ordering: the gate runs BEFORE the lock is taken, so a run that was
    never going to ship does not make every other deploy wait for it."""
    work = tempfile.mkdtemp(prefix="mcplock-")
    lock = os.path.join(work, "held.lock")
    _hold(lock)
    r, repo = _run(GOOD, gate_exit=1,
                   env_extra={"FORGE_MCP_DEPLOY_LOCK": lock})
    assert r.returncode != 0
    assert "release gate is RED" in _flat(r.stderr)
    assert "deploy lock is held" not in _flat(r.stderr)


# ── the tree and the branch ─────────────────────────────────────────────────
def test_a_dirty_tree_refuses_before_the_gate_even_runs():
    """`railway up` uploads the WORKING TREE, so with uncommitted changes there
    is no commit describing what ships and the gate's verdict is about
    different bytes. Without this the gate is bypassed by editing one file
    after it passes."""
    r, repo = _run(GOOD, dirty=True)
    assert r.returncode != 0
    assert "working tree is DIRTY" in _flat(r.stderr), r.stderr
    assert not _uploaded(repo)
    assert not os.path.exists(os.path.join(repo, "gate.log")), \
        "it ran the gate on bytes it had already decided not to ship"


def test_a_feature_branch_refuses():
    r, repo = _run(GOOD, branch="ops/some-feature")
    assert r.returncode != 0
    assert "not 'main'" in _flat(r.stderr), r.stderr
    assert not _uploaded(repo)


def test_a_directory_that_is_not_a_git_repo_refuses():
    r, repo = _run(GOOD, no_git=True)
    assert r.returncode != 0
    assert "not a git repository" in _flat(r.stderr), r.stderr
    assert not _uploaded(repo)


# ── THERE IS NO OVERRIDE, MEASURED ──────────────────────────────────────────
# A --force-deploy is a flag somebody adds to get one release out and nobody
# ever removes, and the thing it disables here is the gate that measures
# whether one tenant can read another's rows.
#
# These are BEHAVIOURAL ON PURPOSE. A test that greps the source for the
# absence of a flag name passes just as happily when the guard it was
# protecting has been deleted -- source-text reintroduction guards have
# already been proven vacuous in this program by deleting a fix, keeping the
# comments, and watching the test still pass. So each candidate override is
# actually PASSED to the script against a RED gate, and the script must still
# refuse and must still upload nothing.


@pytest.mark.parametrize("flag", [
    "--force", "--force-deploy", "-f", "--skip-gate", "--no-gate",
    "--ignore-gate", "--allow-dirty", "--override", "--skip-tests",
    "--no-test", "--yolo", "--force-lock", "--no-lock",
])
def test_no_FLAG_can_bypass_a_red_gate(flag):
    r, repo = _run(GOOD, gate_exit=1, args=("--yes", flag))
    assert r.returncode != 0, f"{flag} bypassed a red release gate"
    assert not _uploaded(repo), f"{flag} uploaded over a red gate"


@pytest.mark.parametrize("var,val", [
    ("FORCE_DEPLOY", "1"), ("FORGE_FORCE_DEPLOY", "1"),
    ("SKIP_GATE", "1"), ("NO_GATE", "1"), ("IGNORE_GATE", "1"),
    ("SKIP_TESTS", "1"), ("FORCE", "1"), ("CI", "1"),
    # The two that would be real if the constants had been written as
    # `${VAR:-default}` -- an override wearing a configuration costume.
    ("GATE_SCRIPT", "/usr/bin/true"), ("GATE_SCRIPT", "true"),
    ("GATE_CHECK", "verify"),
])
def test_no_ENV_VAR_can_bypass_a_red_gate(var, val):
    r, repo = _run(GOOD, gate_exit=1, env_extra={var: val})
    assert r.returncode != 0, f"{var}={val} bypassed a red release gate"
    assert not _uploaded(repo), f"{var}={val} uploaded over a red gate"
    assert "release gate is RED" in _flat(r.stderr), r.stderr


@pytest.mark.parametrize("var", ["DEPLOY_BRANCH", "BRANCH", "FORGE_BRANCH",
                                 "GIT_BRANCH", "RAILWAY_GIT_BRANCH"])
def test_no_ENV_VAR_can_bypass_the_branch_check(var):
    """`DEPLOY_BRANCH="${DEPLOY_BRANCH:-main}"` would let a deploy name
    whatever branch it is already on and delete the check."""
    r, repo = _run(GOOD, branch="ops/some-feature",
                   env_extra={var: "ops/some-feature"})
    assert r.returncode != 0, f"{var} bypassed the branch check"
    assert "not 'main'" in _flat(r.stderr), r.stderr
    assert not _uploaded(repo)


@pytest.mark.parametrize("flag", ["--allow-dirty", "--force", "--dirty",
                                  "--no-clean"])
def test_no_FLAG_can_bypass_the_dirty_tree_check(flag):
    r, repo = _run(GOOD, dirty=True, args=("--yes", flag))
    assert r.returncode != 0, f"{flag} deployed a dirty tree"
    assert not _uploaded(repo)


@pytest.mark.parametrize("var,val", [("FORCE_LOCK", "1"), ("NO_LOCK", "1"),
                                     ("SKIP_LOCK", "1"), ("IGNORE_LOCK", "1"),
                                     ("FORCE_DEPLOY", "1")])
def test_no_ENV_VAR_can_bypass_a_HELD_LOCK(var, val):
    """FORGE_MCP_DEPLOY_LOCK relocates the lock for TESTS; it must not be a way
    to deploy past a held one, and nor may anything else."""
    work = tempfile.mkdtemp(prefix="mcplock-")
    lock = os.path.join(work, "held.lock")
    _hold(lock)
    r, repo = _run(GOOD, env_extra={"FORGE_MCP_DEPLOY_LOCK": lock, var: val})
    assert r.returncode != 0, f"{var}={val} deployed past a held lock"
    assert not _uploaded(repo)
    assert "deploy lock is held" in _flat(r.stderr)


def test_an_unknown_argument_is_refused_rather_than_ignored():
    """An argument the parser does not know must stop the deploy, not be
    silently dropped -- a typo'd flag that is ignored looks like a flag that
    worked."""
    r, repo = _run(GOOD, args=("--yes", "--definitely-not-a-flag"))
    assert r.returncode != 0
    assert "unknown argument" in r.stderr
    assert not _uploaded(repo)


# ── THE DEPLOY LOCK ─────────────────────────────────────────────────────────
# `railway up` uploads a WORKING TREE and this script proves what landed by
# polling /health for its own stamp, so two concurrent deploys race on both
# halves: the later upload wins, and the loser's verification compares /health
# against a stamp that never became the serving build. It then either times out
# blaming the wrong thing or, if both runs shipped the same bytes, passes while
# having had no effect.
#
# The lock path is DIFFERENT from forge-prod's $HOME/.forge-deploy.lock --
# these are two services, and a shared lock would make a kernel deploy block an
# MCP deploy for no reason.


def _hold(lock_dir, *, pid="1"):
    """Pre-create the lock as if another deploy held it."""
    os.makedirs(lock_dir)
    with open(os.path.join(lock_dir, "owner"), "w") as fh:
        fh.write("pid=%s\nhost=otherbox\ncommit=deadbeef\n"
                 "started=2026-10-08T00:00:00Z\n" % pid)


def test_the_lock_path_is_forge_mcps_own():
    """Driven, not grepped: with no FORGE_MCP_DEPLOY_LOCK set the script must
    name a forge-mcp lock, and must NOT reach for forge-prod's."""
    work, repo, binr = _sandbox()
    env_extra = {"FORGE_MCP_DEPLOY_LOCK": ""}      # unset -> fall back
    r, repo = _run(GOOD, sandbox=(work, repo, binr), env_extra=env_extra,
                   args=("--yes", "--no-verify"))
    assert r.returncode == 0, r.stdout + r.stderr
    assert ".forge-mcp-deploy.lock" in r.stdout, r.stdout
    assert ".forge-deploy.lock," not in r.stdout, \
        "it took forge-prod's lock, so an MCP deploy blocks a kernel deploy"


def test_a_successful_deploy_releases_the_lock():
    r, repo = _run(GOOD)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "deploy lock taken" in r.stdout
    assert not os.path.exists(r.lock_dir), \
        "the lock survived a SUCCESSFUL deploy, so the next one is blocked"


def test_a_held_lock_refuses_the_deploy_and_UPLOADS_NOTHING():
    work = tempfile.mkdtemp(prefix="mcplock-")
    lock = os.path.join(work, "held.lock")
    _hold(lock)
    r, repo = _run(GOOD, env_extra={"FORGE_MCP_DEPLOY_LOCK": lock})
    assert r.returncode != 0, "it deployed while another deploy held the lock"
    assert "deploy lock is held" in _flat(r.stderr)
    assert not _uploaded(repo), \
        "it uploaded to production despite the lock being held"


def test_a_refused_run_does_not_steal_the_holders_lock():
    """The HELD_BY_US guard. Without it the loser's EXIT trap removes the
    winner's lock, so the second attempt succeeds and the lock protects
    nothing -- which is worse than no lock, because it looks like one."""
    work = tempfile.mkdtemp(prefix="mcplock-")
    lock = os.path.join(work, "held.lock")
    _hold(lock)
    r, repo = _run(GOOD, env_extra={"FORGE_MCP_DEPLOY_LOCK": lock})
    assert r.returncode != 0
    assert os.path.isdir(lock), \
        "a run that was REFUSED the lock deleted it on the way out"
    assert os.path.exists(os.path.join(lock, "owner")), \
        "it deleted the holder's owner file"


def test_a_FAILED_deploy_still_releases_the_lock():
    """A deploy that dies in verification must not block every one after it."""
    stale = {"status": "ok",
             "build": {"commit_short": "0000000", "content_hash": "sha256:old"}}
    r, repo = _run(stale, timeout_s="2", poll_s="1")
    assert r.returncode != 0, "the stale-build case was supposed to fail"
    assert not os.path.exists(r.lock_dir), \
        "a FAILED deploy left the lock held, blocking every later deploy"


def test_a_red_gate_releases_the_lock_too():
    r, repo = _run(GOOD, gate_exit=1)
    assert r.returncode != 0
    assert not os.path.exists(r.lock_dir)


def test_no_verify_releases_the_lock():
    r, repo = _run(GOOD, args=("--yes", "--no-verify"))
    assert r.returncode == 0, r.stdout + r.stderr
    assert not os.path.exists(r.lock_dir)


def test_the_lock_is_taken_before_the_stamp():
    r, repo = _run(GOOD)
    assert r.returncode == 0, r.stderr
    assert r.stdout.index("deploy lock taken") < r.stdout.index("stamped"), \
        "it stamped before taking the lock, so two runs can race on the stamp"


def test_the_refusal_says_whether_the_holder_is_still_running():
    work = tempfile.mkdtemp(prefix="mcplock-")
    lock = os.path.join(work, "held.lock")
    # pid 1 is launchd: alive, and owned by ROOT. That second half is the
    # point. kill(2) returns EPERM rather than ESRCH for a live process owned
    # by another user, and the shell cannot tell those apart, so a `kill -0`
    # implementation calls a RUNNING deploy stale and tells the operator to
    # rm -rf a live lock. `ps -p` asks the question that was actually meant.
    _hold(lock, pid="1")
    r, _ = _run(GOOD, env_extra={"FORGE_MCP_DEPLOY_LOCK": lock})
    flat = _flat(r.stderr)
    assert "IS STILL RUNNING" in flat, flat
    assert "STALE" not in flat, \
        "a live root-owned holder was reported as a stale lock"


def _dead_pid() -> str:
    """A pid that provably does not exist RIGHT NOW.

    Hardcoding one (99999, say) is wrong on Linux, where pid_max defaults to
    4194304 and that pid may well be live on a busy CI runner -- the test would
    then measure nothing and fail for an unrelated reason.
    """
    for candidate in range(99999, 400000):
        try:
            os.kill(candidate, 0)
        except ProcessLookupError:
            return str(candidate)
        except PermissionError:
            continue                           # alive, owned by someone else
    pytest.skip("no free pid found to simulate a stale lock")


def test_the_refusal_identifies_a_STALE_lock_and_says_how_to_clear_it():
    work = tempfile.mkdtemp(prefix="mcplock-")
    lock = os.path.join(work, "held.lock")
    _hold(lock, pid=_dead_pid())
    r, _ = _run(GOOD, env_extra={"FORGE_MCP_DEPLOY_LOCK": lock})
    flat = _flat(r.stderr)
    assert "STALE" in flat, flat
    assert f"rm -rf {lock}" in flat, "it does not say how to clear a stale lock"


def test_the_refusal_names_the_holder():
    work = tempfile.mkdtemp(prefix="mcplock-")
    lock = os.path.join(work, "held.lock")
    _hold(lock)
    r, _ = _run(GOOD, env_extra={"FORGE_MCP_DEPLOY_LOCK": lock})
    flat = _flat(r.stderr)
    assert "otherbox" in flat and "deadbeef" in flat, flat


def test_a_held_lock_with_no_owner_file_still_refuses():
    """Absence of evidence is not permission."""
    work = tempfile.mkdtemp(prefix="mcplock-")
    lock = os.path.join(work, "held.lock")
    os.makedirs(lock)                          # no owner file written
    r, _ = _run(GOOD, env_extra={"FORGE_MCP_DEPLOY_LOCK": lock})
    assert r.returncode != 0
    assert "deploy lock is held" in _flat(r.stderr)


def test_the_lock_records_who_holds_it():
    r, repo = _run(GOOD, args=("--yes", "--no-verify"))
    assert r.returncode == 0, r.stderr
    assert "pid " in r.stdout, r.stdout


def test_CONCURRENCY_exactly_one_of_two_simultaneous_deploys_wins():
    """The property the whole thing exists for, measured rather than argued.

    mkdir(2) is atomic, which is why it is the lock: `[ -e ]` followed by
    `mkdir -p` has a check-then-act window that this test would walk through
    perhaps one run in ten, which is the worst kind of failure to ship.
    """
    work = tempfile.mkdtemp(prefix="mcplockrace-")
    lock = os.path.join(work, "shared.lock")
    results = []

    def go():
        r, _ = _run(GOOD, args=("--yes", "--no-verify"),
                    env_extra={"FORGE_MCP_DEPLOY_LOCK": lock})
        results.append(r)

    ts = [threading.Thread(target=go) for _ in range(2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    assert len(results) == 2
    winners = [r for r in results if r.returncode == 0]
    losers = [r for r in results if r.returncode != 0]
    # Either they genuinely overlapped (1 win, 1 refused) or they did not
    # overlap at all (2 wins) -- but NEVER two winners that both uploaded while
    # the other held the lock, and never two losers.
    assert len(winners) >= 1, \
        "both concurrent deploys were refused: " + \
        "; ".join(_flat(r.stderr)[:200] for r in results)
    if losers:
        assert len(winners) == 1 and len(losers) == 1
        assert "deploy lock is held" in _flat(losers[0].stderr)
    assert not os.path.exists(lock), "the winner did not release the lock"


# ── THE ARCHIVE ROOT ────────────────────────────────────────────────────────
# `railway up` archives the CLOSEST LINKED project directory from
# ~/.railway/config.json, walking UP the tree -- not $PWD. On 2026-10-09 three
# repos were found unlinked and resolving to $HOME; three deploys hung at
# `Indexing...` for 18, 9 and 6 minutes walking the entire home directory, never
# reaching the network and never creating a deployment record.
#
# The hang was the SAFE outcome: had one completed it would have uploaded every
# .env on the machine and served them as production. ~/forge-mcp was worse than
# the others -- $HOME's link names a DIFFERENT SERVICE (market-data-mcp), so an
# unlinked forge-mcp would have deployed itself onto someone else's service.
#
# BEHAVIOURAL, not a grep of the script. Each case writes a real link map into a
# sandbox HOME and drives deploy.sh, so the guard is exercised rather than
# described.


def test_a_correctly_linked_directory_DEPLOYS():
    """The negative control. Without it, a guard that refused everything would
    pass every test below."""
    r, repo = _run(GOOD)                 # link_dir defaults to the repo itself
    assert r.returncode == 0, r.stdout + r.stderr
    assert "archive root is" in r.stdout


def test_an_unlinked_directory_REFUSES():
    work_parent = tempfile.mkdtemp(prefix="mcplinkmap-")
    r, repo = _run(GOOD, link_dir=work_parent)
    assert r.returncode != 0, "it would have archived an unrelated tree"
    assert "would archive" in _flat(r.stderr), _flat(r.stderr)


def test_nothing_linked_at_all_REFUSES():
    r, repo = _run(GOOD, link_dir="")
    assert r.returncode != 0
    assert "nothing linked" in _flat(r.stderr), _flat(r.stderr)


def test_a_LINKED_ANCESTOR_refuses_because_that_is_the_real_bug():
    """The exact 2026-10-09 shape: the directory itself is not linked but a
    PARENT is, so railway up silently archives the parent -- and, for
    ~/forge-mcp, onto the parent's service."""
    work, repo, binr = _sandbox()
    # Re-point the link map at the repo's PARENT rather than the repo.
    with open(os.path.join(work, ".railway", "config.json"), "w") as fh:
        json.dump({"projects": {work: {"service": "svc"}}}, fh)
    r, repo = _run(GOOD, sandbox=(work, repo, binr))
    assert r.returncode != 0, (
        "a LINKED ANCESTOR was accepted -- this is the exact defect: railway up "
        "would archive the parent, not the repo")
    flat = _flat(r.stderr)
    assert work in flat, flat
    assert "railway link" in flat, "it does not say how to fix it"
    assert "162115b7-b420-4a02-8cff-ddad7be02dc2" in flat, \
        "the fix it suggests does not name forge-mcp's service"


def test_the_archive_refusal_happens_BEFORE_the_stamp_and_the_upload():
    """Order matters: refusing after the stamp would leave build_info.json
    describing a deploy that never happened."""
    work_parent = tempfile.mkdtemp(prefix="mcporder-")
    r, repo = _run(GOOD, link_dir=work_parent)
    assert r.returncode != 0
    assert "stamped" not in r.stdout, "it stamped before checking the root"
    assert not _uploaded(repo), "it uploaded despite the wrong archive root"
    assert not _stamped(repo)


@pytest.mark.parametrize("var,val", [
    ("RAILWAY_PROJECT_ID", "4d8c76bb-c5fc-4eec-baa0-5e8f85579cbf"),
    ("RAILWAY_SERVICE_ID", "162115b7-b420-4a02-8cff-ddad7be02dc2"),
    ("FORCE_DEPLOY", "1"), ("SKIP_ARCHIVE_CHECK", "1"),
    ("ARCHIVE_ROOT", ""), ("ARCHIVE_ROOT", "/does/not/matter"),
])
def test_no_ENV_VAR_can_bypass_the_archive_root_guard(var, val):
    """ARCHIVE_ROOT in particular: it is a plain assignment from a subshell, so
    pre-setting it in the environment must not win."""
    work_parent = tempfile.mkdtemp(prefix="mcpbypass-")
    r, repo = _run(GOOD, link_dir=work_parent, env_extra={var: val})
    assert r.returncode != 0, f"{var}={val} bypassed the archive-root guard"
    assert not _uploaded(repo)
    assert "would archive" in _flat(r.stderr), r.stderr
