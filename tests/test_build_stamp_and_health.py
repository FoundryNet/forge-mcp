"""The build stamp, and what /health says with and without it.

WHY. Until stamp_build.py, `GET https://mcp.foundrynet.io/health` reported
`status`, `service`, `tools_count`, `forge_base_url` and a handful of booleans
about configuration presence -- every one of which was true of EVERY build this
service has ever had. There was no commit, no content hash and no build time, so
"what is running?" was unanswerable and `deploy.sh` had nothing to verify
against.

THE FAILURE MODE THIS FILE GUARDS IS THE QUIET ONE. A missing stamp that
surfaces as a null, or as an absent key, is indistinguishable from a stamped
build whose commit happened to be empty -- so a deploy that skipped the stamp
looks exactly like a deploy that worked. The fix is an explicit sentence:
`build_info.json absent — deploy did not run stamp_build.py`, with commit,
content_hash and built_at present and null. That sentence is asserted here.

Everything is driven: stamp_build.py is executed in sandboxes and its output
read back, and /health is served by the real ASGI app.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
STAMP = REPO / "stamp_build.py"

REQUIRED_KEYS = {"commit", "commit_short", "content_hash", "built_at", "dirty",
                 "identity_source"}


def _sandbox(tmp_path, *, extra=None):
    """A minimal repo-shaped tree: the stamp plus a few files for it to hash."""
    d = tmp_path / "tree"
    d.mkdir(parents=True)
    shutil.copy(STAMP, d / "stamp_build.py")
    (d / "mcp_server.py").write_text("# pretend server\n")
    (d / "gating.py").write_text("# pretend gate\n")
    (d / "requirements.txt").write_text("fastmcp>=3.4.5,<4\n")
    (d / "scripts").mkdir()
    (d / "scripts" / "release_gate.sh").write_text("#!/usr/bin/env bash\n")
    for rel, body in (extra or {}).items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return d


def _stamp(d, *args, env=None):
    e = {**os.environ, **(env or {})}
    # The sandbox is not a git repo, so git-derived fields come back null unless
    # Railway's identity is injected. That is the point of several tests below.
    r = subprocess.run([sys.executable, "stamp_build.py", *args], cwd=d,
                       capture_output=True, text=True, env=e, timeout=120)
    return r


def _read(d):
    return json.loads((d / "build_info.json").read_text())


# ── the stamp writes what a verifier needs ──────────────────────────────────
def test_the_stamp_carries_every_field_a_verifier_reads(tmp_path):
    d = _sandbox(tmp_path)
    r = _stamp(d)
    assert r.returncode == 0, r.stderr
    info = _read(d)
    missing = REQUIRED_KEYS - set(info)
    assert not missing, f"the stamp omits {missing}"
    assert info["content_hash"].startswith("sha256:"), info["content_hash"]
    assert len(info["content_hash"]) == len("sha256:") + 64
    assert info["built_at"].endswith("Z"), info["built_at"]
    assert info["stamped"] is True


def test_the_content_hash_is_deterministic(tmp_path):
    """A hash that depends on directory walk order is not a hash of the
    content, it is a hash of the filesystem -- it would differ between a laptop
    and a container holding identical bytes."""
    d = _sandbox(tmp_path)
    _stamp(d)
    first = _read(d)["content_hash"]
    os.remove(d / "build_info.json")
    _stamp(d)
    assert _read(d)["content_hash"] == first


def test_the_hash_does_not_include_the_stamp_itself(tmp_path):
    """Hashing build_info.json into itself would make each hash depend on the
    previous one, so the same bytes would stamp differently on a re-run."""
    d = _sandbox(tmp_path)
    _stamp(d)
    first = _read(d)["content_hash"]
    _stamp(d)                    # a stamp now exists on disk while hashing
    assert _read(d)["content_hash"] == first


def test_changing_a_SHIPPED_file_changes_the_hash(tmp_path):
    """The property the whole field exists for: `railway up` uploads a TREE, so
    the same commit with a different tree must hash differently."""
    d = _sandbox(tmp_path)
    _stamp(d)
    first = _read(d)["content_hash"]
    (d / "mcp_server.py").write_text("# pretend server, edited\n")
    _stamp(d)
    assert _read(d)["content_hash"] != first


def test_changing_an_EXCLUDED_file_does_not_change_the_hash(tmp_path):
    """The documented exclusions have to actually be excluded, or the hash
    describes something other than what shipped."""
    d = _sandbox(tmp_path, extra={"__pycache__/x.pyc": "a",
                                  ".env": "SECRET=1\n",
                                  "notes.bak.txt": "a",
                                  "migrations/001.sql": "select 1;\n"})
    _stamp(d)
    first = _read(d)["content_hash"]
    (d / "__pycache__" / "x.pyc").write_text("b")
    (d / ".env").write_text("SECRET=2\n")
    (d / "notes.bak.txt").write_text("b")
    (d / "migrations" / "001.sql").write_text("select 2;\n")
    _stamp(d)
    assert _read(d)["content_hash"] == first


def test_a_secret_file_is_not_counted_in_the_shipped_set(tmp_path):
    """.env and *.key are gitignored, so they are not in the uploaded tree.
    Counting them would also mean a stamp whose file_count leaks their
    existence."""
    plain = _sandbox(tmp_path / "a")
    _stamp(plain)
    n = _read(plain)["file_count"]
    withsecrets = _sandbox(tmp_path / "b",
                           extra={".env": "X=1\n", "tls.key": "-----\n"})
    _stamp(withsecrets)
    assert _read(withsecrets)["file_count"] == n


# ── Railway is the primary identity source ──────────────────────────────────
def test_railway_git_env_is_the_primary_identity(tmp_path):
    """There is no .git in the Railpack container, so every git-derived field
    would stamp as null on a GitHub-connected deploy. Railway injects the
    commit it built; that is the authoritative identity there."""
    d = _sandbox(tmp_path)
    sha = "b" * 40
    r = _stamp(d, env={"RAILWAY_GIT_COMMIT_SHA": sha,
                       "RAILWAY_GIT_BRANCH": "main",
                       "RAILWAY_GIT_COMMIT_MESSAGE": "a commit"})
    assert r.returncode == 0, r.stderr
    info = _read(d)
    assert info["commit"] == sha
    assert info["commit_short"] == sha[:9]
    assert info["branch"] == "main"
    assert info["identity_source"] == "railway_git_env"
    # A GitHub-sourced build IS the commit: there is no mechanism by which an
    # uncommitted edit reaches it, so this is a fact rather than an assumption.
    assert info["dirty"] is False


def test_runtime_without_railway_env_leaves_an_existing_stamp_ALONE(tmp_path):
    """The Procfile runs `--runtime` on every boot, including boots that are
    not GitHub-connected deploys. Overwriting a good laptop stamp with a blank
    one there would destroy the only record of what was uploaded."""
    d = _sandbox(tmp_path)
    _stamp(d, env={"RAILWAY_GIT_COMMIT_SHA": "c" * 40})
    before = _read(d)
    r = _stamp(d, "--runtime", env={"RAILWAY_GIT_COMMIT_SHA": ""})
    assert r.returncode == 0, r.stderr
    assert _read(d) == before, "a non-Railway --runtime run clobbered the stamp"
    assert "leaving existing stamp untouched" in r.stdout


def test_runtime_with_railway_env_DOES_stamp(tmp_path):
    d = _sandbox(tmp_path)
    r = _stamp(d, "--runtime", env={"RAILWAY_GIT_COMMIT_SHA": "d" * 40,
                                    "RAILWAY_GIT_BRANCH": "main"})
    assert r.returncode == 0, r.stderr
    assert _read(d)["commit"] == "d" * 40


def test_show_reports_a_missing_stamp_as_a_failure(tmp_path):
    d = _sandbox(tmp_path)
    r = _stamp(d, "--show")
    assert r.returncode != 0
    assert "no build_info.json" in r.stdout


# ── the Procfile stamps at process start ────────────────────────────────────
def test_the_PROCFILE_stamps_before_it_serves(tmp_path):
    """BEHAVIOURAL. Every segment of the Procfile's web command EXCEPT the last
    (which starts the server) is executed in a sandbox, and a stamp must exist
    afterwards. If the stamp line were removed there would be no segment before
    the server and nothing would be written -- which is exactly the regression
    this catches, and it catches it without grepping for a string."""
    web = None
    for line in (REPO / "Procfile").read_text().splitlines():
        if line.startswith("web:"):
            web = line[len("web:"):].strip()
    assert web, "the Procfile declares no web process"

    segments = [s.strip() for s in web.split(";") if s.strip()]
    assert len(segments) >= 2, (
        "the Procfile's web command is a single segment, so nothing runs "
        f"before the server starts: {web!r}")
    prelude = segments[:-1]
    assert "mcp_server" in segments[-1], \
        f"the last segment is not the server: {segments[-1]!r}"

    d = _sandbox(tmp_path)
    env = {**os.environ, "RAILWAY_GIT_COMMIT_SHA": "e" * 40,
           "RAILWAY_GIT_BRANCH": "main"}
    r = subprocess.run(["bash", "-c", "; ".join(prelude)], cwd=d, env=env,
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    assert (d / "build_info.json").exists(), \
        "the Procfile prelude did not write a stamp"
    assert _read(d)["commit"] == "e" * 40


def test_a_broken_stamp_does_not_stop_the_server_from_starting(tmp_path):
    """`|| true` is deliberate: an unstamped build that starts and reports
    "stamped": false is visible. A crash-looping container that reports nothing
    is strictly worse."""
    web = [l for l in (REPO / "Procfile").read_text().splitlines()
           if l.startswith("web:")][0][len("web:"):].strip()
    prelude = [s.strip() for s in web.split(";") if s.strip()][:-1]
    d = _sandbox(tmp_path)
    (d / "stamp_build.py").write_text("import sys; sys.exit(9)\n")
    r = subprocess.run(["bash", "-c", "; ".join(prelude)], cwd=d,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, (
        "a failing stamp propagated a non-zero status into the start command, "
        "which would crash-loop the container")


# ── /health ─────────────────────────────────────────────────────────────────
def test_health_reports_the_build_block():
    import mcp_server
    from starlette.testclient import TestClient

    body = TestClient(mcp_server.build_dual_app()).get("/health").json()
    assert "build" in body, (
        "/health carries no build block, so a deploy cannot be verified: "
        f"keys were {sorted(body)}")
    assert isinstance(body["build"], dict)


def test_an_ABSENT_stamp_is_reported_AS_A_SENTENCE():
    """The load-bearing assertion of this file.

    A null that looks like a missing field is the bug: it is
    indistinguishable from a stamped build whose commit happened to be empty.
    An explicit sentence is the fix, and the key names match forge-prod's so
    ONE verifier reads both services.
    """
    import mcp_server

    saved = REPO / "build_info.json"
    backup = None
    if saved.exists():
        backup = saved.read_bytes()
        saved.unlink()
    try:
        info = mcp_server._load_build_info()
    finally:
        if backup is not None:
            saved.write_bytes(backup)

    assert info["stamped"] is False
    assert info["note"] == ("build_info.json absent — deploy did not run "
                            "stamp_build.py")
    # PRESENT and null, not absent. A verifier reading .get("commit_short")
    # must get None rather than a KeyError, and a human reading the JSON must
    # see the fields that are missing rather than infer them.
    for k in ("commit", "commit_short", "content_hash", "built_at"):
        assert k in info, f"{k} is absent rather than explicitly null"
        assert info[k] is None, f"{k} is {info[k]!r}, not null"


def test_a_PRESENT_stamp_is_what_health_reports(tmp_path):
    """Round trip: what stamp_build.py writes is what /health hands the
    verifier, under the key names deploy.sh polls for."""
    import mcp_server

    saved = REPO / "build_info.json"
    backup = saved.read_bytes() if saved.exists() else None
    payload = {"commit": "f" * 40, "commit_short": "fffffffff",
               "content_hash": "sha256:" + "0" * 64,
               "built_at": "2026-10-09T00:00:00Z", "dirty": False,
               "identity_source": "railway_git_env", "stamped": True}
    try:
        saved.write_text(json.dumps(payload))
        info = mcp_server._load_build_info()
    finally:
        if backup is not None:
            saved.write_bytes(backup)
        elif saved.exists():
            saved.unlink()

    assert info["commit_short"] == "fffffffff"
    assert info["content_hash"] == "sha256:" + "0" * 64
    assert info["stamped"] is True


def test_the_build_block_leaks_no_configuration_values():
    """/health is unauthenticated. The stamp names a commit and a hash; it must
    never carry an env value, and `stamped_by` is a username, not a secret."""
    import mcp_server

    blob = json.dumps(mcp_server._BUILD_INFO).lower()
    for forbidden in ("supabase_service_key", "fnet_", "sb_secret", "sk_live",
                      "jwt_secret", "stripe", "bearer "):
        assert forbidden not in blob, f"the build block carries {forbidden!r}"
