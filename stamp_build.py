#!/usr/bin/env python3
"""Write build_info.json immediately before a deploy. Run by deploy.sh.

    python3 stamp_build.py            # stamp
    python3 stamp_build.py --runtime  # stamp from Railway's injected identity
    python3 stamp_build.py --show     # print what the last stamp says

WHY THIS EXISTS
---------------
Until this file, `GET /health` on mcp.foundrynet.io carried NO build identity at
all: no commit, no content hash, no build time. It reported `tools_count`,
`forge_base_url` and a handful of booleans about configuration presence -- all
true of every build this service has ever had. So "what is running on
mcp.foundrynet.io?" had no answer, and a deploy script could not verify
anything, because there was nothing to compare against.

This is forge-prod's design, copied rather than reinvented, so that ONE verifier
can read both services' /health. Key names are identical on purpose.

The commit SHA alone would be a half-answer and a misleading one, because
`railway up` ships uncommitted edits too. A SHA stamped next to a dirty tree
names a commit that does not describe what was deployed.

So the stamp carries four load-bearing things:

  commit        the SHA, for provenance when the tree IS clean
  dirty         whether anything was uncommitted at deploy time, plus HOW MANY
                files and lines -- so a reader knows the SHA is partial
  content_hash  a hash over the actual DEPLOYED FILE SET. This is the only field
                that identifies what really shipped. Two deploys with the same
                content_hash are the same bytes regardless of git state.
  built_at      UTC, so "is this the build from Friday?" is answerable

THE FILE SET THAT IS HASHED
---------------------------
`content_hash` is computed over the same file set `railway up` sends, which for
this repo is "the working tree minus caches, secrets and backups". Concretely:

  INCLUDED  mcp_server.py, gating.py, Procfile, requirements.txt, server.json,
            smithery.yaml, pytest.ini, README.md, LICENSE, scripts/*, tests/*
            -- i.e. every regular file under this directory not excluded below.
            tests/ IS included deliberately: it is in the uploaded tree, so a
            test-only edit really is a different deployment and the hash should
            say so. A hash that quietly ignores part of the upload is worse than
            no hash, because it claims two different uploads are the same bytes.

  EXCLUDED  SKIP_DIRS      .git, __pycache__, .venv/venv, node_modules,
                           .pytest_cache, .mypy_cache, migrations (gitignored),
                           plus every dotted directory
            SKIP_SUFFIX    .pyc, .pyo, .log, .key, .tar, .tar.gz
            SKIP_CONTAINS  .bak., .backup       (gitignored local backups)
            SKIP_NAMES     build_info.json      (never hash the stamp into
                                                 itself -- the hash would depend
                                                 on the previous hash)
            plus every dotfile (.env, .gitignore, .DS_Store)

  A file excluded here but actually uploaded, or included here but not uploaded,
  makes content_hash describe something other than what shipped. These lists
  mirror .gitignore; if .gitignore changes, change them together.

DETERMINISM
-----------
Paths are sorted and hashed as `path\\0sha256(bytes)\\n`. Sorting matters -- a
hash that depends on directory walk order is not a hash of the content, it is a
hash of the filesystem, and it would differ between a laptop and a container
holding identical bytes.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "build_info.json")

# Mirrors .gitignore / what the uploader skips. See THE FILE SET above.
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules",
             ".pytest_cache", ".mypy_cache", ".benchmarks", "migrations"}
SKIP_SUFFIX = (".pyc", ".pyo", ".log", ".key", ".tar", ".tar.gz")
SKIP_CONTAINS = (".bak.", ".backup")
# `build_info.json` is never hashed into itself. The two CI artefacts are
# written INTO the workspace by release-gate.yml, so on a runner -- or on a
# laptop that has just run the suite -- they would otherwise join the hash and
# make two identical trees report different content_hashes. Both are excluded
# from the upload as well; .railwayignore and this set have to agree, which
# tests/test_the_build_stamp_actually_ships.py asserts.
SKIP_NAMES = {"build_info.json", "junit.xml", "pytest.out"}


def _git(*a):
    try:
        r = subprocess.run(["git", *a], cwd=HERE, capture_output=True,
                           text=True, timeout=60)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""


def deployed_files() -> list:
    out = []
    for root, dirs, files in os.walk(HERE):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS
                         and not d.startswith("."))
        for f in sorted(files):
            if f in SKIP_NAMES or f.startswith("."):
                continue
            if f.endswith(SKIP_SUFFIX) or any(s in f for s in SKIP_CONTAINS):
                continue
            out.append(os.path.relpath(os.path.join(root, f), HERE))
    return sorted(out)


def content_hash(paths: list) -> tuple:
    h = hashlib.sha256()
    total = 0
    for rel in paths:                      # already sorted; order is the point
        p = os.path.join(HERE, rel)
        try:
            with open(p, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        total += len(data)
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(hashlib.sha256(data).hexdigest().encode())
        h.update(b"\n")
    return h.hexdigest(), len(paths), total


def dirty_state() -> dict:
    """What is uncommitted RIGHT NOW -- the part a bare SHA would hide."""
    porcelain = _git("status", "--porcelain", ".")
    lines = [l for l in porcelain.splitlines()
             if l.strip() and not l.rstrip().endswith(".pyc")]
    modified = [l[3:] for l in lines if l[:2].strip() in ("M", "MM", "AM")]
    untracked = [l[3:] for l in lines if l[:2] == "??"]
    stat = _git("diff", "--shortstat", "--", ".", ":!*.pyc")
    return {
        "dirty": bool(lines),
        "modified_tracked": len(modified),
        "untracked": len(untracked),
        "diff_shortstat": stat or None,
        "note": ("deploys upload a working tree, so `commit` alone does not "
                 "describe what shipped; `content_hash` does"),
    }


# ── Railway-sourced identity (--runtime) ─────────────────────────────────────
# WHY. `railway up` uploads a working tree, so the only honest identity was a
# content hash plus a dirty flag. A GitHub-connected service is different:
# Railway resolves a COMMIT and builds exactly that, so the SHA is authoritative
# and `dirty` is provably false -- nobody's laptop is in the path.
#
# There is no .git in the Railpack container, so `git rev-parse` returns nothing
# and every git-derived field would stamp as null. That is how a /health can come
# to report a content_hash from a build three deploys old: the stamp is written
# on a laptop before upload, and once deploys stop going through that laptop
# nothing writes it at all. So read the identity Railway injects instead.
#
# Run from the start command (Procfile), not the build: the start command sees
# the same RAILWAY_GIT_* vars, the container filesystem is writable, and hashing
# the files that are ACTUALLY in the running image is strictly better evidence
# than hashing a directory that was about to be uploaded.
def railway_identity() -> dict:
    """Commit identity from Railway's injected env. {} when not on Railway."""
    sha = os.environ.get("RAILWAY_GIT_COMMIT_SHA") or ""
    if not sha:
        return {}
    return {
        "commit": sha,
        "commit_short": sha[:9],
        "branch": os.environ.get("RAILWAY_GIT_BRANCH") or None,
        "commit_subject": os.environ.get("RAILWAY_GIT_COMMIT_MESSAGE") or None,
        "commit_at": os.environ.get("RAILWAY_GIT_COMMIT_AUTHOR_DATE") or None,
        # A GitHub-sourced build IS the commit. Not "assumed clean" -- there is
        # no mechanism by which an uncommitted edit reaches it.
        "dirty": False,
        "modified_tracked": 0,
        "untracked": 0,
        "diff_shortstat": None,
        "identity_source": "railway_git_env",
    }


def build() -> dict:
    paths = deployed_files()
    chash, count, total = content_hash(paths)
    rw = railway_identity()
    d = dirty_state()
    git_fields = {
        "commit": _git("rev-parse", "HEAD") or None,
        "commit_short": _git("rev-parse", "--short", "HEAD") or None,
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD") or None,
        "commit_subject": _git("log", "-1", "--format=%s") or None,
        "commit_at": _git("log", "-1", "--format=%cI") or None,
        **d,
        "identity_source": "local_git",
    }
    # Railway's identity wins when present: inside the container it is the only
    # one that exists, and it is the stronger claim.
    return {
        **git_fields,
        **rw,
        # Explicit, so /health never has to infer "stamped" from the presence of
        # a key. The unstamped branch reports stamped=false next to the same
        # key names, which is what makes one verifier able to read both states.
        "stamped": True,
        "service": "foundrynet-mcp",
        "content_hash": f"sha256:{chash}",
        "file_count": count,
        "total_bytes": total,
        "built_at": datetime.datetime.now(datetime.timezone.utc)
                    .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "image": os.environ.get("RAILWAY_DEPLOYMENT_ID") or "railway:railpack",
        "stamped_by": os.environ.get("USER", "unknown"),
    }


def main() -> int:
    if "--runtime" in sys.argv and not os.environ.get("RAILWAY_GIT_COMMIT_SHA"):
        # Not on a GitHub-connected Railway deploy. Leave any existing stamp
        # alone rather than overwriting a good laptop stamp with a blank one.
        print("  stamp_build --runtime: no RAILWAY_GIT_COMMIT_SHA; leaving "
              "existing stamp untouched")
        return 0
    if "--show" in sys.argv:
        if not os.path.exists(OUT):
            print("  no build_info.json — run stamp_build.py before deploying")
            return 1
        with open(OUT) as fh:
            print(json.dumps(json.load(fh), indent=2))
        return 0
    info = build()
    with open(OUT, "w") as f:
        json.dump(info, f, indent=2)
        f.write("\n")
    print(f"  stamped {OUT}")
    print(f"    commit       {info['commit_short']} ({info['branch']})")
    print(f"    dirty        {info['dirty']}"
          + (f" — {info['modified_tracked']} modified, "
             f"{info['untracked']} untracked; {info['diff_shortstat']}"
             if info["dirty"] else ""))
    print(f"    content_hash {info['content_hash'][:26]}…")
    print(f"    files        {info['file_count']} ({info['total_bytes']:,} bytes)")
    print(f"    built_at     {info['built_at']}")
    print(f"    identity     {info['identity_source']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
