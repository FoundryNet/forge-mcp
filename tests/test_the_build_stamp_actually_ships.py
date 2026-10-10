#!/usr/bin/env python3
"""The stamp has to reach the container, and the hashed set has to be the
uploaded set.

MEASURED 2026-10-10T05:13Z, on this service, by the deploy that prompted these
tests. `deploy.sh` ran `stamp_build.py`, `railway up` uploaded, the container
came up serving the new code -- and `/health` answered:

    {"build": {"stamped": false, "commit": null, "content_hash": null,
               "built_at": null,
               "note": "build_info.json absent -- deploy did not run
                        stamp_build.py"}}

The note was wrong about the cause and right about the effect. stamp_build.py
HAD run; the file it wrote was simply not in the upload, because Railway's
archive honours `.gitignore` in addition to `.railwayignore`, and
`build_info.json` is gitignored on purpose. `deploy.sh` then polled for a
commit and content_hash that could never appear.

A deployment that cannot say what it is cannot be rolled back to a known build,
which is the entire reason the stamp exists. So this is asserted, not
remembered.
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAILWAYIGNORE = os.path.join(ROOT, ".railwayignore")
GITIGNORE = os.path.join(ROOT, ".gitignore")


def _lines(path):
    if not os.path.exists(path):
        return []
    with open(path) as fh:
        return [ln.strip() for ln in fh
                if ln.strip() and not ln.strip().startswith("#")]


def _stamp_filename():
    """The stamp's name as stamp_build.py itself defines it, so renaming the
    stamp fails this test instead of silently un-shipping it."""
    src = open(os.path.join(ROOT, "stamp_build.py")).read()
    m = re.search(r'^OUT\s*=\s*os\.path\.join\(HERE,\s*"([^"]+)"\)', src, re.M)
    assert m, "stamp_build.py no longer defines OUT as a name under HERE"
    return m.group(1)


def test_railwayignore_exists():
    assert os.path.exists(RAILWAYIGNORE), (
        ".railwayignore is absent, so `railway up` falls back to .gitignore "
        "alone -- which excludes the build stamp. Measured: /health came up "
        '{"stamped": false, "note": "build_info.json absent"} on a deploy '
        "Railway reported as successful.")


def test_the_stamp_is_negated_in_railwayignore():
    stamp = _stamp_filename()
    lines = _lines(RAILWAYIGNORE)
    assert f"!{stamp}" in lines, (
        f"{stamp} is not negated in .railwayignore. It IS in .gitignore "
        f"(deliberately), and Railway honours .gitignore IN ADDITION to "
        f".railwayignore, so without an explicit `!{stamp}` the stamp never "
        f"reaches the image and every deploy is unidentifiable.")
    # A negation only beats patterns ABOVE it.
    assert lines.index(f"!{stamp}") == len(lines) - 1 or all(
        not _matches(p, stamp) for p in lines[lines.index(f"!{stamp}") + 1:]), (
        f"a pattern after `!{stamp}` re-excludes it; later patterns win.")


def test_the_stamp_is_still_gitignored_so_the_tree_stays_clean():
    stamp = _stamp_filename()
    assert stamp in _lines(GITIGNORE), (
        f"{stamp} must stay gitignored: deploy.sh REFUSES a dirty tree, and a "
        f"committed stamp would make every tree dirty by one file and make "
        f"each content_hash depend on the previous one.")


def _matches(pattern, name):
    import fnmatch
    return fnmatch.fnmatch(name, pattern.rstrip("/"))


def test_the_hashed_set_is_the_uploaded_set():
    """Every directory .railwayignore excludes must also be skipped by the
    hash, and vice versa. forge-prod measured two different trees sharing one
    content_hash because `ops/` was uploaded but not hashed."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "stamp_build", os.path.join(ROOT, "stamp_build.py"))
    sb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sb)
    uploaded_excl = {ln.rstrip("/") for ln in _lines(RAILWAYIGNORE)
                     if ln.endswith("/")}
    hashed_excl = set(sb.SKIP_DIRS)
    # File-shaped exclusions too, not just directories: a CI artefact written
    # into the workspace (junit.xml, pytest.out) that is uploaded-excluded but
    # still hashed makes content_hash depend on whether the suite had run.
    uploaded_files = {ln for ln in _lines(RAILWAYIGNORE)
                      if not ln.endswith("/") and not ln.startswith("!")
                      and not ln.startswith("*") and not ln.startswith(".env")
                      and not ln.startswith(".DS")}
    hashed_files = set(sb.SKIP_NAMES) | {"build_info.json"}
    leaked_files = uploaded_files - hashed_files
    assert not leaked_files, (
        f"excluded from the upload but still HASHED: {sorted(leaked_files)}. "
        f"content_hash would move depending on local state.")
    # .git is excluded from the upload and need not be restated as a skip,
    # because stamp_build walks from HERE and .git carries no deployed file.
    only_uploaded = uploaded_excl - hashed_excl - {".git"}
    only_hashed = hashed_excl - uploaded_excl - {".git"}
    assert not only_uploaded, (
        f"excluded from the upload but still HASHED: {sorted(only_uploaded)}. "
        f"content_hash would describe files that never shipped.")
    assert not only_hashed, (
        f"skipped by the hash but still UPLOADED: {sorted(only_hashed)}. "
        f"Two different trees could then share one content_hash -- measured on "
        f"forge-prod 2026-10-05, d7c4c20 and c60a6c6.")
