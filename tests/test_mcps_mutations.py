"""Every MCPS security check is load-bearing: delete it and a test goes red.

WHY. The independent review of 2026-11-23 (finding F1) removed ten security
checks from mcps.py one at a time and the suite stayed green for nine of them:
passport self-signature, both expiry checks, issuer == "self", header
passport_id == session passport, the future-clock bound, the transcript
signature, the 8192-byte limit and the JWK private-member refusal. A check no
test can see is a check that can be deleted in a refactor without anyone
noticing.

HOW. For each entry below, copy the repo to a temp dir, replace exactly one
check in the copy's mcps.py with a no-op, and run tests/test_mcps_envelope.py
there. The mutant must FAIL (pytest exit 1). Two guards keep this harness from
lying:
  * every mutation's source text must occur EXACTLY ONCE in mcps.py, so a
    rename or reformat fails here by name instead of silently mutating nothing;
  * the unmutated copy must PASS (exit 0), so a broken copy cannot make every
    mutant "fail" for the wrong reason.
Exit codes other than 0/1 (collection error, usage error, no tests) fail loudly
with the child's output.
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
SUITE = "tests/test_mcps_envelope.py"

# (id, exact source in mcps.py, replacement that disables the check)
MUTATIONS = [
    # the ten checks the review found untested or found guarded by one test
    ("passport_self_signature",
     'if not verify_p1363(pub, jcs(body), pp.get("signature") or ""):', "if False:"),
    ("passport_expiry_at_initialize",
     "if (now if now is not None else time.time()) > exp:", "if False:"),
    ("passport_issuer_is_self",
     'if body.get("issuer") != "self":', "if False:"),
    ("header_passport_id_is_the_sessions",
     'if header["passport_id"] != passport_body.get("id"):', "if False:"),
    ("passport_expiry_inbound",
     'if t > parse_iso(passport_body["expires_at"]):', "if False:"),
    ("future_timestamp_bound",
     "if ts - t > FUTURE_SKEW_S:", "if False:"),
    ("transcript_signature",
     "if not verify_p1363(s.client_pub, s.transcript.encode(),",
     "if False and verify_p1363(s.client_pub, s.transcript.encode(),"),
    ("passport_size_limit",
     "if len(jcs(body)) > 8192:", "if False:"),
    ("jwk_private_member",
     'if "d" in jwk:', "if False:"),
    ("header_version",
     'if header["version"] != MCPS_VERSION:', "if False:"),
    # the other inbound checks, so the set is complete
    ("message_signature",
     "if not verify_signature(header, message_wo_header, pub):", "if False:"),
    ("nonce_replay",
     "if nonces.seen(nonce, scope):", "if False:"),
    ("past_timestamp_window",
     "if t - ts > TIMESTAMP_WINDOW_S + CLOCK_SKEW_S:", "if False:"),
    ("passport_origin",
     'if expected_origin is not None and _origin(body["origin"]) != _origin(expected_origin):',
     "if False:"),
    ("per_client_quota",
     "if len(mine) >= self.scope_cap:", "if False:"),
    # the 2026-11-23 fixes (review F2-F6)
    ("F2_signed_required_after_passport",
     "if hdr is None and s.client_passport is not None and not is_init:", "if False:"),
    ("F3_nonce_kept_until_message_expires",
     "nonces.add(nonce, scope, expires_at=ts + TIMESTAMP_WINDOW_S + CLOCK_SKEW_S)",
     "nonces.add(nonce, scope)"),
    ("F4_scope_binds_the_key",
     'return f"{passport_id}|{thumb}"', 'return f"{passport_id}|"'),
    ("F5_one_initialize_per_session",
     "if is_init and s.initialized:", "if False:"),
    ("F6_no_passport_is_not_verified",
     "        verified = False\n        if s.client_pub is not None:",
     "        verified = True\n        if s.client_pub is not None:"),
]


def _copy(dst: pathlib.Path) -> pathlib.Path:
    root = dst / "repo"
    shutil.copytree(REPO, root, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    return root


def _run(root: pathlib.Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", SUITE],
                          cwd=root, capture_output=True, text=True, timeout=600)


def test_the_unmutated_copy_passes(tmp_path):
    r = _run(_copy(tmp_path))
    assert r.returncode == 0, f"the harness copy itself is red:\n{r.stdout[-3000:]}\n{r.stderr[-2000:]}"


@pytest.mark.parametrize("old", [m[1] for m in MUTATIONS], ids=[m[0] for m in MUTATIONS])
def test_each_mutation_targets_exactly_one_line(old):
    n = (REPO / "mcps.py").read_text().count(old)
    assert n == 1, f"mutation source occurs {n} times in mcps.py; update MUTATIONS: {old!r}"


@pytest.mark.parametrize("old,new", [m[1:] for m in MUTATIONS], ids=[m[0] for m in MUTATIONS])
def test_deleting_the_check_turns_the_suite_red(tmp_path, old, new):
    root = _copy(tmp_path)
    src = (root / "mcps.py").read_text()
    assert src.count(old) == 1, f"mutation source not unique: {old!r}"
    (root / "mcps.py").write_text(src.replace(old, new))
    r = _run(root)
    assert r.returncode != 0, f"suite still GREEN with the check removed: {old!r}"
    assert r.returncode == 1, (f"mutant broke the run instead of failing a test (exit {r.returncode}):\n"
                               f"{r.stdout[-3000:]}\n{r.stderr[-2000:]}")
