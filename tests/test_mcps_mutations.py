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
     "    if t > exp:", "    if False:"),
    ("passport_issuer_is_self",
     '    if issuer == "self":\n        if not verify_p1363(pub, jcs(body)', '    if False:\n        if not verify_p1363(pub, jcs(body)'),
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
     "if len(jcs(body)) > MAX_PASSPORT_BYTES:", "if False:"),
    ("jwk_private_member",
     'if "d" in jwk:', "if False:"),
    ("header_version",
     'if header["version"] != MCPS_VERSION:', "if False:"),
    # the other inbound checks, so the set is complete
    ("message_signature",
     "if not verify_signature(header, message_wo_header, pub):", "if False:"),
    ("nonce_replay",
     "if nonces.seen(nonce, scope, t) or any(o.seen(nonce, scope, t) for o in also_seen):", "if False:"),
    ("past_timestamp_window",
     "if t - ts > TIMESTAMP_WINDOW_S + CLOCK_SKEW_S:", "if False:"),
    ("passport_origin",
     'mismatch = _origin(body["origin"]) != _origin(expected_origin)',
     "mismatch = False"),
    ("per_client_quota",
     "if len(mine) >= self.scope_cap:", "if False:"),
    # the 2026-11-23 fixes (review F2-F6)
    ("F2_signed_required_after_passport",
     "if hdr is None and s.client_passport is not None and not is_init:", "if False:"),
    ("F3_nonce_kept_until_message_expires",
     "nonces.add(nonce, scope, expires_at=ts + TIMESTAMP_WINDOW_S + CLOCK_SKEW_S + NONCE_MARGIN_S)",
     "nonces.add(nonce, scope)"),
    ("F4_scope_binds_the_key",
     'return f"{passport_id}|{thumb}"', 'return f"{passport_id}|"'),
    ("F5_one_initialize_per_session",
     "if is_init and (s.initialized or s.init_inflight):", "if False:"),
    ("F6_no_passport_is_not_verified",
     "        verified = False\n        if s.client_pub is not None:",
     "        verified = True\n        if s.client_pub is not None:"),
    # the twelve mutants that SURVIVED the re-review of 4f0f090 (finding N5),
    # with the reviewer's own replacement texts
    ("N5_notifications_let_through",
     "if hdr is None and s.client_passport is not None and not is_init:",
     "if hdr is None and s.client_passport is not None and not is_init and is_req:"),
    ("N5_reinit_allowed_without_prior_passport",
     "if is_init and (s.initialized or s.init_inflight):",
     "if is_init and (s.initialized or s.init_inflight) and s.client_passport is not None:"),
    ("N5_future_skew_40", "FUTURE_SKEW_S = 30 ", "FUTURE_SKEW_S = 40 "),
    ("N5_nonce_seen_expires_early",
     "            return t is not None and t > (time.time() if now is None else now)",
     "            return t is not None and t > (time.time() if now is None else now) + 300"),
    ("N5_init_version_negotiation",
     "                if MCPS_VERSION not in vers:", "                if False:"),
    ("N5_nonce_format",
     "    if not (isinstance(nonce, str) and len(nonce) == 32",
     "    if False and (isinstance(nonce, str) and len(nonce) == 32"),
    ("N5_passport_id_prefix",
     'r"ap_[0-9a-f]{8}-', 'r"[a-z]{2}_[0-9a-f]{8}-'),
    ("N5_jwk_kty_crv",
     '    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":',
     "    if not isinstance(jwk, dict):"),
    ("N5_passport_required_fields",
     '        if f not in body:\n            raise MCPSError("INVALID_PASSPORT", f"passport.{f} missing")',
     '        if False:\n            raise MCPSError("INVALID_PASSPORT", f"passport.{f} missing")'),
    ("N5_transcript_hash_equality",
     '        if p.get("transcript_hash") != s.transcript:', "        if False:"),
    ("N5_transcript_none", "        if s.transcript is None:", "        if False:"),
    ("N5_channel_binding_dropped_from_payload",
     '    if "channel_binding" in header:\n        payload["channel_binding"]',
     '    if False:\n        payload["channel_binding"]'),
    # review N1: per-source limit before crypto; anonymous never spends the shared store
    ("N1_limit_before_crypto",
     "                caller = await self._limit(msg)", "                caller = None"),
    ("N1_connection_bucket",
     'if not lim.take("conn:" + s.session_tag):', "if False:"),
    ("N1_source_bucket", "        if not lim.take(src):", "        if False:"),
    ("N1_anonymous_never_writes_the_shared_store",
     "                # shared store; a replay is looked for in both.\n"
     "                store, other = (nonces(), anon_nonces()) if caller else (anon_nonces(), nonces())",
     "                # shared store; a replay is looked for in both.\n"
     "                store, other = nonces(), anon_nonces()"),
    ("N1_replay_looked_for_in_every_store",
     "if nonces.seen(nonce, scope, t) or any(o.seen(nonce, scope, t) for o in also_seen):",
     "if nonces.seen(nonce, scope, t):"),
    ("N1_rate_limited_refusal_is_unsigned",
     'sign=e.name != "RATE_LIMITED")', "sign=True)"),
    ("N1_lookup_has_its_own_bucket",
     'limiter().take("lookup:" + client_source(req, s.session_tag))',
     "limiter().take(client_source(req, s.session_tag))"),
    ("N1_rightmost_forwarded_entry",
     'last = str(v).split(",")[-1].strip()', 'last = str(v).split(",")[0].strip()'),
    # review F7: collection is amortised and runs on every add
    ("F7_collect_on_every_add",
     "            now = time.time()\n            self._collect(now)\n",
     "            now = time.time()\n"),
    ("F7_re_added_nonce_counted_once",
     "            if nonce in mine:                               # expired, not yet collected",
     "            if False:"),
    # review N3: a rejected initialize leaves nothing behind
    ("N3_sdk_error_resets_the_identity",
     "        else:\n            s.reset_identity()", "        else:\n            pass"),
    ("N3_initialized_only_on_the_sdks_result",
     "        if isinstance(root, t.JSONRPCResponse):\n            s.initialized = True",
     "        if isinstance(root, t.JSONRPCResponse):\n            pass"),
    ("N3_inflight_blocks_a_second_initialize",
     "if is_init and (s.initialized or s.init_inflight):", "if is_init and s.initialized:"),
    # 2026-11-24: N2, N4, F8-F15
    ("N2_nonce_outlives_its_message",
     "CLOCK_SKEW_S + NONCE_MARGIN_S)", "CLOCK_SKEW_S)"),
    ("N2_one_clock_for_the_whole_check",
     "if nonces.seen(nonce, scope, t) or any(o.seen(nonce, scope, t) for o in also_seen):",
     "if nonces.seen(nonce, scope) or any(o.seen(nonce, scope) for o in also_seen):"),
    ("N4_channel_binding_refused",
     '    if "channel_binding" in header:\n        # §5.3', '    if False:\n        # §5.3'),
    ("F8_evict_rather_than_refuse",
     "                self._evict_oldest()\n",
     '                raise MCPSError("RATE_LIMITED", "nonce store full")\n'),
    ("F9_mcps_version", 'if pp.get("mcps_version") != MCPS_VERSION:', "if False:"),
    ("F9_uuid_v4_id",
     'if not (isinstance(body["id"], str) and _PASSPORT_ID_RE.fullmatch(body["id"])):',
     'if not (isinstance(body["id"], str) and body["id"].startswith("ap_")):'),
    ("F9_issuer_chain_depth",
     "if chain is not None and (not isinstance(chain, list) or len(chain) > MAX_ISSUER_CHAIN):",
     "if False:"),
    ("F9_capabilities_limit",
     "if caps is not None and (not isinstance(caps, list) or len(caps) > MAX_CAPABILITIES):",
     "if False:"),
    ("F9_future_issued_at", "    if iat - t > FUTURE_SKEW_S:", "    if False:"),
    ("F10_mismatch_terminates",
     "                    s.terminated = True ", "                    pass "),
    ("F10_terminated_refuses_queued",
     '            if s.terminated:\n                raise MCPSError("TRANSCRIPT_MISMATCH"',
     '            if False:\n                raise MCPSError("TRANSCRIPT_MISMATCH"'),
    ("F10_stream_ends",
     "            if self._s.terminated:\n                raise StopAsyncIteration",
     "            if False:\n                raise StopAsyncIteration"),
    ("F11_catch_all",
     "        except Exception as e:\n            if not isinstance(e, MCPSError):",
     "        except MCPSError as e:\n            if not isinstance(e, MCPSError):"),
    ("F11_bad_origin_port",
     "        except ValueError:                          # e.g. port 99999",
     "        except KeyError:                          # e.g. port 99999"),
    ("F12_configured_ta_signature",
     "        if isinstance(issuer, str) and issuer in anchors:\n            # A configured TA: its signature MUST verify",
     "        if False:\n            # A configured TA: its signature MUST verify"),
    ("F12_unknown_ta_is_l0",
     '    if body.get("issuer") != "self" and body.get("issuer") in anchors:', "    if True:"),
    ("F13_responses_are_verified",
     "            return await self._admit_response(msg, root)", "            return True"),
    ("F13_identified_unsigned_response_dropped",
     "        if hdr is None and s.client_passport is None:\n            return True",
     "        if hdr is None:\n            return True"),
    ("F14_hash_over_received_fields",
     '                body = _dump_received(root)\n                body.pop("mcps", None)\n                # Review N1',
     '                body = _dump(root)\n                body.pop("mcps", None)\n                # Review N1'),
    ("F15_draft_error_keys",
     'data = {"string_code": self.string_code, "reason": self.detail}',
     'data = {"mcps_code": self.string_code, "detail": self.detail}'),
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
