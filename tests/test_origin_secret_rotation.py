"""ORIGIN_SHARED_SECRET accepts "new,old" so a rotation has no 400 window.

Mirrors forge-prod's tests/test_origin_secret_rotation.py. The guard reads the
variable when the app is built, so each case builds a fresh app with the
environment it describes and drives a real request through the middleware.
"""
import pytest
from starlette.testclient import TestClient

import mcp_server

PATH = "/.well-known/oauth-protected-resource"   # any non-/health route


def _blocked(monkeypatch, raw, header=None, path=PATH):
    if raw is None:
        monkeypatch.delenv("ORIGIN_SHARED_SECRET", raising=False)
    else:
        monkeypatch.setenv("ORIGIN_SHARED_SECRET", raw)
    client = TestClient(mcp_server.build_dual_app(), raise_server_exceptions=False)
    h = {"x-forge-origin-key": header} if header is not None else {}
    r = client.get(path, headers=h)
    try:
        body = r.json()
    except Exception:
        body = None
    return r.status_code == 400 and body == {"error": "bad_request"}


def test_single_secret_behaves_as_before(monkeypatch):
    assert not _blocked(monkeypatch, "only", "only")
    assert _blocked(monkeypatch, "only", "other")
    assert _blocked(monkeypatch, "only")


def test_rotation_window_accepts_new_and_old_and_nothing_else(monkeypatch):
    assert not _blocked(monkeypatch, "new, old", "new")
    assert not _blocked(monkeypatch, "new, old", "old")
    assert _blocked(monkeypatch, "new, old", "neither")
    assert _blocked(monkeypatch, "new,old", "new,old")
    assert _blocked(monkeypatch, "new,old")


def test_after_rotation_old_is_refused(monkeypatch):
    assert not _blocked(monkeypatch, "new", "new")
    assert _blocked(monkeypatch, "new", "old")


def test_unset_means_enforcement_off(monkeypatch):
    assert not _blocked(monkeypatch, None)
    assert not _blocked(monkeypatch, " , ")


def test_health_stays_exempt_during_rotation(monkeypatch):
    assert not _blocked(monkeypatch, "new,old", path="/health")
