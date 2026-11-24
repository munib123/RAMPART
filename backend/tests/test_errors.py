"""S5: DB/exception details are logged, never returned in an API response.
Run from backend/:
    .venv\\Scripts\\python.exe -m pytest tests/test_errors.py -q
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from starlette.requests import Request

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.errors import error_payload, internal_error   # noqa: E402

SECRET_DSN = "postgresql://postgres:super-secret@aws-0-region.pooler.supabase.com:6543/postgres"


def _request() -> Request:
    req = Request({
        "type": "http", "http_version": "1.1", "method": "POST", "path": "/api/scans",
        "raw_path": b"/api/scans", "query_string": b"", "headers": [],
        "scheme": "http", "server": ("testserver", 80), "client": ("127.0.0.1", 1234),
    })
    req.state.request_id = "abc123def456"
    return req


def test_internal_error_is_generic_and_keeps_the_request_id(caplog):
    caplog.set_level(logging.ERROR, logger="rampart.api")

    resp = internal_error(_request(), RuntimeError(SECRET_DSN), "failed to persist scan")

    assert resp.status_code == 500
    body = json.loads(resp.body)
    assert body == {"ok": False, "error": "failed to persist scan", "request_id": "abc123def456"}
    assert "secret" not in resp.body.decode().lower()

    # The operator still gets the full cause in the log.
    assert "super-secret" in caplog.text
    assert "abc123def456" in caplog.text


def test_error_payload_matches_the_same_contract():
    payload = error_payload(_request(), ValueError(SECRET_DSN), "fix generation failed")
    assert payload["ok"] is False
    assert payload["error"] == "fix generation failed"
    assert payload["request_id"] == "abc123def456"
    assert "secret" not in json.dumps(payload).lower()


def test_persist_route_does_not_leak_the_database_error(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.routers import scans as scans_router

    def boom():
        raise RuntimeError(SECRET_DSN)

    monkeypatch.setattr(scans_router.db, "enabled", lambda: True)
    monkeypatch.setattr(scans_router.db, "transaction", boom)
    app.dependency_overrides[scans_router.current_user] = lambda: {"id": "user-1"}
    try:
        client = TestClient(app)
        r = client.post("/api/scans", json={})
    finally:
        app.dependency_overrides.pop(scans_router.current_user, None)

    assert r.status_code == 500
    assert r.json()["ok"] is False
    assert r.json()["error"] == "failed to persist scan"
    assert r.json()["request_id"]
    assert "super-secret" not in r.text
    assert "postgresql://" not in r.text
