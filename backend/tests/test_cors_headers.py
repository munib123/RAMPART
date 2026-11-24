"""S5: CORS allow-list, security headers, body cap, and no-store on every response.
Run from backend/:
    .venv\\Scripts\\python.exe -m pytest tests/test_cors_headers.py -q
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    # No `with` block: these assertions do not need the lifespan warm-up threads.
    return TestClient(app)


def test_dev_origin_is_allowed(client):
    r = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_tauri_origin_is_allowed(client):
    r = client.get("/api/health", headers={"Origin": "http://tauri.localhost"})
    assert r.headers.get("access-control-allow-origin") == "http://tauri.localhost"


def test_unknown_origin_gets_no_allow_header(client):
    r = client.get("/api/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers
    assert r.status_code == 200


def test_preflight_from_unknown_origin_is_not_allowed(client):
    r = client.options("/api/scan", headers={
        "Origin": "https://evil.example",
        "Access-Control-Request-Method": "POST",
    })
    assert "access-control-allow-origin" not in r.headers


def test_security_and_no_store_headers(client):
    r = client.get("/")
    assert r.headers["Cache-Control"] == "no-store"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert "Permissions-Policy" in r.headers
    assert r.headers["Cross-Origin-Resource-Policy"] == "same-site"
    assert r.headers.get("X-Request-ID")
    assert "origin" in r.headers.get("Vary", "").lower()


def test_oversized_body_is_rejected_before_parsing(client, monkeypatch):
    from app import config
    monkeypatch.setattr(config, "MAX_BODY_BYTES", 1024)

    r = client.post("/api/scan", content=b"x" * 2048,
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 413
    body = json.loads(r.content)
    assert body["ok"] is False and body["limit_bytes"] == 1024
    assert body["request_id"]


def test_small_body_reaches_the_handler(client, tmp_path):
    # A target that does not exist is rejected by the pipeline policy (a normal JSON report),
    # proving the guard only trips above the body limit.
    r = client.post("/api/scan", json={"path": str(tmp_path / "missing")},
                    headers={"Origin": "http://localhost:5173"})
    assert r.status_code == 200
    assert r.json()["ok"] is False
