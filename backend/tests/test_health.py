"""Structural contract test: /api/health exposes the expected top-level keys and
the app boots as a package (app.main:app). Run from backend/:
    .venv\\Scripts\\python.exe -m pytest tests -q

Requires pytest + httpx (dev deps). No external services are contacted for the
keys asserted here; scanners/RAG/embedder load lazily inside the handler.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest  # noqa: F401

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        yield c


def test_root_json_banner(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.json()["service"] == "RAMPART API"


def test_health_keys(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    for key in ("ok", "llm_enabled", "model", "scanner", "scanners",
                "default_target", "db_enabled", "collections"):
        assert key in body, f"missing key {key}"


def test_nostore_header(client):
    r = client.get("/api/health")
    assert r.headers.get("Cache-Control") == "no-store"

def test_health_joern_shape(client):
    """P3/P4: the UI's Setup note reads scanners.joern before a scan; these keys are its contract."""
    j = client.get("/api/health").json()["scanners"]["joern"]
    for key in ("available", "enabled", "note", "server"):
        assert key in j, f"missing scanners.joern.{key}"
    assert "running" in j["server"]
    if j["server"]["running"]:
        for key in ("ready", "port", "pid", "uptime_s", "startup_s"):
            assert key in j["server"], f"missing scanners.joern.server.{key}"
