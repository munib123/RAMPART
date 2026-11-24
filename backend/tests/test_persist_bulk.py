"""S2: a scan + its findings is persisted in two write round trips (one INSERT for the scan,
one EXECUTEMANY for the findings), not one round trip per finding. No database needed - the
transaction connection is captured with a fake. Run from backend/:
    .venv\\Scripts\\python.exe -m pytest tests/test_persist_bulk.py -q
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app.db as db                                  # noqa: E402
from app.routers import scan as scan_router          # noqa: E402
from app.routers import scans as scans_router        # noqa: E402


class _Conn:
    def __init__(self, calls, scan_id):
        self.calls, self.scan_id = calls, scan_id

    async def fetchval(self, q, *args):
        self.calls.append(("scans", q, args))
        return self.scan_id

    async def executemany(self, q, args_list):
        self.calls.append(("findings", q, list(args_list)))


class _Tx:
    def __init__(self, calls, scan_id="scan-1"):
        self.conn = _Conn(calls, scan_id)

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, *exc):
        return False


def _patch_transaction(monkeypatch, calls, scan_id="scan-1"):
    monkeypatch.setattr(db, "transaction", lambda: _Tx(calls, scan_id))


def _report(n: int = 60) -> dict:
    findings = [{
        "tool": "bandit", "rule_id": f"B{i}", "cwe_id": "CWE-79", "severity": "high",
        "verdict": {"verdict": "Likely", "confidence": 70}, "exemplars": [],
    } for i in range(n)]
    return {"ok": True, "target": "D:/x", "scanner": "bandit", "scope": {},
            "counts": {"total": n}, "findings": findings}


def test_scan_persist_is_two_round_trips(monkeypatch):
    calls = []
    _patch_transaction(monkeypatch, calls)

    asyncio.run(scan_router._persist_scan("owner-1", _report(60)))

    assert [c[0] for c in calls] == ["scans", "findings"]
    _, find_q, rows = calls[1]
    assert "values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8)" in find_q
    assert len(rows) == 60
    assert all(len(row) == 8 and row[0] == "scan-1" for row in rows)


def test_create_scan_bulk_insert(monkeypatch):
    calls = []
    _patch_transaction(monkeypatch, calls, scan_id="scan-2")
    monkeypatch.setattr(scans_router.db, "enabled", lambda: True)

    payload = {"target": "D:/x", "scanner": "bandit", "counts": {"total": 60},
               "verdict_summary": {"Likely": 60},
               "findings": [{"cwe_id": "CWE-89", "severity": "high", "verdict": "Likely",
                             "confidence": 70, "rule_id": "B1", "exemplar_urls": [],
                             "tool": "bandit"}] * 60}

    out = asyncio.run(scans_router.create_scan(payload, user={"id": "owner-1"}))

    assert out == {"scan_id": "scan-2"}
    assert [c[0] for c in calls] == ["scans", "findings"]
    assert len(calls[1][2]) == 60
