r"""P4 provenance: what the scan router persists, and the migration runner's pure parts.
No database needed - the DB helpers are captured with monkeypatch. Run from backend/:
    .venv\Scripts\python.exe -m pytest tests/test_persistence.py -q
The live check (columns present, rows by tool) is tests/check_db.py.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app.db as db                              # noqa: E402
from app.routers import scan as scan_router      # noqa: E402


# ---- migration runner: pure parts -----------------------------------------------------

def test_pending_is_ordered_and_skips_applied():
    assert db.pending(["0003_b", "0002_joern", "0004_c"], {"0002_joern"}) == ["0003_b", "0004_c"]
    assert db.pending([], set()) == []
    assert db.pending(["0002_joern"], {"0001_schema", "0002_joern"}) == []


def test_migration_files_are_numbered_and_idempotent():
    files = db.migration_files()
    names = [p.name for p in files]
    assert "0002_joern.sql" in names
    assert names == sorted(names)
    for p in files:
        sql = p.read_text(encoding="utf-8").lower()
        # every DDL statement must survive a second run (start-up applies them best-effort)
        for stmt in ("alter table", "create index", "create view"):
            for line in (l for l in sql.splitlines() if l.strip().startswith(stmt)):
                assert "if not exists" in line or "or replace" in line, f"{p.name}: not idempotent: {line.strip()}"


def test_0002_adds_the_provenance_columns():
    sql = (db.MIGRATIONS / "0002_joern.sql").read_text(encoding="utf-8").lower()
    assert "alter table findings add column if not exists tool" in sql
    assert "alter table scans" in sql and "joern jsonb" in sql
    assert "create or replace view tool_stats" in sql


# ---- _persist_scan writes tool + joern -------------------------------------------------

class _FakeConn:
    """The tiny slice of asyncpg's connection _persist_scan uses inside db.transaction()."""

    def __init__(self, calls, scan_id):
        self.calls, self.scan_id = calls, scan_id

    async def fetchval(self, q, *args):
        self.calls.append(("scans", q, args))
        return self.scan_id

    async def executemany(self, q, args_list):
        self.calls.append(("findings", q, args_list))


class _FakeTx:
    def __init__(self, calls, scan_id="scan-1"):
        self.conn = _FakeConn(calls, scan_id)

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, *exc):
        return False


def _patch_transaction(monkeypatch, calls, scan_id="scan-1"):
    monkeypatch.setattr(scan_router.db, "transaction", lambda: _FakeTx(calls, scan_id))


def _report():
    return {
        "ok": True, "target": "D:/x", "scanner": "semgrep", "scope": {"platform": "ecommerce"},
        "joern": {"used": True, "mode": "server", "candidates": 1, "elapsed_ms": 8000,
                  "rule_state": {"joern-idor-missing-ownership": {"state": "ok"}}},
        "counts": {"total": 2, "high": 2},
        "findings": [
            {"tool": "joern", "rule_id": "joern-idor-missing-ownership", "cwe_id": "CWE-639",
             "severity": "high", "verdict": {"verdict": "Confirmed", "confidence": 90}, "exemplars": []},
            {"tool": "semgrep", "rule_id": "python.flask.x", "cwe_id": "CWE-89", "severity": "high",
             "verdict": {"verdict": "Likely", "confidence": 70},
             "exemplars": [{"url": "https://hackerone.com/reports/1"}]},
            {"rule_id": "legacy-no-tool", "cwe_id": "CWE-79", "severity": "high",
             "verdict": {}, "exemplars": []},
        ],
    }


def test_persist_scan_writes_tool_and_joern(monkeypatch):
    calls = []
    _patch_transaction(monkeypatch, calls)

    scan_id = asyncio.run(scan_router._persist_scan("owner-1", _report()))
    assert scan_id == "scan-1"

    (_, scan_q, scan_args), = [c for c in calls if c[0] == "scans"]
    assert "joern" in scan_q and "$8::jsonb" in scan_q
    assert json.loads(scan_args[-1])["mode"] == "server"
    assert json.loads(scan_args[-1])["rule_state"]["joern-idor-missing-ownership"]["state"] == "ok"

    (_, find_q, rows), = [c for c in calls if c[0] == "findings"]
    assert "tool" in find_q
    assert len(rows) == 3
    tools = [row[-1] for row in rows]
    assert tools == ["joern", "semgrep", "unknown"]          # missing tool -> 'unknown', never NULL
    assert all(row[0] == "scan-1" for row in rows)
    # code never reaches the DB: no code_slice column in the insert, no slice in the args
    assert "code_slice" not in find_q
    for row in rows:
        assert not any(isinstance(a, dict) and "code" in a for a in row)


def test_persist_scan_without_joern_block(monkeypatch):
    """A report from a pipeline without the CPG phase (or an older backend) stores '{}'."""
    calls = []
    _patch_transaction(monkeypatch, calls, scan_id="scan-2")
    r = _report(); del r["joern"]; r["findings"] = []
    asyncio.run(scan_router._persist_scan("owner-1", r))
    (_, _, scan_args), = [c for c in calls if c[0] == "scans"]
    assert json.loads(scan_args[-1]) == {}
    assert not [c for c in calls if c[0] == "findings"]      # no rows -> no executemany
