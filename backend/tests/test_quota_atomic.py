"""S2: plan quotas are reserved with one conditional UPDATE, so concurrent requests cannot
both take the last slot, and a failed scan/fix gives the slot back. No database needed - the
DB helpers are faked. Run from backend/:
    .venv\\Scripts\\python.exe -m pytest tests/test_quota_atomic.py -q
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.routers import fix as fix_router            # noqa: E402
from app.routers import scan as scan_router          # noqa: E402
from app.schemas.scan import FixReq, ScanReq         # noqa: E402

FREE_SCANS = 10


def _free_user(**extra) -> dict:
    return {"id": "user-1", "plan": "free", "scans_used": 0, "fixes_used": 0,
            "last_fix_scan_id": None, **extra}


# ---- scan reservation ----------------------------------------------------------------

def test_reserve_scan_is_one_conditional_update(monkeypatch):
    seen = {}

    async def fetch_val(q, *args):
        seen.update(q=q, args=args)
        return 4

    monkeypatch.setattr(scan_router.db, "fetch_val", fetch_val)
    got = asyncio.run(scan_router._reserve_scan(_free_user(scans_used=3)))

    assert got == 4
    assert "scans_used = scans_used + 1" in seen["q"]
    assert "scans_used < $2" in seen["q"]
    assert "returning scans_used" in seen["q"]
    assert seen["args"] == ("user-1", FREE_SCANS)


def test_full_plan_is_rejected_before_the_scan(monkeypatch):
    called = []

    async def lookup(_auth):
        return _free_user(scans_used=FREE_SCANS)

    async def fetch_val(q, *args):
        return None                       # conditional update matched no row

    def run(*args):
        called.append(args)
        return {"ok": True}

    monkeypatch.setattr(scan_router, "_lookup_user", lookup)
    monkeypatch.setattr(scan_router.db, "fetch_val", fetch_val)
    monkeypatch.setattr(scan_router.pipeline, "run_scan", run)

    res = asyncio.run(scan_router.scan(ScanReq(path="x"), authorization="Bearer t"))

    assert res.status_code == 402
    body = json.loads(res.body)
    assert body["code"] == "plan_limit" and body["kind"] == "scan"
    assert called == []                    # no scanner/RAG/LLM spend


def test_failed_scan_refunds_the_reserved_slot(monkeypatch):
    refunds = []

    async def lookup(_auth):
        return _free_user(scans_used=3)

    async def fetch_val(q, *args):
        return 4

    async def execute(q, *args):
        refunds.append((q, args))

    def run(*args):
        raise RuntimeError("scanner exploded")

    monkeypatch.setattr(scan_router, "_lookup_user", lookup)
    monkeypatch.setattr(scan_router.db, "fetch_val", fetch_val)
    monkeypatch.setattr(scan_router.db, "execute", execute)
    monkeypatch.setattr(scan_router.pipeline, "run_scan", run)

    res = asyncio.run(scan_router.scan(ScanReq(path="x"), authorization="Bearer t"))

    assert res.status_code == 500
    assert len(refunds) == 1
    assert "greatest(scans_used - 1, 0)" in refunds[0][0]
    assert refunds[0][1] == ("user-1",)


def test_concurrent_scans_cannot_both_take_the_last_slot(monkeypatch):
    state = {"used": FREE_SCANS - 1}
    lock = asyncio.Lock()

    async def lookup(_auth):
        return _free_user(scans_used=state["used"])

    async def fetch_val(q, *args):
        async with lock:                  # the conditional UPDATE's serialisation
            if state["used"] < FREE_SCANS:
                state["used"] += 1
                return state["used"]
            return None

    async def persist(_uid, _report):
        return "scan-1"

    def run(path, scanner, scope, fresh=False):
        time.sleep(0.05)                  # keep the winner inside the critical section
        return {"ok": True, "target": path, "scanner": "bandit", "counts": {}, "findings": []}

    monkeypatch.setattr(scan_router, "_lookup_user", lookup)
    monkeypatch.setattr(scan_router.db, "fetch_val", fetch_val)
    monkeypatch.setattr(scan_router, "_persist_scan", persist)
    monkeypatch.setattr(scan_router.pipeline, "run_scan", run)

    async def both():
        return await asyncio.gather(
            scan_router.scan(ScanReq(path="x"), authorization="Bearer t"),
            scan_router.scan(ScanReq(path="x"), authorization="Bearer t"),
        )

    a, b = asyncio.run(both())
    statuses = sorted(getattr(r, "status_code", 200) for r in (a, b))
    assert statuses == [200, 402]
    assert state["used"] == FREE_SCANS


# ---- fix reservation -----------------------------------------------------------------

def _fix_user(**extra) -> dict:
    return {"id": "user-1", "plan": "free", "fixes_used": 2, "last_fix_scan_id": None, **extra}


def test_fix_refunds_when_generation_is_unavailable(monkeypatch):
    calls = []

    async def fetch_val(q, *args):
        calls.append(("reserve", q))
        return 3

    async def execute(q, *args):
        calls.append(("refund", q, args))

    monkeypatch.setattr(fix_router.db, "enabled", lambda: True)
    monkeypatch.setattr(fix_router.db, "fetch_val", fetch_val)
    monkeypatch.setattr(fix_router.db, "execute", execute)
    monkeypatch.setattr(fix_router.gemini, "generate_fix",
                        lambda *a, **kw: {"available": False, "error": "quota"})

    res = asyncio.run(fix_router.fix(FixReq(code="x = 1", scan_id="scan-9"), user=_fix_user()))

    assert res["available"] is False
    assert res["fixes_used"] == 2                         # rolled back
    assert [c[0] for c in calls] == ["reserve", "refund"]
    assert "greatest(fixes_used - 1, 0)" in calls[1][1]


def test_fix_reservation_uses_a_conditional_update(monkeypatch):
    seen = {}

    async def fetch_val(q, *args):
        seen.update(q=q, args=args)
        return 3

    monkeypatch.setattr(fix_router.db, "fetch_val", fetch_val)
    got = asyncio.run(fix_router._reserve_fix(_fix_user(), "scan-9"))

    assert got == 3
    assert "fixes_used < $3" in seen["q"] and "returning fixes_used" in seen["q"]
    assert seen["args"] == ("scan-9", "user-1", 5)        # free plan fixes = 5


def test_already_fixed_scan_is_not_charged(monkeypatch):
    def no_reserve(*a, **kw):
        raise AssertionError("must not charge the same scan twice")

    monkeypatch.setattr(fix_router.db, "enabled", lambda: True)
    monkeypatch.setattr(fix_router.db, "fetch_val", no_reserve)
    monkeypatch.setattr(fix_router.gemini, "generate_fix",
                        lambda *a, **kw: {"available": True, "fixed_code": "y = 2"})

    user = _fix_user(last_fix_scan_id="scan-9", fixes_used=3)
    res = asyncio.run(fix_router.fix(FixReq(code="x = 1", scan_id="scan-9"), user=user))

    assert res["available"] is True
    assert res["fixes_used"] == 3
