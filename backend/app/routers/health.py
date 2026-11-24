"""GET /api/health - scanner availability, LLM on/off, RAG collections, db stats.

The scanner probes spawn subprocesses (and a cold `joern --help` can take seconds), so their
result is cached for 30 s. `/api/health?refresh=1` bypasses the cache; the Joern server's live
status, LLM availability and DB flag are still read on every request (all cheap).
"""
from __future__ import annotations

import threading
import time

from fastapi import APIRouter

from app import config, db
from app.services import gemini, rag

router = APIRouter(tags=["health"])

_TTL_S = 30.0
_probe_cache: dict = {"at": 0.0, "value": None}
_probe_lock = threading.Lock()


def _probes(force: bool = False) -> dict:
    """Scanner availability + collection stats, cached for _TTL_S. One probe at a time."""
    now = time.monotonic()
    with _probe_lock:
        cached = _probe_cache["value"]
        if not force and cached is not None and (now - _probe_cache["at"]) < _TTL_S:
            return cached

        from app.services.scanner import SemgrepScanner, BanditScanner
        from app.services.joern import scan as joern_scan
        sg_ok, sg_why = SemgrepScanner().available()
        bd_ok, _ = BanditScanner().available()
        jn_ok, jn_why = joern_scan.available()
        value = {
            "sg_ok": sg_ok, "sg_why": sg_why,
            "bd_ok": bd_ok,
            "jn_ok": jn_ok, "jn_why": jn_why,
            "collections": rag.collection_stats(),
        }
        _probe_cache["at"] = time.monotonic()
        _probe_cache["value"] = value
        return value


@router.get("/api/health")
def health(refresh: int = 0):
    from app.services.joern import server as joern_server
    p = _probes(force=bool(refresh))
    active = "semgrep" if p["sg_ok"] else "bandit"
    return {
        "ok": True,
        "llm_enabled": gemini.available(),
        "model": gemini.active_model() if gemini.available() else None,
        "scanner": active,
        "scanners": {
            "semgrep": {"available": p["sg_ok"], "note": p["sg_why"]},
            "bandit": {"available": p["bd_ok"], "note": "python-only"},
            # additive CPG phase, not an alternative scanner: runs alongside whichever is active
            "joern": {"available": p["jn_ok"], "enabled": config.JOERN_ENABLED,
                      "note": p["jn_why"] or "CPG logic-bug locator (Python) - IDOR, mass assignment, "
                                            "unchecked quantity, TOCTOU",
                      "server": joern_server.status()},
        },
        "default_target": config.DEFAULT_TARGET,
        "db_enabled": db.enabled(),
        "collections": p["collections"],
    }
