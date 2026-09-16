"""GET /api/health - scanner availability, LLM on/off, RAG collections, db stats."""
from __future__ import annotations

from fastapi import APIRouter

from app import config, db
from app.services import gemini, rag

router = APIRouter(tags=["health"])


@router.get("/api/health")
def health():
    from app.services.scanner import SemgrepScanner, BanditScanner
    from app.services.joern import scan as joern_scan, server as joern_server
    sg_ok, sg_why = SemgrepScanner().available()
    bd_ok, _ = BanditScanner().available()
    jn_ok, jn_why = joern_scan.available()
    active = "semgrep" if sg_ok else "bandit"
    return {
        "ok": True,
        "llm_enabled": gemini.available(),
        "model": gemini.active_model() if gemini.available() else None,
        "scanner": active,
        "scanners": {
            "semgrep": {"available": sg_ok, "note": sg_why},
            "bandit": {"available": bd_ok, "note": "python-only"},
            # additive CPG phase, not an alternative scanner: runs alongside whichever is active
            "joern": {"available": jn_ok, "enabled": config.JOERN_ENABLED,
                      "note": jn_why or "CPG logic-bug locator (Python) - IDOR, mass assignment, "
                                        "unchecked quantity, TOCTOU",
                      "server": joern_server.status()},
        },
        "default_target": config.DEFAULT_TARGET,
        "db_enabled": db.enabled(),
        "collections": rag.collection_stats(),
    }