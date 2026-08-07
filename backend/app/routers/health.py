"""GET /api/health - scanner availability, LLM on/off, RAG collections, db stats."""
from __future__ import annotations

from fastapi import APIRouter

from app import config, db
from app.services import gemini, rag

router = APIRouter(tags=["health"])


@router.get("/api/health")
def health():
    from app.services.scanner import SemgrepScanner, BanditScanner
    sg_ok, sg_why = SemgrepScanner().available()
    bd_ok, _ = BanditScanner().available()
    active = "semgrep" if sg_ok else "bandit"
    return {
        "ok": True,
        "llm_enabled": gemini.available(),
        "model": config.GEMINI_MODEL if gemini.available() else None,
        "scanner": active,
        "scanners": {
            "semgrep": {"available": sg_ok, "note": sg_why},
            "bandit": {"available": bd_ok, "note": "python-only"},
        },
        "default_target": config.DEFAULT_TARGET,
        "db_enabled": db.enabled(),
        "collections": rag.collection_stats(),
    }