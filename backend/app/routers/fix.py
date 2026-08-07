"""POST /api/fix - on-demand LLM fix for one finding (never auto-applied)."""
from __future__ import annotations

from fastapi import APIRouter

from app.schemas.scan import FixReq
from app.services import gemini

router = APIRouter(tags=["fix"])


@router.post("/api/fix")
def fix(req: FixReq):
    finding = {"cwe_id": req.cwe_id, "title": req.title, "message": req.message}
    try:
        return gemini.generate_fix(finding, req.code, req.exemplars)
    except Exception as e:
        return {"available": False, "error": f"{type(e).__name__}: {e}"}