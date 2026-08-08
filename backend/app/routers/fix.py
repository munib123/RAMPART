"""POST /api/fix - on-demand LLM fix for one finding (never auto-applied).
Requires a signed-in user. Charges one plan "fix" per distinct scan (users.last_fix_scan_id
dedupes: fixing more findings from the same scan is free)."""
from __future__ import annotations

from fastapi import APIRouter, Depends

import app.db as db
from app import config
from app.core.deps import optional_user
from app.schemas.scan import FixReq
from app.services import gemini

router = APIRouter(tags=["fix"])

_AUTH_PAYLOAD = {
    "available": False,
    "code": "auth_required",
    "error": "Sign in to suggest a fix. Your plan tracks how many scans you can fix.",
}


def _limit_payload(user: dict) -> dict:
    plan = user.get("plan") or "free"
    limits = config.PLANS.get(plan, config.PLANS["free"])
    return {
        "available": False,
        "code": "plan_limit",
        "kind": "fix",
        "plan": plan,
        "used": user.get("fixes_used") or 0,
        "limit": limits["fixes"],
    }


@router.post("/api/fix")
async def fix(req: FixReq, user=Depends(optional_user)):
    if user is None:
        return _AUTH_PAYLOAD
    if not db.enabled():
        return _AUTH_PAYLOAD

    # Charge rule (1 fix = one scan). Dedupe on last_fix_scan_id so the same scan's
    # remaining findings don't each consume a fix.
    plan = user.get("plan") or "free"
    limits = config.PLANS.get(plan, config.PLANS["free"])
    used = user.get("fixes_used") or 0
    if used >= limits["fixes"]:
        return _limit_payload(user)

    charge = True
    if req.scan_id:
        charge = req.scan_id != user.get("last_fix_scan_id")
    if charge:
        await db.execute(
            """update users
               set fixes_used = fixes_used + 1, last_fix_scan_id = $1
               where id = $2""",
            req.scan_id or None, user["id"],
        )

    finding = {"cwe_id": req.cwe_id, "title": req.title, "message": req.message}
    try:
        result = gemini.generate_fix(finding, req.code, req.exemplars)
        result["plan"] = plan
        result["fixes_used"] = used + (1 if charge else 0)
        result["fixes_limit"] = limits["fixes"]
        return result
    except Exception as e:
        return {"available": False, "error": f"{type(e).__name__}: {e}"}