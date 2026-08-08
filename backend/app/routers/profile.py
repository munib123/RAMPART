"""Profile + billing-facing profile data. GET/PUT /api/profile; password change lives in auth.py."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

import app.db as db
from app import config
from app.core import security
from app.core.deps import current_user
from app.schemas.profile import ChangePasswordReq, UpdateNameReq

router = APIRouter(tags=["profile"])


def _profile(user: dict) -> dict:
    """Public profile shape: user + plan usage limits from the single source of truth."""
    plan = user.get("plan") or "free"
    limits = config.PLANS.get(plan, config.PLANS["free"])
    return {
        "user": {
            "id": user.get("id"),
            "name": user.get("name"),
            "email": user.get("email"),
            "created_at": user.get("created_at"),
            "plan": plan,
        },
        "usage": {
            "plan": plan,
            "scans": {"used": user.get("scans_used") or 0, "limit": limits["scans"]},
            "fixes": {"used": user.get("fixes_used") or 0, "limit": limits["fixes"]},
        },
    }


@router.get("/api/profile")
async def get_profile(user=Depends(current_user)):
    if not db.enabled():
        raise HTTPException(status_code=503, detail="Database not configured (set DATABASE_URL).")
    return _profile(user)


@router.put("/api/profile")
async def update_profile(req: UpdateNameReq, user=Depends(current_user)):
    if not db.enabled():
        raise HTTPException(status_code=503, detail="Database not configured (set DATABASE_URL).")
    name = req.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Display name is required.")
    try:
        row = await db.fetch_row(
            """update users set name = $1 where id = $2
               returning id::text as id, name, email, is_admin, plan, scans_used, fixes_used,
                         last_fix_scan_id, created_at""",
            name, user["id"],
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"update failed: {e}")
    return _profile(row)


@router.post("/api/auth/change-password")
async def change_password(req: ChangePasswordReq, user=Depends(current_user)):
    if not db.enabled():
        raise HTTPException(status_code=503, detail="Database not configured (set DATABASE_URL).")
    row = await db.fetch_row("select password from users where id = $1", user["id"])
    if not row or not security.verify_password(req.old_password, row["password"]):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    await db.execute(
        "update users set password = $1 where id = $2",
        security.hash_password(req.new_password), user["id"],
    )
    return {"ok": True}