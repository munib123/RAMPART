"""Plans/billing: usage snapshot, public plan catalog, and a stub upgrade (no real payment yet)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

import app.db as db
from app import config
from app.core.deps import current_user
from app.schemas.profile import UpgradeReq

router = APIRouter(prefix="/api/billing", tags=["billing"])


def _serialize_plans() -> list[dict]:
    out = []
    for key, p in config.PLANS.items():
        out.append({
            "key": key,
            "label": p["label"],
            "scans": p["scans"],
            "fixes": p["fixes"],
            "price": p["price"],
            "note": p["note"],
        })
    return out


@router.get("")
async def billing(user=Depends(current_user)):
    if not db.enabled():
        raise HTTPException(status_code=503, detail="Database not configured (set DATABASE_URL).")
    plan = user.get("plan") or "free"
    limits = config.PLANS.get(plan, config.PLANS["free"])
    return {
        "plan": plan,
        "label": limits["label"],
        "scans": {"used": user.get("scans_used") or 0, "limit": limits["scans"]},
        "fixes": {"used": user.get("fixes_used") or 0, "limit": limits["fixes"]},
        "models": {"label": "Advanced Gemini verification", "note": "All tiers currently share the working model."},
    }


@router.get("/plans")
async def plans():
    return {"plans": _serialize_plans()}


@router.post("/upgrade")
async def upgrade(req: UpgradeReq, user=Depends(current_user)):
    if not db.enabled():
        raise HTTPException(status_code=503, detail="Database not configured (set DATABASE_URL).")
    plan = (req.plan or "").strip().lower()
    if plan not in ("pro", "premium"):
        raise HTTPException(status_code=422, detail="Upgrade target must be one of: pro, premium")
    await db.execute("update users set plan = $1 where id = $2", plan, user["id"])
    limits = config.PLANS[plan]
    return {
        "ok": True,
        "plan": plan,
        "label": limits["label"],
        "note": "Payment is not wired yet - TODO integrate Stripe/Razorpay; plan set for demo.",
    }