"""POST /api/fix - on-demand LLM fix for one finding (never auto-applied).
Requires a signed-in user. Charges one plan "fix" per distinct scan (users.last_fix_scan_id
dedupes: fixing more findings from the same scan is free).

POST /api/fix/apply + POST /api/fix/revert - apply the generated fix to the user's local
codebase (with a lazy whole-target snapshot) and revert it. Destructive local file ops;
loopback-only like the rest of the API; snapshot is the durable undo net."""
from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

import app.db as db
from app import config
from app.core.deps import current_user, optional_user
from app.schemas.scan import ApplyFixReq, FixReq, RevertReq, VerifyFixReq
from app.services import apply as apply_svc
from app.services import gemini
from app.services.joern import reverify as reverify_svc

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


async def _owns_scan(scan_id: str, user_id: str) -> tuple[str | None, dict | None]:
    """Ownership check for apply/revert: return (scanned target, error payload)."""
    if not db.enabled():
        return None, {"ok": False, "error": "Database not configured (set DATABASE_URL)."}
    if not scan_id:
        return None, {"ok": False, "error": "scan_id is required"}
    row = await db.fetch_row(
        "select target from scans where id = $1 and owner_id = $2", scan_id, user_id)
    if not row:
        return None, {"ok": False, "code": "not_found", "error": "scan not found"}
    return row.get("target"), None


_FORBIDDEN = {"ok": False, "code": "forbidden", "error": "path is outside the scanned target"}


def within_target(path: str | None, target: str | None) -> bool:
    """Containment rule for apply/revert/verify: the client-supplied file path must resolve
    inside the owned scan's target (or BE the target when a single file was scanned). Owning
    a scan row must never turn into a write anywhere on the machine. Pure - resolve() only
    (symlinks and '..' collapse there), so it is unit-testable without a DB."""
    if not path or not target:
        return False
    try:
        p, t = Path(path).resolve(), Path(target).resolve()
    except (OSError, RuntimeError):
        return False
    return p.is_relative_to(t)


def same_target(requested: str | None, target: str | None) -> bool:
    """Revert restores the WHOLE target: the client may name it (resolved equality) or omit it,
    never redirect it."""
    if not requested:
        return True
    if not target:
        return False
    try:
        return Path(requested).resolve() == Path(target).resolve()
    except (OSError, RuntimeError):
        return False


@router.post("/api/fix/apply")
async def apply_fix(req: ApplyFixReq, user=Depends(current_user)):
    target, err = await _owns_scan(req.scan_id, user["id"])
    if err:
        return err
    if not within_target(req.path, target):
        return dict(_FORBIDDEN)
    # The snapshot is the durable revert net - never apply without it.
    snap = await asyncio.to_thread(apply_svc.snapshot_target, req.scan_id, target)
    if not snap.get("ok"):
        return snap
    return await asyncio.to_thread(
        apply_svc.apply_fix, req.path, req.start_line, req.end_line,
        req.fixed_code, req.original_code,
    )


@router.post("/api/fix/revert")
async def revert_fix(req: RevertReq, user=Depends(current_user)):
    target, err = await _owns_scan(req.scan_id, user["id"])
    if err:
        return err
    if not same_target(req.target, target):
        return {**_FORBIDDEN, "error": "target does not match the scanned target"}
    return await asyncio.to_thread(apply_svc.revert_snapshot, req.scan_id, target)


@router.post("/api/fix/verify")
async def verify_fix(req: VerifyFixReq, user=Depends(current_user)):
    """O3 re-verification (P8): rebuild the CPG on the patched code and ask whether the locator
    still fires on this method - and if not, whether a guard appeared or the sink vanished.
    Only meaningful for joern-* findings; the pattern scanners have no such check."""
    target, err = await _owns_scan(req.scan_id, user["id"])
    if err:
        return err
    if not within_target(req.path, target):
        return dict(_FORBIDDEN)
    if not str(req.rule_id or "").startswith("joern-"):
        return {"ok": False, "code": "not_cpg",
                "error": "re-verification runs the CPG locator; this finding came from a pattern scanner"}
    before_dir = None
    if req.fixed_code is None:                          # post-apply: the snapshot is the before state
        snap = apply_svc._snapshot_dir(req.scan_id)
        tree = snap / "tree"
        before_dir = str(tree) if tree.is_dir() else None
    return await asyncio.to_thread(
        reverify_svc.verify, target, req.path, req.function, req.rule_id,
        fixed_code=req.fixed_code, start_line=req.start_line, end_line=req.end_line,
        original_code=req.original_code, before_dir=before_dir,
    )