"""POST /api/scan - run the full scan pipeline, optionally persisting for a signed-in user.
Signed-in users are also quota-checked (cumulative per-plan scan allowance). Anonymous (no
token) scans run untracked - today's behavior, kept."""

from __future__ import annotations

import json

from fastapi import APIRouter, Header
from fastapi.responses import JSONResponse

from app import config
from app import db
from app.schemas.scan import ScanReq
from app.services import pipeline
from app.core import security

router = APIRouter(tags=["scan"])


async def _lookup_user(authorization: str | None) -> dict | None:
    """Decode the optional Bearer token to a DB user row (plan + usage included), or None."""
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    payload = security.decode_token(authorization[7:].strip())
    if not payload or not payload.get("sub") or not db.enabled():
        return None
    try:
        return await db.fetch_row(
            "select id::text as id, name, email, is_admin, plan, scans_used, fixes_used, "
            "last_fix_scan_id, created_at from users where id = $1",
            payload["sub"],
        )
    except Exception:
        return None


@router.post("/api/scan")
async def scan(req: ScanReq, authorization: str | None = Header(default=None)):
    import asyncio

    path = (req.path or config.DEFAULT_TARGET).strip()
    user = await _lookup_user(authorization)

    # Quota guard BEFORE spending scan/LLM time: a signed-in user at their plan's scan cap
    # is rejected immediately (no RAG/LLM spend).
    if user is not None:
        plan = user.get("plan") or "free"
        limits = config.PLANS.get(plan, config.PLANS["free"])
        used = user.get("scans_used") or 0
        if used >= limits["scans"]:
            return JSONResponse(status_code=402, content={
                "ok": False, "code": "plan_limit", "kind": "scan", "plan": plan,
                "used": used, "limit": limits["scans"],
            })

    try:
        report = await asyncio.to_thread(pipeline.run_scan, path, req.scanner, req.scope)
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": f"{type(e).__name__}: {e}"})

    # Persist for an authenticated user (best-effort; never blocks the report), then charge
    # one scan toward the plan in the same session.
    if report.get("ok") and user is not None:
        try:
            scan_id = await _persist_scan(user["id"], report)
            report["scan_id"] = scan_id
            await db.execute("update users set scans_used = scans_used + 1 where id = $1", user["id"])
        except Exception as e:
            import traceback
            traceback.print_exc()
    return report


async def _persist_scan(owner_id: str, report: dict) -> str:
    """Store an anonymised scan snapshot: fingerprint fields only, raw code stays local.
    Returns the new scans.id (used to dedupe fix charges)."""
    findings = report.get("findings", [])
    counts = report.get("counts", {})
    vsum = {}
    for f in findings:
        vname = f.get("verdict", {}).get("verdict") or "Unverified"
        vsum[vname] = vsum.get(vname, 0) + 1

    scan_id = await db.fetch_val(
        """insert into scans (owner_id, target, scanner, status, counts, verdict_summary, scope)
           values ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7::jsonb) returning id::text""",
        owner_id, report.get("target", ""), report.get("scanner", ""),
        "done", json.dumps(counts), json.dumps(vsum), json.dumps(report.get("scope") or {}),
    )
    for f in findings:
        v = f.get("verdict", {})
        exemplar_urls = [e.get("url") for e in f.get("exemplars", []) if e.get("url")]
        await db.execute(
            """INSERT INTO findings
               (scan_id, cwe_id, severity, verdict, confidence, rule_id, exemplar_urls)
               values ($1,$2,$3,$4,$5,$6,$7::jsonb)""",
            scan_id, f.get("cwe_id"), f.get("severity"), v.get("verdict"),
            v.get("confidence"), f.get("rule_id"), json.dumps(exemplar_urls),
        )
    return scan_id