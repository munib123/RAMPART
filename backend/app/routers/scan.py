"""POST /api/scan - run the full scan pipeline, optionally persisting for a signed-in user.
Signed-in users are also quota-checked (cumulative per-plan scan allowance). Anonymous (no
token) scans run untracked - today's behavior, kept."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Header
from fastapi.responses import JSONResponse

from app import config
from app import db
from app.schemas.scan import ScanReq
from app.services import pipeline
from app.core import security

router = APIRouter(tags=["scan"])


def _limits(user: dict) -> dict:
    plan = user.get("plan") or "free"
    return config.PLANS.get(plan, config.PLANS["free"])


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


async def _reserve_scan(user: dict) -> int | None:
    """Atomically take one scan slot and return the new count, or None when the plan is full.
    A single conditional UPDATE means two concurrent requests can never both pass the last
    slot: the second sees scans_used = limit and gets no row back."""
    return await db.fetch_val(
        "update users set scans_used = scans_used + 1 "
        "where id = $1 and scans_used < $2 returning scans_used",
        user["id"], _limits(user)["scans"],
    )


async def _refund_scan(user_id: str) -> None:
    """Give back a reserved slot after a failed scan/persist. Best-effort: a refund failure is
    logged but never turns a usable report into an error."""
    try:
        await db.execute(
            "update users set scans_used = greatest(scans_used - 1, 0) where id = $1",
            user_id,
        )
    except Exception as e:
        print(f"[scan] quota refund failed for {user_id}: {type(e).__name__}: {e}")


@router.post("/api/scan")
async def scan(req: ScanReq, authorization: str | None = Header(default=None)):
    path = (req.path or config.DEFAULT_TARGET).strip()
    user = await _lookup_user(authorization)

    # Quota guard BEFORE spending scan/LLM time. The slot is reserved atomically here and is
    # refunded below if the scan or its persistence fails.
    reserved = False
    if user is not None:
        if await _reserve_scan(user) is None:
            limits = _limits(user)
            return JSONResponse(status_code=402, content={
                "ok": False, "code": "plan_limit", "kind": "scan",
                "plan": user.get("plan") or "free",
                "used": user.get("scans_used") or 0, "limit": limits["scans"],
            })
        reserved = True

    try:
        report = await asyncio.to_thread(pipeline.run_scan, path, req.scanner, req.scope)
    except Exception as e:
        if reserved:
            await _refund_scan(user["id"])
        return JSONResponse(status_code=500, content={"ok": False, "error": f"{type(e).__name__}: {e}"})

    if not report.get("ok"):
        if reserved:
            await _refund_scan(user["id"])
        return report

    # Persist for an authenticated user (best-effort; never blocks the report). The slot was
    # already charged by the reservation, so this no longer increments scans_used.
    if user is not None:
        try:
            scan_id = await _persist_scan(user["id"], report)
            report["scan_id"] = scan_id
        except Exception:
            import traceback
            traceback.print_exc()
            if reserved:
                await _refund_scan(user["id"])
    return report


async def _persist_scan(owner_id: str, report: dict) -> str:
    """Store an anonymised scan snapshot: fingerprint fields only, raw code stays local.
    Returns the new scans.id (used to dedupe fix charges). One transaction, one executemany."""
    findings = report.get("findings", [])
    counts = report.get("counts", {})
    vsum = {}
    for f in findings:
        vname = f.get("verdict", {}).get("verdict") or "Unverified"
        vsum[vname] = vsum.get(vname, 0) + 1

    rows = []
    for f in findings:
        v = f.get("verdict", {})
        exemplar_urls = [e.get("url") for e in f.get("exemplars", []) if e.get("url")]
        rows.append((
            f.get("cwe_id"), f.get("severity"), v.get("verdict"), v.get("confidence"),
            f.get("rule_id"), json.dumps(exemplar_urls), f.get("tool") or "unknown",
        ))

    async with db.transaction() as conn:
        scan_id = await conn.fetchval(
            """insert into scans (owner_id, target, scanner, status, counts, verdict_summary, scope, joern)
               values ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7::jsonb,$8::jsonb) returning id::text""",
            owner_id, report.get("target", ""), report.get("scanner", ""),
            "done", json.dumps(counts), json.dumps(vsum), json.dumps(report.get("scope") or {}),
            json.dumps(report.get("joern") or {}),
        )
        if rows:
            await conn.executemany(
                """INSERT INTO findings
                   (scan_id, cwe_id, severity, verdict, confidence, rule_id, exemplar_urls, tool)
                   values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8)""",
                [(scan_id, *row) for row in rows],
            )
    return scan_id
