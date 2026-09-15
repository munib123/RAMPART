"""Scan persistence + history + research endpoints. Only a logged-in user's scans are
stored; raw code_slice is NOT sent to the cloud for research (anonymised fingerprint only)."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException

import app.db as db
from app.core.deps import current_user

router = APIRouter(prefix="/api", tags=["scans"])


@router.post("/scans")
async def create_scan(payload: dict, user=Depends(current_user)):
    """Persist a completed scan + its findings for the authenticated user."""
    if not db.enabled():
        raise HTTPException(status_code=503, detail="Database not configured (set DATABASE_URL).")
    try:
        scan_id = await db.fetch_val(
            """insert into scans (owner_id, target, scanner, status, counts, verdict_summary, scope, joern)
               values ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7::jsonb,$8::jsonb) returning id::text""",
            user["id"], payload.get("target", ""), payload.get("scanner", ""),
            payload.get("status", "done"), json.dumps(payload.get("counts", {})),
            json.dumps(payload.get("verdict_summary", {})), json.dumps(payload.get("scope", {})),
            json.dumps(payload.get("joern") or {}),
        )
        for f in payload.get("findings", []):
            await db.execute(
                """insert into findings
                   (scan_id, cwe_id, severity, verdict, confidence, rule_id, exemplar_urls, tool)
                   values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8)""",
                scan_id, f.get("cwe_id"), f.get("severity"), f.get("verdict"),
                f.get("confidence"), f.get("rule_id"),
                json.dumps(f.get("exemplar_urls", [])), f.get("tool") or "unknown",
            )
        return {"scan_id": scan_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to persist scan: {e}")


@router.get("/scans")
async def list_scans(user=Depends(current_user)):
    if not db.enabled():
        raise HTTPException(status_code=503, detail="Database not configured (set DATABASE_URL).")
    return await db.fetch_all(
        "select id::text, target, scanner, status, counts, verdict_summary, scope, joern, created_at "
        "from scans where owner_id=$1 order by created_at desc",
        user["id"],
    )


@router.get("/scans/{id}")
async def get_scan(id: str, user=Depends(current_user)):
    try:
        return await db.fetch_row(
            "select id, target, scanner, status, counts, verdict_summary, scope, joern, created_at "
            "from scans where id=$1 and owner_id=$2", id, user["id"])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"db error: {e}")


@router.get("/research/overview")
async def research_overview(user=Depends(current_user)):
    try:
        return await db.fetch_all(
            "select cwe_id, severity, verdict, n, avg_conf from cwe_stats order by n desc")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"db error: {e}")


@router.get("/research/tools")
async def research_tools(user=Depends(current_user)):
    """Findings per engine x verdict (tool_stats view): what Joern located vs what the LLM proved."""
    try:
        return await db.fetch_all(
            "select tool, verdict, n, avg_conf from tool_stats order by tool, n desc")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"db error: {e}")


@router.get("/research/codebase")
async def research_codebase(user=Depends(current_user)):
    """Categorize codebase types x vulnerabilities from saved scans (scope must be set)."""
    try:
        return await db.fetch_all(
            "select platform, scanner, cwe_id, severity, verdict, n, avg_conf "
            "from code_stats order by n desc")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"db error: {e}")