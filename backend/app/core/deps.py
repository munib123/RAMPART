"""FastAPI dependencies: extract + decode the JWT from the Authorization header."""
from __future__ import annotations

from fastapi import Depends, Header, HTTPException

import app.db as db
from app.core import security


async def current_user(authorization: str | None = Header(default=None)):
    """Resolve the authenticated user from a Bearer token, or raise 401."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization[7:].strip()
    payload = security.decode_token(token)
    if not payload or not payload.get("sub"):
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    try:
        user = await db.fetch_row(
            "select id::text as id, name, email, is_admin, created_at from users where id = $1",
            payload["sub"],
        )
    except Exception:
        user = None
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def optional_user(authorization: str | None = Header(default=None)):
    """Return the user if a valid token is present, else None (for unauthenticated scans)."""
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization[7:].strip()
    payload = security.decode_token(token)
    if not payload or not payload.get("sub"):
        return None
    if not db.enabled():
        return None
    try:
        return await db.fetch_row(
            "select id::text as id, name, email, is_admin, created_at from users where id = $1",
            payload["sub"],
        )
    except Exception:
        return None