"""Auth endpoints: signup, login, me, refresh. Passwords are bcrypt-hashed; tokens are JWT.

S5 hardening: /login and /signup are rate-limited per (route, ip, email); a missing account
still runs a dummy bcrypt check so response timing does not reveal whether an email exists;
DB failures return a generic message (never a DSN/traceback)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field

import app.db as db
from app.core import security
from app.core.deps import current_user
from app.core.errors import internal_error
from app.core.ratelimit import auth_limit

router = APIRouter(prefix="/api/auth", tags=["auth"])

# A real bcrypt hash (cost 12) of a throwaway string. Verifying against it when no user row
# exists costs the same as a real password check, equalising the timing of the 401 path.
_DUMMY_HASH = "$2b$12$gdHkUqryGQ8qL.fxTGVJ0.Dkiy839uooeFsIKTEENo6iDxpRE3nEe"


class SignupReq(BaseModel):
    name: str
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginReq(BaseModel):
    email: EmailStr
    password: str


@router.post("/signup")
async def signup(req: SignupReq, request: Request = None):
    email = req.email.lower()
    auth_limit("signup", request, email)
    if not db.enabled():
        raise HTTPException(status_code=503, detail="Database not configured (set DATABASE_URL).")
    name = req.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Display name is required.")
    if len(name) > 80:
        raise HTTPException(status_code=422, detail="Display name must be 80 characters or fewer.")
    password_hash = security.hash_password(req.password)
    try:
        row = await db.fetch_row(
            """insert into users (name, email, password) values ($1, $2, $3)
               returning id::text as id, name, email, is_admin, plan, created_at""",
            name, email, password_hash,
        )
    except Exception as e:
        if "duplicate" in str(e).lower() or "unique" in str(e).lower():
            raise HTTPException(status_code=409, detail="Email already registered")
        return internal_error(request, e, "signup failed")
    return {
        "user": row,
        "token": security.create_token(row["id"], row["email"], row["is_admin"], row["name"]),
    }


@router.post("/login")
async def login(req: LoginReq, request: Request = None):
    email = req.email.lower()
    auth_limit("login", request, email)
    if not db.enabled():
        raise HTTPException(status_code=503, detail="Database not configured (set DATABASE_URL).")
    try:
        row = await db.fetch_row(
            "select id::text as id, name, email, password, is_admin, plan, created_at "
            "from users where email = $1",
            email,
        )
    except Exception as e:
        return internal_error(request, e, "sign-in failed")

    if not row:
        # Equalise timing with the wrong-password path; the result is intentionally ignored.
        security.verify_password(req.password, _DUMMY_HASH)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not security.verify_password(req.password, row["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    del row["password"]
    return {
        "user": row,
        "token": security.create_token(row["id"], row["email"], row["is_admin"], row["name"]),
    }


@router.get("/me")
async def me(user=Depends(current_user)):
    return {"user": user}


@router.post("/refresh")
async def refresh(user=Depends(current_user)):
    """Exchange a still-valid Bearer token for a fresh one (no schema change).

    ``current_user`` re-reads the row, so plan/quota changes are reflected immediately; an
    expired or invalid token gets the dependency's 401 and the UI clears the session."""
    return {
        "user": user,
        "token": security.create_token(user["id"], user["email"], user["is_admin"], user.get("name", "")),
    }
