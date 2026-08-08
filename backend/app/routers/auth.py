"""Auth endpoints: signup, login, me. Passwords are bcrypt-hashed; tokens are JWT."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field

import app.db as db
from app.core import security
from app.core.deps import current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])


class SignupReq(BaseModel):
    name: str
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginReq(BaseModel):
    email: EmailStr
    password: str


@router.post("/signup")
async def signup(req: SignupReq):
    if not db.enabled():
        raise HTTPException(status_code=503, detail="Database not configured (set DATABASE_URL).")
    name = req.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Display name is required.")
    if len(name) > 80:
        raise HTTPException(status_code=422, detail="Display name must be 80 characters or fewer.")
    email = req.email.lower()
    password_hash = security.hash_password(req.password)
    try:
        row = await db.fetch_row(
            """insert into users (name, email, password) values ($1, $2, $3)
               returning id::text as id, name, email, is_admin, created_at""",
            name, email, password_hash,
        )
    except Exception as e:
        if "duplicate" in str(e).lower() or "unique" in str(e).lower():
            raise HTTPException(status_code=409, detail="Email already registered")
        raise HTTPException(status_code=500, detail=f"signup failed: {e}")
    return {
        "user": row,
        "token": security.create_token(row["id"], row["email"], row["is_admin"], row["name"]),
    }


@router.post("/login")
async def login(req: LoginReq):
    if not db.enabled():
        raise HTTPException(status_code=503, detail="Database not configured (set DATABASE_URL).")
    email = req.email.lower()
    row = await db.fetch_row(
        "select id::text as id, name, email, password, is_admin, created_at from users where email = $1",
        email,
    )
    if not row or not security.verify_password(req.password, row["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    del row["password"]
    return {
        "user": row,
        "token": security.create_token(row["id"], row["email"], row["is_admin"], row["name"]),
    }


@router.get("/me")
async def me(user=Depends(current_user)):
    return {"user": user}