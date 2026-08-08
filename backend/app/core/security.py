"""Password hashing (bcrypt) + JWT sign/verify (PyJWT). Never log or store plaintext."""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import warnings

import bcrypt

from app import config


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


def create_token(user_id: str, email: str, is_admin: bool = False, name: str = "") -> str:
    import jwt
    now = dt.datetime.now(dt.timezone.utc)
    payload = {
        "sub": str(user_id),
        "email": email,
        "is_admin": bool(is_admin),
        "name": name or "",
        "iat": now,
        "exp": now + dt.timedelta(minutes=config.JWT_EXPIRE_MIN),
    }
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # PyJWT "datetime.datetime is not UTC" notice
        return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)


def decode_token(token: str) -> dict | None:
    if not config.JWT_SECRET or not token:
        return None
    try:
        import jwt
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
    except Exception:
        return None


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)