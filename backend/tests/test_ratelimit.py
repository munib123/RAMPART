"""S5: in-memory sliding-window rate limiting for /api/auth/login and /api/auth/signup.
No database needed - the limiter runs before the DB check. Run from backend/:
    .venv\\Scripts\\python.exe -m pytest tests/test_ratelimit.py -q
"""
from __future__ import annotations

import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.ratelimit import RateLimiter, parse_spec   # noqa: E402


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_parse_spec_supports_minutes_and_hours():
    assert parse_spec("5/min,30/hour") == [(5, 60), (30, 3600)]
    assert parse_spec("3/seconds, 2/h") == [(3, 1), (2, 3600)]
    assert parse_spec("2/120") == [(2, 120)]
    assert parse_spec("garbage,,9/") == []


def test_fifth_attempt_is_allowed_and_the_sixth_is_not():
    clock = Clock()
    limiter = RateLimiter("5/min", clock=clock)

    for _ in range(5):
        allowed, _retry = limiter.hit(("login", "127.0.0.1", "a@example.com"))
        assert allowed is True

    allowed, retry = limiter.hit(("login", "127.0.0.1", "a@example.com"))
    assert allowed is False
    assert retry == 60


def test_window_slides_and_retry_after_shrinks():
    clock = Clock()
    limiter = RateLimiter("2/min", clock=clock)

    assert limiter.hit(("login", "ip", "a@b.c"))[0] is True
    clock.advance(20)
    assert limiter.hit(("login", "ip", "a@b.c"))[0] is True
    allowed, retry = limiter.hit(("login", "ip", "a@b.c"))
    assert allowed is False
    assert retry == 40                     # first hit expires 60 s after t=1000, now t=1020

    clock.advance(41)                      # t=1061: both old hits are outside the window
    assert limiter.hit(("login", "ip", "a@b.c"))[0] is True


def test_long_window_applies_after_short_one_recovers():
    clock = Clock()
    limiter = RateLimiter("2/min,3/hour", clock=clock)

    for _ in range(2):
        assert limiter.hit(("signup", "ip", "x@y.z"))[0] is True
    assert limiter.hit(("signup", "ip", "x@y.z"))[0] is False

    clock.advance(61)                      # per-minute window is clear...
    assert limiter.hit(("signup", "ip", "x@y.z"))[0] is True   # 3rd hit still under 3/hour
    assert limiter.hit(("signup", "ip", "x@y.z"))[0] is False   # 4th exceeds the hour cap


def test_keys_are_independent_per_email_and_route():
    clock = Clock()
    limiter = RateLimiter("1/min", clock=clock)

    assert limiter.hit(("login", "ip", "a@x.y"))[0] is True
    assert limiter.hit(("login", "ip", "a@x.y"))[0] is False
    assert limiter.hit(("login", "ip", "b@x.y"))[0] is True
    assert limiter.hit(("signup", "ip", "a@x.y"))[0] is True


def test_reset_clears_all_windows():
    clock = Clock()
    limiter = RateLimiter("1/min", clock=clock)
    assert limiter.hit(("login", "ip", "a@x.y"))[0] is True
    limiter.reset()
    assert limiter.hit(("login", "ip", "a@x.y"))[0] is True


def test_login_route_returns_429_with_retry_after(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.routers import auth as auth_router

    # Keep the test DB-free and deterministic: the limiter runs before the DB guard.
    monkeypatch.setattr(auth_router.db, "enabled", lambda: False)

    client = TestClient(app)
    email = f"rl-{uuid.uuid4().hex}@example.com"
    codes = [client.post("/api/auth/login",
                         json={"email": email, "password": "not-the-password"}).status_code
             for _ in range(6)]

    assert codes[:5] == [503] * 5          # no DATABASE_URL: DB guard, still counted
    assert codes[5] == 429
    last = client.post("/api/auth/login",
                       json={"email": email, "password": "not-the-password"})
    assert last.status_code == 429
    assert int(last.headers["Retry-After"]) >= 1
