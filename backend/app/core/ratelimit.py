"""In-memory sliding-window rate limiting for the auth endpoints (S5).

The local API is one uvicorn process, so a process-local window is enough for this POC. A
multi-worker deployment would need a shared store (Redis/Postgres); this module deliberately
has no dependency and no persistence.

``RAMPART_AUTH_RATE`` uses ``<count>/<unit>`` pairs separated by commas, e.g.
``5/min,30/hour`` (default). Units: s/sec/second(s), m/min/minute(s), h/hr/hour(s), or a
number of seconds.
"""
from __future__ import annotations

import math
import threading
import time
from collections import deque

from fastapi import HTTPException, Request

from app import config

_UNIT_SECONDS = {
    "s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1,
    "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
    "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600,
}


def parse_spec(spec: str) -> list[tuple[int, int]]:
    """Parse ``"5/min,30/hour"`` into ``[(5, 60), (30, 3600)]``. Invalid parts are ignored."""
    limits: list[tuple[int, int]] = []
    for part in (spec or "").split(","):
        part = part.strip()
        if not part or "/" not in part:
            continue
        count_s, _, unit = part.partition("/")
        try:
            count = int(count_s.strip())
            unit = unit.strip().lower()
            seconds = _UNIT_SECONDS.get(unit) or int(unit)
        except (TypeError, ValueError):
            continue
        if count > 0 and seconds > 0:
            limits.append((count, seconds))
    return limits


class RateLimiter:
    """Sliding-window limiter keyed by an arbitrary tuple (route, ip, email).

    ``clock`` is injectable so tests can advance time without sleeping. Thread-safe: the
    FastAPI handlers are async but may run in a threadpool under TestClient/uvicorn.
    """

    def __init__(self, spec: str, clock=time.monotonic):
        self.limits = parse_spec(spec) or [(5, 60), (30, 3600)]
        self._clock = clock
        self._hits: dict[tuple, deque[float]] = {}
        self._lock = threading.Lock()
        self._horizon = max(seconds for _, seconds in self.limits)
        self._hits_since_sweep = 0

    def hit(self, key: tuple) -> tuple[bool, int]:
        """Record one attempt. Returns ``(allowed, retry_after_seconds)``."""
        now = self._clock()
        with self._lock:
            self._hits_since_sweep += 1
            if self._hits_since_sweep >= 512:
                self._sweep(now)
                self._hits_since_sweep = 0

            dq = self._hits.get(key)
            if dq is None:
                dq = self._hits[key] = deque()
            cutoff = now - self._horizon
            while dq and dq[0] <= cutoff:
                dq.popleft()

            for count, window in self.limits:
                recent = [t for t in dq if t > now - window]
                if len(recent) >= count:
                    oldest = recent[-count]
                    retry = max(1, int(math.ceil(oldest + window - now)))
                    return False, retry

            dq.append(now)
            return True, 0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
            self._hits_since_sweep = 0

    def _sweep(self, now: float) -> None:
        cutoff = now - self._horizon
        for key in list(self._hits):
            dq = self._hits[key]
            while dq and dq[0] <= cutoff:
                dq.popleft()
            if not dq:
                self._hits.pop(key, None)


AUTH_LIMITER = RateLimiter(config.AUTH_RATE)


def auth_limit(route: str, request: Request | None, email: str = "") -> None:
    """Count one auth attempt for (route, client ip, email) and raise ``429`` when over budget.

    The email is part of the key so one abusive address does not lock out every account on the
    machine; the IP keeps a rotating-email attack on one account bounded too.
    """
    ip = "unknown"
    if request is not None and request.client is not None:
        ip = request.client.host or "unknown"
    allowed, retry = AUTH_LIMITER.hit((route, ip, (email or "").strip().lower()))
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. Try again shortly.",
            headers={"Retry-After": str(retry)},
        )
