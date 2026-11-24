"""Safe API error responses (S5).

Exception strings can contain DSNs, API keys, or local paths (asyncpg errors are especially
chatty). Routes log the full exception with a short request id and return a generic message
plus that id, so an operator can find the detail in the server log without leaking it to the
client or into a saved report.
"""
from __future__ import annotations

import logging
import uuid

from fastapi import Request
from fastapi.responses import JSONResponse

_log = logging.getLogger("rampart.api")


def request_id(request: Request | None) -> str:
    """The id assigned by the middleware, or a fresh one when called outside a request."""
    if request is not None:
        rid = getattr(request.state, "request_id", None)
        if rid:
            return str(rid)
    return uuid.uuid4().hex[:12]


def log_exception(request: Request | None, exc: BaseException, public: str) -> str:
    """Log the full exception (type, message, traceback) tagged with the request id."""
    rid = request_id(request)
    method = getattr(request, "method", "?") if request is not None else "?"
    path = getattr(getattr(request, "url", None), "path", "?")
    _log.error("[%s] %s %s failed (%s): %s", rid, method, path, public, exc,
               exc_info=(type(exc), exc, exc.__traceback__))
    return rid


def internal_error(
    request: Request | None,
    exc: BaseException,
    public: str = "Internal server error",
    status_code: int = 500,
) -> JSONResponse:
    """Return a JSON error with the generic message and request id; log the real cause."""
    rid = log_exception(request, exc, public)
    return JSONResponse(
        status_code=status_code,
        content={"ok": False, "error": public, "request_id": rid},
    )


def error_payload(request: Request | None, exc: BaseException,
                  public: str = "Internal server error") -> dict:
    """The same contract for handlers that return a JSON dict instead of a Response."""
    rid = log_exception(request, exc, public)
    return {"ok": False, "error": public, "request_id": rid}
