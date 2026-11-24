"""RAMPART - FastAPI application. API-only: exposes the scan/verify/auth endpoints.

The UI is a separate frontend (Vite/React/Tauri) that talks to this API over HTTP.
This server does NOT serve HTML/CSS/JS - it only handles JSON requests.
"""
from __future__ import annotations

import threading
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import app.db as db
from app import config
from app.routers import auth as auth_router
from app.routers import scans as scans_router
from app.routers import scan as scan_router
from app.routers import fix as fix_router
from app.routers import browse as browse_router
from app.routers import health as health_router
from app.routers import profile as profile_router
from app.routers import billing as billing_router


def _warm_rag() -> None:
    """Load the ONNX embedder + Chroma collections in the background so the first scan does
    not pay the 10-30 s cold load. Best-effort: never raises, never blocks startup."""
    try:
        from app.services import rag
        rag.warm()
    except Exception as e:
        print(f"[rag] warm-up skipped: {type(e).__name__}: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Warm the RAG embedder/collections off the event loop. A daemon thread keeps startup
    # instant even when ONNX is slow; a failed load is retried on the first real request.
    threading.Thread(target=_warm_rag, name="rag-warm", daemon=True).start()
    # P3: start the Joern CPGQL server sidecar once per backend process (if the runtime is
    # installed and JOERN_ENABLED/JOERN_SERVER allow). Non-blocking - the first scan uses
    # script mode if the JVM is not up yet, later scans use the server. Never raises.
    try:
        from app.services.joern import scan as joern_scan
        joern_scan.warm()
    except Exception as e:
        print(f"[joern] warm-up skipped: {type(e).__name__}: {e}")
    # P4: bring the database forward (backend/db/migrations). Best-effort: a DB that is
    # unreachable at boot just means persistence fails later with its own error, as before.
    if db.enabled():
        try:
            await db.migrate()
        except Exception as e:
            print(f"[db] migration skipped: {type(e).__name__}: {e}")
    yield
    try:
        from app.services.joern import server as joern_server
        joern_server.stop()
    except Exception:
        pass
    try:
        await db.close()
    except Exception:
        pass


app = FastAPI(title="RAMPART", lifespan=lifespan)


def _security_headers(resp, rid: str) -> None:
    """Local-API hardening headers, applied to every response (including errors)."""
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault(
        "Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
    resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-site")
    resp.headers["X-Request-ID"] = rid
    try:                                     # CORS responses must vary on Origin, not be cached
        resp.headers.add_vary_header("Origin")
    except Exception:
        pass


@app.middleware("http")
async def local_api_guard(request, call_next):
    """Assign a request id, cap the body size, and attach security/no-store headers.

    The body cap is a Content-Length check: the local UI always sends a length, and this stops
    a multi-megabyte POST before it is parsed or buffered. Chunked bodies are not inspected.
    """
    rid = uuid.uuid4().hex[:12]
    request.state.request_id = rid
    declared = request.headers.get("content-length")
    if declared:
        try:
            too_big = int(declared) > config.MAX_BODY_BYTES
        except ValueError:
            too_big = False
        if too_big:
            resp = JSONResponse(status_code=413, content={
                "ok": False, "error": "request body too large",
                "limit_bytes": config.MAX_BODY_BYTES, "request_id": rid,
            })
            _security_headers(resp, rid)
            return resp

    resp = await call_next(request)
    # API responses are JSON; never cache them so the UI always gets fresh data.
    resp.headers["Cache-Control"] = "no-store"
    _security_headers(resp, rid)
    return resp


# Only the local UI may call the API. The browser dev server (:5173/:4173) and the Tauri
# webview are allow-listed by default; CORS_ORIGINS adds a custom port, RAMPART_CORS_ALL=1
# restores the old "*" behaviour. Auth is a Bearer header (not cookies), so no credentials
# need mirroring. This middleware is added last so it wraps the guard and adds CORS headers
# to 413 responses too.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if config.CORS_ALL else config.CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(auth_router.router)
app.include_router(scans_router.router)
app.include_router(scan_router.router)
app.include_router(fix_router.router)
app.include_router(browse_router.router)
app.include_router(health_router.router)
app.include_router(profile_router.router)
app.include_router(billing_router.router)


@app.get("/")
def root():
    """API-only backend: the UI is served by the frontend (Vite/React), not here."""
    return {
        "service": "RAMPART API",
        "docs": "/docs",
        "health": "/api/health",
    }