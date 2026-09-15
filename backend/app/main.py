"""RAMPART - FastAPI application. API-only: exposes the scan/verify/auth endpoints.

The UI is a separate frontend (Vite/React/Tauri) that talks to this API over HTTP.
This server does NOT serve HTML/CSS/JS - it only handles JSON requests.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import app.db as db
from app.routers import auth as auth_router
from app.routers import scans as scans_router
from app.routers import scan as scan_router
from app.routers import fix as fix_router
from app.routers import browse as browse_router
from app.routers import health as health_router
from app.routers import profile as profile_router
from app.routers import billing as billing_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # P3: start the Joern CPGQL server sidecar once per backend process (if the runtime is
    # installed and JOERN_ENABLED/JOERN_SERVER allow). Non-blocking - the first scan uses
    # script mode if the JVM is not up yet, later scans use the server. Never raises.
    try:
        from app.services.joern import scan as joern_scan
        joern_scan.warm()
    except Exception as e:
        print(f"[joern] warm-up skipped: {type(e).__name__}: {e}")
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

# Allow the browser dev server (:5173) and the Tauri webview (tauri://localhost /
# http://localhost) to call this localhost API. POC binds to 127.0.0.1 only, so
# permitting all origins here is acceptable. Auth is via the Authorization header
# (Bearer token), not cookies, so no credentials need mirroring.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def no_store(request, call_next):
    # API responses are JSON; never cache them so the UI always gets fresh data.
    resp = await call_next(request)
    resp.headers["Cache-Control"] = "no-store"
    return resp


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