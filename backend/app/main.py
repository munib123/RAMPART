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


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
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


@app.get("/")
def root():
    """API-only backend: the UI is served by the frontend (Vite/React), not here."""
    return {
        "service": "RAMPART API",
        "docs": "/docs",
        "health": "/api/health",
    }