"""FastAPI application entry point.

Run with: uvicorn app.main:app --reload
"""
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI
from fastapi.staticfiles import StaticFiles

from app.api import logs as logs_router
from app.api import admin as admin_router
from app.config import Settings, get_settings
from app.db.indexes import ensure_indexes
from app.db.mongo import close_mongo_connection, connect_to_mongo, get_db, ping_mongo
from app.schemas.log_entry import HealthResponse


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown hooks. Runs once per process."""
    await connect_to_mongo()
    await ensure_indexes(get_db())
    yield  # ← app serves requests during this period
    await close_mongo_connection()


app = FastAPI(
    title="Secure Audit Log Gateway",
    description="IS-Lab Module 12 — tamper-evident audit log ingestion + query API.",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(logs_router.router)
app.include_router(admin_router.router)

# Serve the admin UI static files at /admin/*
app.mount("/admin", StaticFiles(directory="app/static", html=True), name="admin-ui")


# ─────────────────────────────────────────────────────────────────────────────
# Public routes (no auth)
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["meta"])
async def health(settings: Annotated[Settings, Depends(get_settings)]) -> HealthResponse:
    """Liveness + dependency check. Returns 200 even when degraded — callers
    inspect the `mongo` field to decide if the gateway is *usable*."""
    mongo_ok = await ping_mongo()
    return HealthResponse(
        status="ok" if mongo_ok else "degraded",
        mongo=mongo_ok,
        version=settings.app_version,
    )
