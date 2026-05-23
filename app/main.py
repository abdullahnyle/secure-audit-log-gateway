"""FastAPI application entry point.

Run with: uvicorn app.main:app --reload
"""
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI

from app.config import Settings, get_settings
from app.db.mongo import close_mongo_connection, connect_to_mongo, ping_mongo
from app.middleware.jwt_auth import JWTClaims
from app.schemas.log_entry import HealthResponse


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown hooks. Runs once per process."""
    await connect_to_mongo()
    yield  # ← app serves requests during this period
    await close_mongo_connection()


app = FastAPI(
    title="Secure Audit Log Gateway",
    description="IS-Lab Module 12 — tamper-evident audit log ingestion + query API.",
    version="0.1.0",
    lifespan=lifespan,
)


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


# ─────────────────────────────────────────────────────────────────────────────
# Protected routes (JWT required)
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/logs/write", tags=["logs"])
async def write_log(claims: JWTClaims) -> dict:
    """Skeleton — real implementation lands on Day 2.
    Currently just echoes the caller's JWT claims as proof the auth layer works."""
    return {
        "status": "not_implemented",
        "message": "Day 2 will land the actual write path.",
        "authenticated_as": claims.get("sub"),
    }
