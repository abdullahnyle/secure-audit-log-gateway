"""Pydantic schemas for the audit log gateway.

Position B validation: strict on critical fields (severity, timestamps),
tolerant on cosmetic ones (message, metadata).
"""
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


# ─────────────────────────────────────────────────────────────────────────────
# Enums — fixed vocabularies, strictly validated
# ─────────────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    """Log severity levels. Inheriting from `str` so JSON serializes as strings,
    not as enum objects. Fixed set — anything else is rejected by Pydantic."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


# ─────────────────────────────────────────────────────────────────────────────
# Incoming: what clients POST to /api/logs/write
# ─────────────────────────────────────────────────────────────────────────────

class LogEntryIn(BaseModel):
    """Client-supplied fields. Server adds 5 more before storage."""

    # Forbid extra fields the client didn't declare — prevents accidental
    # garbage and stops attackers from injecting fields like `prev_hash`.
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime = Field(
        ...,
        description="ISO 8601 timestamp from the client. Server records its own arrival time separately.",
    )
    service: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Name of the service emitting the log (e.g. 'auth-service').",
    )
    severity: Severity = Field(
        ...,
        description="One of DEBUG, INFO, WARN, ERROR, CRITICAL. Strictly validated.",
    )
    event_type: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Short identifier for the event (e.g. 'user.login.failed').",
    )
    user_id: str | None = Field(
        default=None,
        max_length=100,
        description="Optional user identifier. None for system events.",
    )
    message: str = Field(
        ...,
        min_length=1,
        max_length=10_000,
        description="Human-readable description. Tolerant: any printable string under 10KB.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form structured context. Tolerant: any JSON-serializable dict.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Outgoing: what's stored in MongoDB and returned in responses
# ─────────────────────────────────────────────────────────────────────────────

class LogEntryOut(LogEntryIn):
    """Full record after server-side enrichment. Inherits all client fields,
    adds the 5 server-controlled ones from your schema decision."""

    model_config = ConfigDict(extra="forbid")

    log_id: UUID = Field(..., description="Server-generated UUID, primary identifier.")
    received_at: datetime = Field(..., description="Server clock at the moment of receipt.")
    prev_hash: str = Field(..., description="Hash of the previous log entry — chains entries for tamper-evidence.")
    schema_version: int = Field(..., description="Schema version of this entry, for future migrations.")
    source_ip: str = Field(..., description="IP address that submitted the log (from request).")


# ─────────────────────────────────────────────────────────────────────────────
# Query: filters for GET /api/logs/query
# ─────────────────────────────────────────────────────────────────────────────

class LogQuery(BaseModel):
    """Query parameters for filtering logs. All optional — empty query returns
    recent logs (capped by `limit`)."""

    model_config = ConfigDict(extra="forbid")

    service: str | None = Field(default=None, description="Filter by exact service name.")
    severity: Severity | None = Field(default=None, description="Filter by exact severity.")
    event_type: str | None = Field(default=None, description="Filter by exact event_type.")
    user_id: str | None = Field(default=None, description="Filter by exact user_id.")
    start_time: datetime | None = Field(default=None, description="Inclusive lower bound on `timestamp`.")
    end_time: datetime | None = Field(default=None, description="Inclusive upper bound on `timestamp`.")
    limit: int = Field(default=100, ge=1, le=1000, description="Max results, 1–1000.")
    offset: int = Field(default=0, ge=0, description="Pagination offset.")


# ─────────────────────────────────────────────────────────────────────────────
# Health + Error responses
# ─────────────────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    """Response for GET /health."""
    status: str = Field(..., description="'ok' when healthy, 'degraded' otherwise.")
    mongo: bool = Field(..., description="Whether MongoDB is reachable.")
    version: str = Field(..., description="Gateway version (from config).")


class ErrorResponse(BaseModel):
    """Standardized error envelope for all 4xx/5xx responses."""
    error: str = Field(..., description="Short error code (e.g. 'invalid_token').")
    detail: str = Field(..., description="Human-readable explanation.")
    request_id: str | None = Field(default=None, description="For log correlation.")
