"""Pydantic schemas for the audit log gateway.

Position B validation: strict on critical fields (severity, timestamps),
tolerant on cosmetic ones (message, metadata).

Datetime serialization note: `received_at` and `timestamp` are serialized
in a fixed form (ISO-8601 with explicit Z suffix for UTC, naive datetimes
treated as UTC). This MUST match _stringify_for_hash in app/db/chain.py
byte-for-byte, or client-side chain verification will fail.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any
from uuid import UUID

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
)


MAX_SAFE_JSON_INTEGER = 2**53 - 1


def _serialize_dt(v: datetime) -> str:
    """Produce the canonical ISO string used in both hashing and API output.

    Naive datetimes are treated as UTC (Mongo strips tzinfo on store, so reads
    come back naive even though the original write was UTC-aware).
    """
    if v.tzinfo is None:
        v = v.replace(tzinfo=timezone.utc)
    return v.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _require_string_timestamp(v: object) -> object:
    """Reject non-string inputs before Pydantic's default datetime coercion runs.

    Pydantic v2's default coerces ints/floats via datetime.fromtimestamp(), which
    silently turns a client's 12345 into 1970-01-01T03:25:45Z. For an audit log
    where stored timestamps must reflect client-claimed values, that silent
    coercion is a data-integrity failure. This validator runs before the
    datetime parser and rejects anything that isn't a string outright; valid
    ISO 8601 strings pass through unchanged for normal parsing to handle.
    """
    if not isinstance(v, str):
        raise ValueError("timestamp must be a string in ISO 8601 format")
    return v


# ISO 8601 datetime that explicitly refuses numeric/boolean inputs.
ISOTimestamp = Annotated[datetime, BeforeValidator(_require_string_timestamp)]


def _validate_metadata_value(value: Any, path: str = "metadata") -> Any:
    """Keep metadata reproducible in both Python and JavaScript.

    JavaScript represents every JSON number as a binary floating-point value,
    while Python distinguishes integers and floats. Restricting metadata to
    strings, booleans, null, arrays, objects, and safe integers avoids cases
    such as Python's ``1.0`` versus JavaScript's ``1``.
    """
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_JSON_INTEGER:
            raise ValueError(f"{path} contains an integer outside JavaScript's safe range")
        return value
    if isinstance(value, float):
        raise ValueError(f"{path} contains a floating-point value; use a string if decimals matter")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_metadata_value(item, f"{path}[{index}]")
        return value
    if isinstance(value, dict):
        for key, item in value.items():
            _validate_metadata_value(item, f"{path}.{key}")
        return value
    raise ValueError(f"{path} contains an unsupported value")


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

    model_config = ConfigDict(extra="forbid")

    timestamp: ISOTimestamp = Field(
        ...,
        description="ISO 8601 timestamp from the client. Server records its own arrival time separately.",
    )
    service: str = Field(..., min_length=1, max_length=100)
    severity: Severity = Field(...)
    event_type: str = Field(..., min_length=1, max_length=100)
    user_id: str | None = Field(default=None, max_length=100)
    message: str = Field(..., min_length=1, max_length=10_000)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def _metadata_has_cross_language_json_shape(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_metadata_value(value)

    @field_serializer("timestamp", when_used="json")
    def _ser_timestamp(self, v: datetime) -> str:
        return _serialize_dt(v)


# ─────────────────────────────────────────────────────────────────────────────
# Outgoing: what's stored in MongoDB and returned in responses
# ─────────────────────────────────────────────────────────────────────────────

class LogEntryOut(LogEntryIn):
    """Full record after server-side enrichment."""

    model_config = ConfigDict(extra="forbid")

    # Stored MongoDB records use BSON datetimes. The input model above remains
    # strict about requiring clients to send an ISO-8601 string.
    timestamp: datetime = Field(...)
    log_id: UUID = Field(...)
    received_at: datetime = Field(...)
    prev_hash: str = Field(...)
    schema_version: int = Field(...)
    source_ip: str = Field(...)

    @field_serializer("received_at", when_used="json")
    def _ser_received_at(self, v: datetime) -> str:
        return _serialize_dt(v)


# ─────────────────────────────────────────────────────────────────────────────
# Query: filters for GET /api/logs/query
# ─────────────────────────────────────────────────────────────────────────────

class LogQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service: str | None = Field(default=None)
    severity: Severity | None = Field(default=None)
    event_type: str | None = Field(default=None)
    user_id: str | None = Field(default=None)
    start_time: datetime | None = Field(default=None)
    end_time: datetime | None = Field(default=None)
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


# ─────────────────────────────────────────────────────────────────────────────
# Health + Error responses
# ─────────────────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = Field(...)
    mongo: bool = Field(...)
    version: str = Field(...)


class ErrorResponse(BaseModel):
    error: str = Field(...)
    detail: str = Field(...)
    request_id: str | None = Field(default=None)
