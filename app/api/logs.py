"""Audit log API routes — write and query.

Mounted under /api/logs in app.main.
"""
from typing import Annotated

from fastapi import APIRouter, Depends, Request, status

from app.config import Settings, get_settings
from app.db.chain import append_entry
from app.db.mongo import get_db
from app.middleware.jwt_auth import JWTClaims
from app.schemas.log_entry import LogEntryIn, LogEntryOut, LogQuery

router = APIRouter(prefix="/api/logs", tags=["logs"])


@router.post(
    "/write",
    response_model=LogEntryOut,
    status_code=status.HTTP_201_CREATED,
    summary="Append a new log entry to the chain",
)
async def write_log(
    payload: LogEntryIn,
    request: Request,
    claims: JWTClaims,
    settings: Annotated[Settings, Depends(get_settings)],
) -> LogEntryOut:
    """Validate, enrich, hash-chain, and persist a log entry.

    Authentication: requires valid JWT (enforced by JWTClaims dependency).
    The caller's identity (claims['sub']) is *not* trusted as user_id —
    user_id is whatever the client puts in the payload, since one service
    may log on behalf of many users. The JWT proves the *service* is allowed
    to write; the payload says *what* it's writing.
    """
    # Extract source IP. request.client.host is the immediate peer; if we ever
    # sit behind a reverse proxy, swap this for X-Forwarded-For parsing.
    source_ip = request.client.host if request.client else "unknown"

    entry = await append_entry(
        get_db(),
        client_payload=payload.model_dump(mode="json"),
        schema_version=settings.schema_version,
        source_ip=source_ip,
    )

    return LogEntryOut(**entry)


@router.get(
    "/query",
    response_model=list[LogEntryOut],
    summary="Query log entries with filters and pagination",
)
async def query_logs(
    claims: JWTClaims,
    query: Annotated[LogQuery, Depends()],
) -> list[LogEntryOut]:
    """Return log entries matching the filters, newest first.

    All filter fields are optional. Empty query returns the most recent
    `limit` entries (default 100, max 1000). Pagination via `offset`.

    `start_time`/`end_time` filter on the *client-supplied* `timestamp`,
    not `received_at` — debugging usually cares about when the event happened,
    not when the gateway saw it.
    """
    db = get_db()

    # Build the filter dict by including only fields the caller set.
    # Pydantic gave us a model — we walk its non-None fields.
    mongo_filter: dict = {}
    if query.service is not None:
        mongo_filter["service"] = query.service
    if query.severity is not None:
        mongo_filter["severity"] = query.severity.value
    if query.event_type is not None:
        mongo_filter["event_type"] = query.event_type
    if query.user_id is not None:
        mongo_filter["user_id"] = query.user_id

    # Time range on client-supplied timestamp. $gte/$lte for inclusive bounds.
    if query.start_time is not None or query.end_time is not None:
        ts_filter: dict = {}
        if query.start_time is not None:
            ts_filter["$gte"] = query.start_time
        if query.end_time is not None:
            ts_filter["$lte"] = query.end_time
        mongo_filter["timestamp"] = ts_filter

    cursor = (
        db["entries"]
        .find(mongo_filter, {"_id": 0})  # exclude Mongo's _id; not in our schema
        .sort("received_at", -1)         # newest first
        .skip(query.offset)
        .limit(query.limit)
    )

    docs = await cursor.to_list(length=query.limit)
    return [LogEntryOut(**doc) for doc in docs]
