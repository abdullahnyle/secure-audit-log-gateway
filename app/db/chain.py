"""Chain-aware insertion for the entries collection.

Each write atomically advances a tail pointer in `chain_state` and inserts
into `entries`. The tail pointer holds the hash of the most recent entry,
which becomes the next entry's `prev_hash`.

Concurrency model: optimistic. Read the tail, compute the new entry's hash,
then conditional-update the tail (filter on old hash). If the update misses,
another writer won the race — we re-read and retry. Bounded retry count
keeps a runaway from looping forever.
"""
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.hashing import GENESIS_HASH, compute_hash

def _now_ms() -> datetime:
    """UTC now, truncated to millisecond precision (matches BSON storage)."""
    n = datetime.now(timezone.utc)
    return n.replace(microsecond=(n.microsecond // 1000) * 1000)


_MAX_RETRIES = 5  # generous; real contention should resolve in 1-2 tries


async def _get_or_init_tail(db: AsyncIOMotorDatabase) -> dict[str, Any]:
    """Return the current tail doc, creating a genesis tail if absent.

    Uses upsert + $setOnInsert so concurrent first-writers don't race to
    create two tails — Mongo's unique _id guarantees one winner.
    """
    tail = await db["chain_state"].find_one_and_update(
        {"_id": "tail"},
        {
            "$setOnInsert": {
                "last_hash": GENESIS_HASH,
                "last_log_id": None,
                "updated_at": datetime.now(timezone.utc),
            }
        },
        upsert=True,
        return_document=True,  # return the post-update doc
    )
    # find_one_and_update with upsert+return_document=AFTER can still return
    # None on the *insert* path in some driver versions — fetch as fallback.
    if tail is None:
        tail = await db["chain_state"].find_one({"_id": "tail"})
    return tail


def _stringify_for_hash(entry: dict[str, Any]) -> dict[str, Any]:
    """Convert non-JSON-native types (datetime, UUID) to strings for hashing.

    Mongo stores datetimes natively; the canonical hash input needs strings
    so the hash is reproducible from either the stored doc or the wire format.
    """
    out = {}
    for k, v in entry.items():
        if isinstance(v, datetime):
            # ISO-8601 with Z suffix for UTC, microsecond precision
            out[k] = (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        else:
            out[k] = v
    return out


async def append_entry(
    db: AsyncIOMotorDatabase,
    *,
    client_payload: dict[str, Any],
    schema_version: int,
    source_ip: str,
) -> dict[str, Any]:
    """Append one entry to the chain atomically. Returns the full stored doc.

    Raises RuntimeError if the chain can't be advanced after _MAX_RETRIES
    (indicates serious contention or a bug — not expected in normal use).
    """
    for attempt in range(_MAX_RETRIES):
        tail = await _get_or_init_tail(db)
        prev_hash = tail["last_hash"]

        # Build the candidate entry. log_id and received_at are server-assigned.
        entry: dict[str, Any] = {
            **client_payload,
            "log_id": str(uuid4()),
            "received_at": _now_ms(),
            "schema_version": schema_version,
            "source_ip": source_ip,
            "prev_hash": prev_hash,
        }

        # Hash uses the string-normalized form so verification is reproducible.
        new_hash = compute_hash(_stringify_for_hash(entry))

        # Conditional tail advance: only succeeds if no other writer raced us.
        advance = await db["chain_state"].update_one(
            {"_id": "tail", "last_hash": prev_hash},
            {
                "$set": {
                    "last_hash": new_hash,
                    "last_log_id": entry["log_id"],
                    "updated_at": datetime.now(timezone.utc),
                }
            },
        )

        if advance.modified_count == 1:
            # We won the race. Safe to insert.
            await db["entries"].insert_one(entry)
            # Strip Mongo's _id before returning — not part of our schema.
            entry.pop("_id", None)
            return entry

        # Lost the race; loop and re-read tail.

    raise RuntimeError(
        f"Failed to advance chain after {_MAX_RETRIES} retries — check for contention."
    )
