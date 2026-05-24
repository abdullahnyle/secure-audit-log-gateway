"""MongoDB index definitions for the entries collection.

Called once at startup. Safe to re-run — Mongo skips existing indexes.
"""
from pymongo import ASCENDING, DESCENDING, IndexModel
from motor.motor_asyncio import AsyncIOMotorDatabase


async def ensure_indexes(db: AsyncIOMotorDatabase) -> list[str]:
    """Create all indexes on the entries collection. Returns names created."""
    entries = db["entries"]

    indexes = [
        IndexModel(
            [("received_at", DESCENDING)],
            name="received_at_desc",
        ),
        IndexModel(
            [("service", ASCENDING), ("severity", ASCENDING)],
            name="service_severity",
        ),
        IndexModel(
            [("user_id", ASCENDING)],
            name="user_id_sparse",
            sparse=True,
        ),
        IndexModel(
            [("log_id", ASCENDING)],
            name="log_id_unique",
            unique=True,
        ),
    ]

    created = await entries.create_indexes(indexes)
    return created
