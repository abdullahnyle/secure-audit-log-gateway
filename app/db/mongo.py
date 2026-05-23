"""MongoDB client lifecycle + accessor.

One AsyncIOMotorClient per process, created at app startup,
closed at shutdown. Route handlers get the database via `get_db()`.
"""
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.config import get_settings

# Module-level holders. Populated by connect_to_mongo() on app startup.
_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None


async def connect_to_mongo() -> None:
    """Open the client and verify the server responds. Called on app startup."""
    global _client, _db
    settings = get_settings()

    _client = AsyncIOMotorClient(
        settings.mongo_url,
        serverSelectionTimeoutMS=3000,  # fail fast if Mongo is down (3s vs default 30s)
    )
    # `ping` forces an actual connection attempt — without it, motor lazily
    # connects on first query, and we'd only learn Mongo is down at request time.
    await _client.admin.command("ping")
    _db = _client[settings.mongo_db_name]


async def close_mongo_connection() -> None:
    """Close the client. Called on app shutdown."""
    global _client, _db
    if _client is not None:
        _client.close()
    _client = None
    _db = None


def get_db() -> AsyncIOMotorDatabase:
    """Return the live database handle. Raises if not connected."""
    if _db is None:
        raise RuntimeError("Mongo not connected. Did the app startup hook run?")
    return _db


async def ping_mongo() -> bool:
    """Health-check helper. Returns True if Mongo responds within timeout."""
    if _client is None:
        return False
    try:
        await _client.admin.command("ping")
        return True
    except Exception:
        return False
