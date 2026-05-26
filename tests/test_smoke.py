"""Fixture smoke test — confirms test_db, client, and tokens all wire up.

Delete this file once real auth/validation/chain tests exist.
"""
import httpx
from motor.motor_asyncio import AsyncIOMotorDatabase

from tests.conftest import TEST_DB_NAME


async def test_test_db_is_isolated(test_db: AsyncIOMotorDatabase):
    """The fixture really gives us the test db, not production."""
    assert test_db.name == TEST_DB_NAME
    # Fresh db: entries collection exists (via indexes) but is empty.
    count = await test_db.entries.count_documents({})
    assert count == 0


async def test_health_endpoint_via_client(client: httpx.AsyncClient):
    """Client can reach the app in-process; health responds 200."""
    response = await client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] in {"ok", "degraded"}


async def test_write_log_via_fixtures(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
    test_db: AsyncIOMotorDatabase,
):
    """End-to-end: write a log through the app, confirm it lands in the test db."""
    payload = {
        "service": "fixture-smoke",
        "severity": "INFO",
        "event_type": "sanity",
        "message": "fixture smoke write",
        "timestamp": "2026-05-27T00:00:00Z",
    }
    response = await client.post("/api/logs/write", json=payload, headers=auth_headers)
    assert response.status_code == 201, response.text

    # The write went to the TEST db, not production.
    count = await test_db.entries.count_documents({})
    assert count == 1
