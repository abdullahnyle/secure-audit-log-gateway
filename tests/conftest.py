"""Test fixtures: isolated test DB, app HTTP client with DB override, JWT minters.

Design notes:
- Test DB is hardcoded to `audit_logs_test` — never reads from settings,
  so a misconfigured env can't redirect tests at the production db.
- Each test gets a fresh, indexed db (collections dropped between tests).
- HTTP client uses ASGITransport — no real network, same event loop as the app.
- `app.dependency_overrides[get_db]` makes every route that takes
  `db: Annotated[..., Depends(get_db)]` receive the test db instead.
"""
import time
from typing import AsyncIterator

import httpx
import jwt
import pytest
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.config import get_settings
from app.db.indexes import ensure_indexes
from app.db.mongo import get_db
from app.main import app

# Hardcoded — see module docstring for rationale.
TEST_DB_NAME = "audit_logs_test"


@pytest.fixture
async def test_db() -> AsyncIterator[AsyncIOMotorDatabase]:
    """Fresh, indexed test database. Dropped before yield and after teardown."""
    settings = get_settings()
    client = AsyncIOMotorClient(settings.mongo_url, serverSelectionTimeoutMS=3000)
    db = client[TEST_DB_NAME]

    # Drop before, not just after — protects against a previously-crashed test
    # leaving stale data in the test db.
    await client.drop_database(TEST_DB_NAME)
    await ensure_indexes(db)

    yield db

    await client.drop_database(TEST_DB_NAME)
    client.close()


@pytest.fixture
async def client(test_db: AsyncIOMotorDatabase) -> AsyncIterator[httpx.AsyncClient]:
    """HTTP client bound to the FastAPI app with the test db injected."""
    app.dependency_overrides[get_db] = lambda: test_db

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    # Always clear overrides so one test's override can't leak into another.
    app.dependency_overrides.clear()


@pytest.fixture
def service_token() -> str:
    """Valid JWT for a service-to-service caller. 1-hour lifetime."""
    settings = get_settings()
    now = int(time.time())
    claims = {
        "sub": "test-service",
        "iat": now,
        "exp": now + 3600,
    }
    if settings.jwt_issuer:
        claims["iss"] = settings.jwt_issuer
    return jwt.encode(claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)


@pytest.fixture
def admin_token() -> str:
    """Valid JWT for an admin caller (role=admin). 1-hour lifetime."""
    settings = get_settings()
    now = int(time.time())
    claims = {
        "sub": "test-admin",
        "role": "admin",
        "iat": now,
        "exp": now + 3600,
    }
    if settings.jwt_issuer:
        claims["iss"] = settings.jwt_issuer
    return jwt.encode(claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)


@pytest.fixture
def auth_headers(service_token: str) -> dict[str, str]:
    """Shortcut: ready-to-use Authorization header with a service token."""
    return {"Authorization": f"Bearer {service_token}"}
