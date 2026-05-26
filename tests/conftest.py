"""Test fixtures: isolated test DB, app HTTP client with DB + settings overrides, JWT minters.

Design notes:
- Test DB is hardcoded to `audit_logs_test` — never reads from settings,
  so a misconfigured env can't redirect tests at the production db.
- Each test gets a fresh, indexed db (collections dropped between tests).
- HTTP client uses ASGITransport — no real network, same event loop as the app.
- `app.dependency_overrides[get_db]` and `[get_settings]` make every route
  that takes `Depends(get_db)` or `Depends(get_settings)` receive the test
  versions instead.
- The admin password hash below is bcrypt of TEST_ADMIN_PASSWORD on this
  machine. To regenerate (e.g. after a bcrypt cost-factor change):
    python -c "import bcrypt; print(bcrypt.hashpw(b'test-admin-password-not-a-real-secret', bcrypt.gensalt()).decode())"
"""

import time
from typing import AsyncIterator

import httpx
import jwt
import pytest
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.config import Settings, get_settings
from app.db.indexes import ensure_indexes
from app.db.mongo import get_db
from app.main import app

# ─── Hardcoded test constants ─────────────────────────────────────────
# See module docstring for rationale.

TEST_DB_NAME = "audit_logs_test"

# Admin login test credentials. Plaintext + hash must match.
TEST_ADMIN_USERNAME = "test-admin"
TEST_ADMIN_PASSWORD = "test-admin-password-not-a-real-secret"
TEST_ADMIN_PASSWORD_HASH = "$2b$12$mvHc.lWvxEUZxemssCdJne5YsuzGlKWtIjGMrjoEJ13CjVeMSAXIe"

# A deliberately-different secret, used only to mint a token the app should reject.
WRONG_JWT_SECRET = "this-is-a-different-secret-used-only-to-prove-rejection-aaaaaaaa"


# ─── DB fixture ───────────────────────────────────────────────────────


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


# ─── Settings override fixture ────────────────────────────────────────


@pytest.fixture
def test_settings() -> Settings:
    """Settings object for tests. Overrides admin credentials to known test values.

    The real .env values for admin_username and admin_password_hash are bypassed
    via app.dependency_overrides[get_settings] in the `client` fixture.
    Other fields (jwt_secret, jwt_algorithm, etc.) come from .env unchanged so
    the same secret used by production code also verifies test-minted tokens.
    """
    base = get_settings()
    # model_copy preserves every other field; we only swap the admin bits.
    return base.model_copy(update={
        "admin_username": TEST_ADMIN_USERNAME,
        "admin_password_hash": TEST_ADMIN_PASSWORD_HASH,
    })


# ─── HTTP client fixture ──────────────────────────────────────────────


@pytest.fixture
async def client(
    test_db: AsyncIOMotorDatabase,
    test_settings: Settings,
) -> AsyncIterator[httpx.AsyncClient]:
    """HTTP client bound to the FastAPI app with test db + test settings injected."""
    app.dependency_overrides[get_db] = lambda: test_db
    app.dependency_overrides[get_settings] = lambda: test_settings
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    # Always clear overrides so one test's override can't leak into another.
    app.dependency_overrides.clear()


# ─── Valid JWT fixtures ───────────────────────────────────────────────


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


# ─── Invalid JWT fixtures (for negative auth tests) ───────────────────


@pytest.fixture
def expired_token() -> str:
    """JWT with `exp` 1 hour in the past. Signature valid; should be rejected for expiry."""
    settings = get_settings()
    now = int(time.time())
    claims = {
        "sub": "test-service",
        "iat": now - 7200,  # issued 2h ago
        "exp": now - 3600,  # expired 1h ago
    }
    if settings.jwt_issuer:
        claims["iss"] = settings.jwt_issuer
    return jwt.encode(claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)


@pytest.fixture
def wrong_secret_token() -> str:
    """JWT signed with a different secret. Algorithm and claims are valid; signature won't verify."""
    settings = get_settings()
    now = int(time.time())
    claims = {
        "sub": "test-service",
        "iat": now,
        "exp": now + 3600,
    }
    if settings.jwt_issuer:
        claims["iss"] = settings.jwt_issuer
    # Use WRONG_JWT_SECRET, not settings.jwt_secret — that's the whole point.
    return jwt.encode(claims, WRONG_JWT_SECRET, algorithm=settings.jwt_algorithm)


@pytest.fixture
def wrong_algo_token() -> str:
    """JWT signed with HS512 instead of the configured HS256. Server's algorithm
    allowlist should reject it even though the signature is technically valid."""
    settings = get_settings()
    now = int(time.time())
    claims = {
        "sub": "test-service",
        "iat": now,
        "exp": now + 3600,
    }
    if settings.jwt_issuer:
        claims["iss"] = settings.jwt_issuer
    # Real secret, wrong algorithm. Use HS512 (or any non-HS256 HMAC algo).
    wrong_algo = "HS512" if settings.jwt_algorithm != "HS512" else "HS384"
    return jwt.encode(claims, settings.jwt_secret, algorithm=wrong_algo)
