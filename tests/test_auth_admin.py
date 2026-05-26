"""Auth tests for the admin login path (POST /api/admin/login).

Covers:
  - Correct username + correct password → 200, returns a JWT whose claims
    decode cleanly with role=admin, sub=<configured admin>, and a sensible exp.
  - Correct username + wrong password → 401, generic detail (doesn't leak which).
  - Wrong username + any password → 401, same generic detail.

Timing-attack assertions live in test_auth_timing.py — split out because
they need extra setup (multiple runs, perf_counter timing) that's noisier
than functional tests.
"""

import time
from typing import Annotated

import jwt
import pytest
from fastapi import Depends

from app.config import Settings, get_settings
from tests.conftest import (
    TEST_ADMIN_PASSWORD,
    TEST_ADMIN_USERNAME,
)


# ─── Positive case ────────────────────────────────────────────────────


async def test_correct_credentials_returns_valid_admin_jwt(client, test_settings):
    """Login with the test admin credentials returns 200 + a valid JWT."""
    resp = await client.post(
        "/api/admin/login",
        json={
            "username": TEST_ADMIN_USERNAME,
            "password": TEST_ADMIN_PASSWORD,
        },
    )
    assert resp.status_code == 200, resp.text

    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] > 0
    token = body["access_token"]
    assert isinstance(token, str) and len(token) > 0

    # Decode the token to verify the claim shape. We have direct access to the
    # signing secret via test_settings, so this is a stronger check than just
    # "the server accepts its own token" — it's "the token has the structure
    # we expect, signed with the secret we expect."
    claims = jwt.decode(
        token,
        test_settings.jwt_secret,
        algorithms=[test_settings.jwt_algorithm],
        options={"require": ["exp", "iat"]},
    )
    assert claims["sub"] == TEST_ADMIN_USERNAME
    assert claims["role"] == "admin"

    # exp should be in the future and roughly match the admin_jwt_lifetime_hours
    # setting. Allow a generous tolerance for test execution time.
    now = int(time.time())
    expected_exp = now + (test_settings.admin_jwt_lifetime_hours * 3600)
    assert abs(claims["exp"] - expected_exp) < 60, (
        f"exp drift too large: claim={claims['exp']} expected~={expected_exp}"
    )


# ─── Negative cases ───────────────────────────────────────────────────


async def test_correct_username_wrong_password_returns_401(client):
    """Right username, wrong password → 401 with generic detail."""
    resp = await client.post(
        "/api/admin/login",
        json={
            "username": TEST_ADMIN_USERNAME,
            "password": "definitely-not-the-right-password",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid username or password."


async def test_wrong_username_returns_401(client):
    """Unknown username (regardless of password) → 401 with same generic detail.

    The fact that wrong-username and wrong-password produce the same detail
    string is the deliberate property: a probing attacker can't enumerate
    valid usernames by comparing error responses."""
    resp = await client.post(
        "/api/admin/login",
        json={
            "username": "no-such-admin",
            "password": "whatever",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid username or password."


# ─── Parametrized: both wrong-credential paths share the same detail ──


@pytest.mark.parametrize(
    "username, password, case_label",
    [
        (TEST_ADMIN_USERNAME, "wrong-password", "wrong_password"),
        ("nobody", TEST_ADMIN_PASSWORD,         "wrong_username"),
        ("nobody", "wrong-password",            "both_wrong"),
        ("",       TEST_ADMIN_PASSWORD,         "empty_username"),
    ],
    ids=lambda v: v if isinstance(v, str) and " " not in v else None,
)
async def test_failed_login_responses_are_indistinguishable(
    client, username, password, case_label,
):
    """Every failed-login response should be identical in shape and detail.
    This is the anti-enumeration property; the timing equivalent gets its
    own test in test_auth_timing.py."""
    resp = await client.post(
        "/api/admin/login",
        json={"username": username, "password": password},
    )
    # Empty username will be 422 (Pydantic min_length=1), the others 401.
    # Both are correct rejections — what matters is none of them is 200.
    assert resp.status_code in (401, 422), f"case={case_label} got {resp.status_code}"
    # For the 401 cases the detail must be the generic string.
    if resp.status_code == 401:
        assert resp.json()["detail"] == "Invalid username or password."
