"""Admin authentication route.

Exposes POST /api/admin/login for the admin UI. Verifies username +
password against values in settings (bcrypt-hashed) and mints a JWT
that the UI stores in localStorage and presents on subsequent requests.

The JWT it mints is the same kind validated by the existing jwt_auth
middleware — same secret, same algorithm — so admin requests flow
through exactly the same authentication path as service-to-service
requests from Modules 13/17.
"""

from datetime import datetime, timedelta, timezone
from typing import Annotated

import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.config import Settings, get_settings

router = APIRouter(prefix="/api/admin", tags=["admin"])


class LoginRequest(BaseModel):
    """Body of POST /api/admin/login."""

    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class LoginResponse(BaseModel):
    """Response from POST /api/admin/login on success."""

    access_token: str = Field(..., description="JWT to include as Bearer token on subsequent requests.")
    token_type: str = Field(default="bearer")
    expires_in: int = Field(..., description="Seconds until the token expires.")


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Admin login — returns a JWT for the admin UI.",
)
async def login(
    body: LoginRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> LoginResponse:
    # Compare username in constant-ish time. Python's == on short strings
    # isn't strictly constant-time, but for a lab project with one admin
    # user this is fine; bcrypt below is the real defense.
    username_ok = body.username == settings.admin_username

    # ALWAYS run bcrypt even on bad username, to prevent timing attacks
    # that could reveal whether a username exists. bcrypt.checkpw will
    # return False on a mismatch; we throw away the result if the
    # username was wrong anyway.
    try:
        password_ok = bcrypt.checkpw(
            body.password.encode("utf-8"),
            settings.admin_password_hash.encode("utf-8"),
        )
    except ValueError:
        # bcrypt raises ValueError if the stored hash is malformed.
        # Treat as auth failure rather than 500-ing.
        password_ok = False

    if not (username_ok and password_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    # Mint the JWT. Uses the same secret and algorithm as the existing
    # service-to-service JWT, so it validates through the same middleware.
    now = datetime.now(timezone.utc)
    lifetime = timedelta(hours=settings.admin_jwt_lifetime_hours)
    expires_at = now + lifetime

    claims = {
        "sub": settings.admin_username,
        "role": "admin",
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    if settings.jwt_issuer:
        claims["iss"] = settings.jwt_issuer

    token = jwt.encode(
        claims,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )

    return LoginResponse(
        access_token=token,
        expires_in=int(lifetime.total_seconds()),
    )
