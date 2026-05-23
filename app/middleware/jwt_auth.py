"""JWT validation for the audit log gateway.

Used as a FastAPI dependency rather than ASGI middleware — gives us
per-route control (some routes like /health are public) and lets us
inject the decoded claims directly into route handlers.
"""
from typing import Annotated, Any

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import get_settings

# HTTPBearer extracts the token from `Authorization: Bearer <token>`.
# auto_error=False so WE control the error response shape (matches ErrorResponse).
_bearer_scheme = HTTPBearer(auto_error=False)


def _unauthorized(detail: str) -> HTTPException:
    """401 with a consistent shape. WWW-Authenticate header is required by the spec
    for 401s so clients know which auth scheme to use."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def verify_jwt(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
) -> dict[str, Any]:
    """FastAPI dependency: validates the bearer token, returns decoded claims.

    Usage in a route:
        @app.post("/api/logs/write")
        async def write_log(claims: Annotated[dict, Depends(verify_jwt)]):
            ...

    Rejects with 401 on any of: missing header, wrong scheme, bad signature,
    expired token, malformed payload.
    """
    if credentials is None:
        raise _unauthorized("missing_authorization_header")

    if credentials.scheme.lower() != "bearer":
        raise _unauthorized("invalid_auth_scheme")

    token = credentials.credentials
    settings = get_settings()

    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            issuer=settings.jwt_issuer,  # None disables the check
            options={
                "require": ["exp", "iat"],  # require expiry and issued-at
                "verify_signature": True,
                "verify_exp": True,
            },
        )
    except jwt.ExpiredSignatureError:
        raise _unauthorized("token_expired")
    except jwt.InvalidIssuerError:
        raise _unauthorized("invalid_issuer")
    except jwt.MissingRequiredClaimError as e:
        raise _unauthorized(f"missing_claim:{e.claim}")
    except jwt.InvalidTokenError:
        # Catch-all for everything else: bad signature, malformed, wrong alg, etc.
        # Deliberately vague — don't leak which check failed to a potential attacker.
        raise _unauthorized("invalid_token")

    # Stash claims on request.state for downstream handlers / logging
    request.state.jwt_claims = claims
    return claims


# Type alias for cleaner route signatures.
# Lets you write `claims: JWTClaims` instead of the verbose Annotated form.
JWTClaims = Annotated[dict[str, Any], Depends(verify_jwt)]
