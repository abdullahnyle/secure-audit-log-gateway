"""Generate a test JWT for hitting the gateway during dev.

Usage:
    python scripts/make_test_token.py
    python scripts/make_test_token.py --sub alice --ttl 3600
    python scripts/make_test_token.py --sub alice --service auth-service

Prints the token to stdout. Use it like:
    curl -H "Authorization: Bearer $(python scripts/make_test_token.py)" http://localhost:8000/api/logs/write
"""
import argparse
import time

import jwt

from app.config import get_settings


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sub", default="dev-user", help="Subject claim (who the token represents).")
    parser.add_argument("--ttl", type=int, default=3600, help="Lifetime in seconds (default 1h).")
    parser.add_argument("--service", default=None, help="Optional custom 'service' claim.")
    args = parser.parse_args()

    settings = get_settings()
    now = int(time.time())

    claims: dict = {
        "sub": args.sub,
        "iat": now,
        "exp": now + args.ttl,
    }
    if settings.jwt_issuer:
        claims["iss"] = settings.jwt_issuer
    if args.service:
        claims["service"] = args.service

    token = jwt.encode(claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    print(token)


if __name__ == "__main__":
    main()
