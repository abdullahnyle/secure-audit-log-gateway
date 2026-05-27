"""Auth tests for the service-token path (/api/logs/write).

Covers the negative cases enumerated in the jwt_auth dependency:
  - missing Authorization header
  - wrong scheme (Basic instead of Bearer)
  - malformed bearer token (gibberish, not JWT-shaped)
  - expired token (signature valid, exp in past)
  - token signed with wrong secret
  - token signed with wrong algorithm (HS512 instead of HS256)
And the positive case: a valid service token writes successfully.

Admin login tests (POST /api/admin/login) and timing-attack assertions
land in separate files, each a coherent unit.
"""

from datetime import datetime, timezone

import pytest


# ─── Shared payload fixture ───────────────────────────────────────────


@pytest.fixture
def valid_log_payload() -> dict:
    """Minimum-valid POST /api/logs/write body. Reused across negative tests
    so a 422 (schema rejection) can't be confused with a 401 (auth rejection)."""
    return {
        "service": "test-service",
        "severity": "INFO",
        "event_type": "auth_test",
        "message": "auth test event",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


# ─── Negative cases: missing or malformed Authorization header ────────


async def test_missing_authorization_header_returns_401(client, valid_log_payload):
    """No Authorization header at all → 401 with missing_authorization_header detail."""
    resp = await client.post("/api/logs/write", json=valid_log_payload)
    assert resp.status_code == 401
    assert resp.json()["detail"] == "missing_authorization_header"
    # Per RFC 6750 §3, 401 responses must include WWW-Authenticate.
    assert "www-authenticate" in {k.lower() for k in resp.headers.keys()}


async def test_wrong_scheme_returns_401(client, valid_log_payload, service_token):
    """Authorization header present but uses Basic instead of Bearer → 401.

    Note: FastAPI's HTTPBearer only parses Bearer-scheme headers; anything else
    is reported as 'no credentials present', so verify_jwt's explicit
    scheme-mismatch branch never fires for this case. The detail is therefore
    'missing_authorization_header' rather than 'invalid_auth_scheme'. The
    user-facing security guarantee (401 on non-Bearer auth) is the same.
    """
    headers = {"Authorization": f"Basic {service_token}"}
    resp = await client.post("/api/logs/write", json=valid_log_payload, headers=headers)
    assert resp.status_code == 401
    assert resp.json()["detail"] == "missing_authorization_header"


# ─── Negative cases: bad token table (parametrized) ───────────────────


# Each entry: (label_for_test_id, source, is_fixture). When is_fixture is True,
# `source` is the name of a fixture to resolve; otherwise it's a literal token string.
BAD_TOKEN_CASES = [
    ("gibberish",          "this-is-not-a-jwt", False),
    ("almost_jwt_shaped",  "aaa.bbb.ccc",       False),
    ("expired",            "expired_token",     True),
    ("wrong_secret",       "wrong_secret_token", True),
    ("wrong_algorithm",    "wrong_algo_token",  True),
]


@pytest.mark.parametrize(
    "case_label, source, is_fixture",
    BAD_TOKEN_CASES,
    ids=[case[0] for case in BAD_TOKEN_CASES],
)
async def test_bad_token_returns_401(
    client,
    valid_log_payload,
    request,
    case_label,
    source,
    is_fixture,
):
    """Every bad-token shape should return 401. Detail string is asserted only
    for the most informative case (expired) — others may all return the
    deliberately-vague 'invalid_token' from the catch-all branch."""
    bad_token = request.getfixturevalue(source) if is_fixture else source
    headers = {"Authorization": f"Bearer {bad_token}"}
    resp = await client.post("/api/logs/write", json=valid_log_payload, headers=headers)

    assert resp.status_code == 401, f"case={case_label} body={resp.text}"

    # Expired tokens are specifically signaled; the rest collapse to invalid_token.
    if case_label == "expired":
        assert resp.json()["detail"] == "token_expired"


# ─── Positive case: a valid service token succeeds ────────────────────


async def test_valid_service_token_writes_log(client, valid_log_payload, auth_headers):
    """Sanity check that the fixtures all align: with a valid token the request
    actually reaches the handler and writes a log entry (202)."""
    resp = await client.post("/api/logs/write", json=valid_log_payload, headers=auth_headers)
    assert resp.status_code == 202, resp.text
