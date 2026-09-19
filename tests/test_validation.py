"""Schema validation tests for POST /api/logs/write.

The auth path is already proven by tests/test_auth.py, so every test here
uses a valid service token and focuses on Pydantic's enforcement of the
LogEntryIn schema:

  - Required fields are required (one parametrized test per field).
  - Severity is a strict enum (no lowercase, no unknown values).
  - String length constraints fire on min and max sides.
  - Timestamp must parse as ISO 8601.
  - Extra fields are rejected (model_config extra='forbid').
  - Positive control: a full valid payload writes successfully.
"""

from datetime import datetime, timezone

import pytest


# ─── Helpers ──────────────────────────────────────────────────────────


def _now_iso() -> str:
    """Canonical ISO timestamp string for test payloads."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def valid_payload() -> dict:
    """Full valid payload with every required field populated. Function-scoped
    so each test mutates its own copy — modifications can't leak between tests."""
    return {
        "timestamp": _now_iso(),
        "service": "test-service",
        "severity": "INFO",
        "event_type": "validation_test",
        "message": "validation test event",
    }


REQUIRED_FIELDS = ["timestamp", "service", "severity", "event_type", "message"]


# ─── Missing required fields ──────────────────────────────────────────


@pytest.mark.parametrize("missing_field", REQUIRED_FIELDS)
async def test_missing_required_field_returns_422(
    client, auth_headers, valid_payload, missing_field,
):
    """Dropping any required field should produce 422 with that field cited."""
    del valid_payload[missing_field]
    resp = await client.post("/api/logs/write", json=valid_payload, headers=auth_headers)
    assert resp.status_code == 422, resp.text

    # Pydantic v2 error detail is a list of dicts with `loc` pointing at the
    # offending field. Assert the missing field is named — protects against
    # regressions where required-ness silently slips.
    errors = resp.json()["detail"]
    missing_locs = [err["loc"] for err in errors if err["type"] == "missing"]
    assert ["body", missing_field] in missing_locs, (
        f"expected missing-field error for '{missing_field}', got: {errors}"
    )


# ─── Severity enum strictness ─────────────────────────────────────────


@pytest.mark.parametrize(
    "bad_severity",
    [
        "info",       # right value, wrong case
        "INFORMATIONAL",
        "FATAL",      # plausible but not in our enum
        "",
        123,
    ],
    ids=["lowercase", "unknown_long", "unknown_short", "empty", "non_string"],
)
async def test_bad_severity_returns_422(
    client, auth_headers, valid_payload, bad_severity,
):
    """Severity is a strict enum — anything outside DEBUG/INFO/WARN/ERROR/CRITICAL fails."""
    valid_payload["severity"] = bad_severity
    resp = await client.post("/api/logs/write", json=valid_payload, headers=auth_headers)
    assert resp.status_code == 422, resp.text


# ─── String length constraints ────────────────────────────────────────


@pytest.mark.parametrize(
    "field, value, label",
    [
        ("service",    "",            "service_empty"),
        ("event_type", "",            "event_type_empty"),
        ("message",    "",            "message_empty"),
        ("service",    "x" * 101,     "service_too_long"),
        ("event_type", "x" * 101,     "event_type_too_long"),
        ("message",    "x" * 10_001,  "message_too_long"),
    ],
    ids=lambda v: v if isinstance(v, str) and len(v) <= 30 else None,
)
async def test_string_length_violations_return_422(
    client, auth_headers, valid_payload, field, value, label,
):
    """Both min_length=1 (empty) and the per-field max_length should fire."""
    valid_payload[field] = value
    resp = await client.post("/api/logs/write", json=valid_payload, headers=auth_headers)
    assert resp.status_code == 422, f"case={label}: {resp.text}"


# ─── Timestamp shape ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "bad_timestamp",
    [
        "not-a-date",
        "2026-13-01T00:00:00Z",  # invalid month
        "2026-02-30T00:00:00Z",  # invalid day
        "yesterday",
        12345,                    # number, not a string
    ],
    ids=["garbage", "bad_month", "bad_day", "english", "non_string"],
)
async def test_bad_timestamp_returns_422(
    client, auth_headers, valid_payload, bad_timestamp,
):
    """Timestamps must parse as ISO 8601 datetime."""
    valid_payload["timestamp"] = bad_timestamp
    resp = await client.post("/api/logs/write", json=valid_payload, headers=auth_headers)
    assert resp.status_code == 422, resp.text


# ─── Extra fields rejected ────────────────────────────────────────────


async def test_extra_field_rejected(client, auth_headers, valid_payload):
    """LogEntryIn uses extra='forbid' — any unknown field should 422.

    This protects two properties simultaneously:
      (a) clients can't smuggle server-only fields (log_id, received_at,
          prev_hash) into their writes;
      (b) typos in client payloads fail loudly instead of being silently
          dropped from storage.
    """
    valid_payload["definitely_not_a_real_field"] = "smuggled value"
    resp = await client.post("/api/logs/write", json=valid_payload, headers=auth_headers)
    assert resp.status_code == 422, resp.text

    errors = resp.json()["detail"]
    extra_locs = [err["loc"] for err in errors if err["type"] == "extra_forbidden"]
    assert ["body", "definitely_not_a_real_field"] in extra_locs, (
        f"expected extra_forbidden error, got: {errors}"
    )


# ─── Positive control ─────────────────────────────────────────────────


async def test_valid_payload_with_optional_fields_writes(client, auth_headers, valid_payload):
    """Sanity: a valid payload — including the optional user_id and metadata —
    writes successfully. Confirms the test setup isn't trivially producing 422s."""
    valid_payload["user_id"] = "test-user-42"
    valid_payload["metadata"] = {"client_ip": "10.0.0.1", "request_id": "abc-123"}
    resp = await client.post("/api/logs/write", json=valid_payload, headers=auth_headers)
    assert resp.status_code == 202, resp.text


@pytest.mark.parametrize(
    "metadata",
    [
        {"dose": 1.0},
        {"nested": [1, {"dose": 2.5}]},
        {"too_large": 2**53},
    ],
    ids=["float", "nested_float", "unsafe_integer"],
)
async def test_metadata_rejects_numbers_that_javascript_cannot_reproduce(
    client, auth_headers, valid_payload, metadata,
):
    valid_payload["metadata"] = metadata
    resp = await client.post("/api/logs/write", json=valid_payload, headers=auth_headers)
    assert resp.status_code == 422, resp.text
