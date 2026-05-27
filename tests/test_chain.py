"""Chain integrity tests.

Validates the hash-chain construction properties the system's tamper-evidence
rests on:

  1. Genesis sentinel — first entry's prev_hash is GENESIS_HASH.
  2. Linkage         — entry N's prev_hash equals hash(entry N-1).
  3. Determinism     — same input, same hash, every time.
  4. Sensitivity     — mutating any hashable field changes the hash.
  5. µs-precision    — back-to-back writes still link correctly
                       (regression guard for the Day 3 microsecond bug).

Out of scope for this file: tamper *detection* (verifier flags a mutated
entry) — that's Step 5, a distinct concern from chain construction.
"""
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.core.hashing import GENESIS_HASH, compute_hash
from app.db.chain import _stringify_for_hash


# ─────────────────────────────────────────────────────────────────────────────
# Helper: write N distinct entries through the real API and return stored docs
# ─────────────────────────────────────────────────────────────────────────────

async def _write_n_entries(client, auth_headers, test_db, n: int) -> list[dict]:
    """POST n distinct entries through /api/logs/write; return stored docs in order.

    Goes through the real API so the production chain path is exercised end-to-end.
    Queries Mongo directly afterward because the API response body may not surface
    server-assigned fields (prev_hash, log_id, received_at) needed for verification.
    """
    for i in range(n):
        payload = {
            "timestamp": f"2026-05-27T12:00:{i:02d}Z",
            "service": "test-service",
            "severity": "INFO",
            "event_type": "test.event",
            "message": f"entry number {i}",
        }
        response = await client.post(
            "/api/logs/write", json=payload, headers=auth_headers
        )
        assert response.status_code == 202, (
            f"write {i} failed: {response.status_code} {response.text}"
        )

    cursor = test_db["entries"].find({}).sort("received_at", 1)
    entries = await cursor.to_list(length=n)
    assert len(entries) == n, f"expected {n} entries, got {len(entries)}"
    return entries


# ─────────────────────────────────────────────────────────────────────────────
# Test 1: Genesis sentinel
# ─────────────────────────────────────────────────────────────────────────────

async def test_first_entry_uses_genesis_sentinel(client, auth_headers, test_db):
    """The first entry written to an empty chain has prev_hash = GENESIS_HASH."""
    entries = await _write_n_entries(client, auth_headers, test_db, 1)
    assert entries[0]["prev_hash"] == GENESIS_HASH


# ─────────────────────────────────────────────────────────────────────────────
# Test 2: Chain linkage across N entries
# ─────────────────────────────────────────────────────────────────────────────

async def test_chain_links_correctly_across_n_entries(client, auth_headers, test_db):
    """For entries 1..N-1, each prev_hash equals hash(previous entry).

    This is the core chain property. If this passes, the chain is actually
    a chain — every entry cryptographically commits to the one before it.
    """
    entries = await _write_n_entries(client, auth_headers, test_db, 5)

    # First entry pins to genesis.
    assert entries[0]["prev_hash"] == GENESIS_HASH

    # Each subsequent entry's prev_hash must equal hash(previous entry).
    for i in range(1, len(entries)):
        prev = {k: v for k, v in entries[i - 1].items() if k != "_id"}
        recomputed = compute_hash(_stringify_for_hash(prev))
        assert entries[i]["prev_hash"] == recomputed, (
            f"chain break at entry {i}: "
            f"expected prev_hash={recomputed}, got {entries[i]['prev_hash']}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Test 3: Hash determinism
# ─────────────────────────────────────────────────────────────────────────────

def test_compute_hash_is_deterministic():
    """Same canonical input → same hash, always. Tested twice:
       (a) literal repeat call, (b) same data with keys in different order.
    """
    entry = {
        "log_id": "11111111-1111-1111-1111-111111111111",
        "timestamp": "2026-05-27T12:00:00Z",
        "service": "svc",
        "severity": "INFO",
        "event_type": "test.event",
        "message": "hello",
        "metadata": {},
        "received_at": "2026-05-27T12:00:01Z",
        "schema_version": 1,
        "source_ip": "127.0.0.1",
    }
    # (a) Repeated calls produce identical hashes.
    assert compute_hash(entry) == compute_hash(entry)

    # (b) Key-order changes don't change the hash (sort_keys=True).
    reordered = dict(reversed(list(entry.items())))
    assert compute_hash(entry) == compute_hash(reordered)


# ─────────────────────────────────────────────────────────────────────────────
# Test 4: Hash sensitivity — mutating any hashable field changes the hash
# ─────────────────────────────────────────────────────────────────────────────

# Canonical entry used as the baseline for sensitivity mutations. Pre-stringified
# (datetimes already ISO strings) so compute_hash can run without going through
# _stringify_for_hash — keeps this test a pure unit test of the hash primitive.
_CANONICAL = {
    "log_id": "11111111-1111-1111-1111-111111111111",
    "timestamp": "2026-05-27T12:00:00Z",
    "service": "svc",
    "severity": "INFO",
    "event_type": "test.event",
    "user_id": "user-a",
    "message": "hello",
    "metadata": {"k": "v"},
    "received_at": "2026-05-27T12:00:01Z",
    "schema_version": 1,
    "source_ip": "127.0.0.1",
}


@pytest.mark.parametrize(
    "field, new_value",
    [
        ("log_id", "22222222-2222-2222-2222-222222222222"),
        ("timestamp", "2099-01-01T00:00:00Z"),
        ("service", "different-service"),
        ("severity", "ERROR"),
        ("event_type", "different.event"),
        ("user_id", "user-b"),
        ("message", "tampered"),
        ("metadata", {"k": "different"}),
        ("received_at", "2099-01-01T00:00:00Z"),
        ("schema_version", 999),
        ("source_ip", "9.9.9.9"),
    ],
)
def test_mutating_any_hashable_field_changes_hash(field, new_value):
    """Every field in a stored entry must contribute to the hash.

    If a field is accidentally excluded from canonical_json (e.g. someone
    adds it to the schema but forgets to update hashing), this test catches
    it: the mutated entry would hash identically to the baseline, and the
    chain would silently lose its tamper-evidence for that field.
    """
    baseline_hash = compute_hash(_CANONICAL)

    mutated = dict(_CANONICAL)
    mutated[field] = new_value

    assert compute_hash(mutated) != baseline_hash, (
        f"mutating {field!r} did NOT change the hash — "
        f"field is likely not included in canonical_json"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 5: Microsecond-precision regression guard
# ─────────────────────────────────────────────────────────────────────────────

async def test_chain_survives_back_to_back_writes(client, auth_headers, test_db):
    """Three writes in tight succession still produce a valid chain.

    Day 3 surfaced a microsecond-precision bug where in-memory datetime
    precision differed from BSON-stored precision, causing the hash computed
    at write time to differ from the hash recomputable from the stored doc.
    `_now_ms()` truncates to milliseconds on the way in to make BSON's
    storage precision canonical. This test would fail if that fix regressed.
    """
    entries = await _write_n_entries(client, auth_headers, test_db, 3)

    for i in range(1, len(entries)):
        prev = {k: v for k, v in entries[i - 1].items() if k != "_id"}
        recomputed = compute_hash(_stringify_for_hash(prev))
        assert entries[i]["prev_hash"] == recomputed, (
            f"chain break at entry {i} (back-to-back write regression): "
            f"recomputed={recomputed}, stored={entries[i]['prev_hash']}"
        )
