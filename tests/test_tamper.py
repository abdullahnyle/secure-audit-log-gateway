"""Tamper detection tests for the hash chain verifier."""
import pytest
from app.db.chain import verify_chain


async def _write_and_fetch(client, auth_headers, test_db, n: int) -> list[dict]:
    for i in range(n):
        resp = await client.post(
            "/api/logs/write",
            json={
                "timestamp": f"2024-01-{i + 1:02d}T00:00:00Z",
                "service": "tamper-test",
                "severity": "INFO",
                "event_type": "test.tamper",
                "user_id": f"user-{i}",
                "message": f"entry {i}",
                "metadata": {},
            },
            headers=auth_headers,
        )
        assert resp.status_code == 202, resp.text
    cursor = test_db["entries"].find().sort("received_at", 1)
    return await cursor.to_list(length=None)


@pytest.mark.asyncio
async def test_clean_chain_all_ok(client, auth_headers, test_db):
    entries = await _write_and_fetch(client, auth_headers, test_db, 4)
    results = verify_chain(list(reversed(entries)))
    statuses = [r["status"] for r in results]
    assert statuses.count("broken") == 0
    assert statuses[-1] == "genesis"
    assert all(s in ("ok", "genesis") for s in statuses)


@pytest.mark.asyncio
async def test_mutate_payload_field_breaks_chain(client, auth_headers, test_db):
    """Mutating entry N's payload changes its hash — entry N+1's prev_hash is now wrong."""
    entries = await _write_and_fetch(client, auth_headers, test_db, 4)
    await test_db["entries"].update_one(
        {"log_id": entries[1]["log_id"]},
        {"$set": {"message": "TAMPERED"}},
    )
    entries = await test_db["entries"].find().sort("received_at", 1).to_list(length=None)
    results = verify_chain(list(reversed(entries)))
    result_by_id = {r["log_id"]: r for r in results}

    assert result_by_id[entries[0]["log_id"]]["status"] == "genesis"
    assert result_by_id[entries[1]["log_id"]]["status"] == "ok"   # prev_hash untouched
    assert result_by_id[entries[2]["log_id"]]["status"] == "broken"  # sees wrong expected hash


@pytest.mark.asyncio
async def test_mutate_prev_hash_breaks_at_that_entry(client, auth_headers, test_db):
    entries = await _write_and_fetch(client, auth_headers, test_db, 3)
    await test_db["entries"].update_one(
        {"log_id": entries[1]["log_id"]},
        {"$set": {"prev_hash": "a" * 64}},
    )
    entries = await test_db["entries"].find().sort("received_at", 1).to_list(length=None)
    results = verify_chain(list(reversed(entries)))
    result_by_id = {r["log_id"]: r for r in results}

    assert result_by_id[entries[0]["log_id"]]["status"] == "genesis"
    assert result_by_id[entries[1]["log_id"]]["status"] == "broken"


@pytest.mark.asyncio
async def test_mutate_genesis_prev_hash_breaks_at_entry_0(client, auth_headers, test_db):
    entries = await _write_and_fetch(client, auth_headers, test_db, 3)
    await test_db["entries"].update_one(
        {"log_id": entries[0]["log_id"]},
        {"$set": {"prev_hash": "b" * 64}},
    )
    entries = await test_db["entries"].find().sort("received_at", 1).to_list(length=None)
    results = verify_chain(list(reversed(entries)))
    result_by_id = {r["log_id"]: r for r in results}

    assert result_by_id[entries[0]["log_id"]]["status"] == "broken"


@pytest.mark.asyncio
async def test_empty_chain_returns_empty(client, auth_headers, test_db):
    assert verify_chain([]) == []


@pytest.mark.asyncio
async def test_single_entry_chain_is_genesis(client, auth_headers, test_db):
    entries = await _write_and_fetch(client, auth_headers, test_db, 1)
    results = verify_chain(list(reversed(entries)))
    assert len(results) == 1
    assert results[0]["status"] == "genesis"
    assert results[0]["log_id"] == entries[0]["log_id"]


@pytest.mark.asyncio
async def test_broken_chain_only_breaks_at_detection_point(client, auth_headers, test_db):
    """Break at N is detected at N+1 (where prev_hash mismatch occurs)."""
    entries = await _write_and_fetch(client, auth_headers, test_db, 4)
    await test_db["entries"].update_one(
        {"log_id": entries[1]["log_id"]},
        {"$set": {"message": "CORRUPTED"}},
    )
    entries = await test_db["entries"].find().sort("received_at", 1).to_list(length=None)
    results = verify_chain(list(reversed(entries)))
    result_by_id = {r["log_id"]: r for r in results}

    assert result_by_id[entries[0]["log_id"]]["status"] == "genesis"
    assert result_by_id[entries[1]["log_id"]]["status"] == "ok"
    assert result_by_id[entries[2]["log_id"]]["status"] == "broken"
