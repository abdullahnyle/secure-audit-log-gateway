"""Admin authorization and timestamp-range query regressions."""
from datetime import datetime


async def test_admin_token_can_query(client, admin_headers):
    response = await client.get("/api/logs/query", headers=admin_headers)
    assert response.status_code == 200
    assert response.json() == []


async def test_service_token_cannot_query_admin_logs(client, auth_headers):
    response = await client.get("/api/logs/query", headers=auth_headers)
    assert response.status_code == 403
    assert response.json()["detail"] == "admin_role_required"


async def test_time_range_uses_bson_datetimes(
    client, auth_headers, admin_headers, test_db,
):
    for day in (1, 2, 3):
        response = await client.post(
            "/api/logs/write",
            headers=auth_headers,
            json={
                "timestamp": f"2026-05-{day:02d}T12:00:00Z",
                "service": "range-test",
                "severity": "INFO",
                "event_type": "query.range",
                "message": f"day {day}",
            },
        )
        assert response.status_code == 202, response.text

    stored = await test_db["entries"].find_one({"message": "day 2"})
    assert isinstance(stored["timestamp"], datetime)

    response = await client.get(
        "/api/logs/query",
        headers=admin_headers,
        params={
            "start_time": "2026-05-02T00:00:00Z",
            "end_time": "2026-05-02T23:59:59Z",
        },
    )

    assert response.status_code == 200, response.text
    assert [entry["message"] for entry in response.json()] == ["day 2"]
