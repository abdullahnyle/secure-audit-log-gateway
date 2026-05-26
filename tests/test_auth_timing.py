"""Timing-attack defense test for POST /api/admin/login.

The property being tested: the response time for "wrong username" is
indistinguishable from the response time for "wrong password" — both
paths run bcrypt.checkpw, so neither short-circuits. An attacker who
can measure response times can NOT enumerate valid usernames by
comparing how long each guess takes.

If admin.py ever regresses to short-circuiting on bad usernames (e.g.
`if not username_ok: raise 401` before the bcrypt block), this test
should fail loudly: the wrong-user median will drop by ~250ms (the
bcrypt cost), blowing past the 100ms tolerance.

Caveats:
- Wall-clock timing is noisy. We use the median of 7 runs and a
  100ms tolerance — large enough to absorb GC / OS scheduling jitter,
  small enough to catch a real ~250ms short-circuit gap.
- The test is marked @pytest.mark.timing so it can be opted out of
  via `pytest -m "not timing"` if running on constrained hardware.
"""

import statistics
import time

import pytest

from tests.conftest import TEST_ADMIN_PASSWORD, TEST_ADMIN_USERNAME


# How many real measurements per condition.
ITERATIONS = 7

# How many warmup calls before measurement begins. Lets imports / Mongo
# connection / bcrypt internals settle so the first real sample isn't
# paying first-call costs.
WARMUP = 2

# Tolerance in seconds. bcrypt at cost-12 is ~0.25s, so a true short-circuit
# would produce a gap of that order. 100ms is comfortably below 250ms and
# comfortably above measurement noise on a normal dev machine.
TOLERANCE_SECONDS = 0.100


async def _time_login(client, username: str, password: str) -> float:
    """Single timed login call. Returns elapsed seconds."""
    start = time.perf_counter()
    resp = await client.post(
        "/api/admin/login",
        json={"username": username, "password": password},
    )
    elapsed = time.perf_counter() - start
    # Sanity: this is a negative test, both calls should fail with 401.
    assert resp.status_code == 401, f"unexpected status {resp.status_code}: {resp.text}"
    return elapsed


@pytest.mark.timing
async def test_wrong_username_and_wrong_password_take_similar_time(client):
    """Median response time for wrong-username and wrong-password must be
    within TOLERANCE_SECONDS. Proves admin.py doesn't short-circuit before
    bcrypt on the wrong-username path."""

    # Warmup — discard these measurements.
    for _ in range(WARMUP):
        await _time_login(client, "warmup-user", "warmup-password")

    # Interleave the two conditions to spread out any time-varying noise
    # (background GC, network stack warming up, etc.) evenly across both
    # samples. If we ran all "wrong user" first then all "wrong password",
    # any drift over the test's duration would bias one condition.
    wrong_user_times: list[float] = []
    wrong_pw_times: list[float] = []
    for _ in range(ITERATIONS):
        wrong_user_times.append(
            await _time_login(client, "no-such-admin", "any-password")
        )
        wrong_pw_times.append(
            await _time_login(client, TEST_ADMIN_USERNAME, "wrong-password")
        )

    median_wrong_user = statistics.median(wrong_user_times)
    median_wrong_pw = statistics.median(wrong_pw_times)
    delta = abs(median_wrong_user - median_wrong_pw)

    # On failure: print the raw samples so the cause is debuggable.
    # If this ever fails, the assertion message is the first thing you
    # want — much more useful than just "delta=0.31 > 0.10".
    assert delta < TOLERANCE_SECONDS, (
        f"Timing delta {delta * 1000:.1f}ms exceeds tolerance "
        f"{TOLERANCE_SECONDS * 1000:.0f}ms.\n"
        f"  wrong_user median: {median_wrong_user * 1000:.1f}ms  samples: {[f'{t*1000:.1f}' for t in wrong_user_times]}\n"
        f"  wrong_pw   median: {median_wrong_pw * 1000:.1f}ms  samples: {[f'{t*1000:.1f}' for t in wrong_pw_times]}\n"
        f"This usually means admin.py is short-circuiting before bcrypt on "
        f"the wrong-username path. Confirm both paths run bcrypt.checkpw."
    )
