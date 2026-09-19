# Secure Audit Log Gateway

A FastAPI and MongoDB audit-log service, built as my module in a 17-module secure exam platform at UET Lahore. It accepts structured events, restricts queries to admin tokens, and includes an admin dashboard with a browser-side hash-chain checker.

## What it does

Services submit events over HTTP. The gateway validates each event, assigns an ID and receipt timestamp, and stores it in MongoDB. Admins can filter records by service, severity, event type, user, and time range, with pagination.

Each entry contains the SHA-256 hash of the previous entry, and that stored `prev_hash` is included when calculating the entry's own hash. The API exposes append and query operations, with no update or delete endpoint. This is an application-level restriction; it does not prevent a database administrator from changing stored records.

## Verification and trust boundary

Python and JavaScript implementations check the links between entries. The browser fetches the complete unfiltered history for this check instead of treating the displayed page as a complete chain. The second implementation can help expose implementation errors, but the browser receives both the history and its application code from the server. It is not an external trust anchor.

Changing an earlier entry without updating its successor's `prev_hash` breaks the link. A fully privileged attacker who rewrites the records and recomputes the chain can present a consistent false history that both verifiers accept.

The current link-only verifiers also cannot detect an edit to the newest entry or removal of a suffix: there is no successor to expose that change. The database tail pointer is not compared by these verifiers and is not independently protected. Detecting these cases requires a trusted checkpoint or signature outside the attacker's control. Neither is implemented here.

## Storage limitations

Inserting an entry and advancing the tail pointer are separate database operations. The entry is inserted first, so an insertion failure leaves the tail unchanged. A conditional tail update handles competing writers, and a losing candidate is removed before retrying. The sequence is still not a transaction: a process or network failure between operations can leave an orphaned candidate or an ambiguous result. Production use would require transactional storage and more extensive failure and concurrency validation.

## Tech stack

- **Python 3.12** with **FastAPI** for the HTTP layer
- **MongoDB** (via **Motor**, its async driver) for storage
- **Pydantic v2** for schema validation and locking down input
- **PyJWT** + **bcrypt** for auth — service tokens for the modules, password login for admins
- **Alpine.js** for the admin dashboard front end
- **pytest** + **httpx** for the tests

## What a log entry looks like

Every entry has a fixed shape, which is what makes them consistent to query and analyze later:

| Field | What it is |
|---|---|
| `log_id` | server-assigned UUID |
| `timestamp` | when the event happened (sent by the client, ISO-8601) |
| `received_at` | when the gateway received it (set by the server) |
| `service` | which module sent it |
| `severity` | `DEBUG` / `INFO` / `WARN` / `ERROR` / `CRITICAL` |
| `event_type` | category of event, e.g. `auth.login` |
| `user_id` | who the event is about |
| `message` | human-readable description |
| `metadata` | structured extras; strings, booleans, null, arrays, objects, and safe integers |
| `prev_hash` | hash of the previous entry; the chain link |
| `schema_version` | room to migrate the format later |
| `source_ip` | where the write came from |

## How it's laid out

```
app/
├── main.py            # FastAPI app entry point
├── config.py          # settings / environment config
├── api/
│   ├── logs.py        # write + query endpoints
│   └── admin.py       # admin login
├── core/
│   └── hashing.py     # the hash primitive (canonical JSON → SHA-256)
├── db/
│   ├── chain.py       # chain append + verification
│   ├── mongo.py       # connection
│   └── indexes.py     # query indexes
├── schemas/
│   └── log_entry.py   # the validated data model
├── middleware/
│   └── jwt_auth.py    # token verification
└── static/            # admin dashboard (login + log browser) and the JS verifier
tests/                 # auth, validation, chain integrity, tamper detection
```

## Running it

You'll need MongoDB running locally on the default port. After installing dependencies, copy `.env.example` to `.env`, set `JWT_SECRET`, and run `python -m scripts.make_admin_password_hash` to generate `ADMIN_PASSWORD_HASH`. Keep `.env` out of Git.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Fill in JWT_SECRET and ADMIN_PASSWORD_HASH before starting.
uvicorn app.main:app --reload
```

The current suite contains 72 tests, including parametrized cases and a Python/JavaScript hashing comparison.

The tests require MongoDB and the required environment settings. They drop and recreate the `audit_logs_test` database on the configured MongoDB server, so use a disposable local instance. Run:

```bash
pytest                    # everything
pytest -m "not timing"    # skip the slow timing-attack test
```

## Scope

This is a class project and a few things are scoped to match that. It runs against a single standalone MongoDB rather than a replica set, the auth secrets come from config rather than a proper secrets manager, and the chain checker lives as a function plus a browser view rather than a standalone public API. Metadata rejects floating-point values and integers outside JavaScript's safe range so Python and JavaScript can reproduce the supported canonical form. A production system would need an external trust anchor, transactional storage, and broader failure and concurrency testing.

---

Part of a 17-module secure exam system · UET Lahore
