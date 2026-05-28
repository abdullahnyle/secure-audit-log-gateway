# Secure Audit Log Gateway

This is the part of a bigger system that remembers what happened.

It's one of 17 modules in a secure exam platform I built with my class at UET Lahore. Whenever something worth recording happens anywhere in that system — someone logs in, an admin changes a permission, a student submits an exam — the event gets sent here. My job was to make sure that once those events are written down, nobody can quietly go back and change the record.

That last part is the whole point. It's easy to store logs. The hard and interesting bit is being able to *prove* a log hasn't been tampered with after the fact.

## What it does, in plain terms

Other modules send their events to this service over HTTP. Each one gets checked, timestamped, given an ID, and stored in MongoDB in a structured, append-only way. Admins can then search through everything from a web dashboard and confirm the full history is still intact.

Two things make it more than a fancy "save this row":

**Each entry is cryptographically linked to the one before it.** Every log record carries the SHA-256 hash of the record before it. So the entries form a chain. Change a single character in any past entry and its hash no longer lines up with what the next entry expects — the chain breaks at exactly that spot. It's the same trick that keeps a blockchain honest, pointed at an audit trail. If someone edits the database directly to hide something, you can see it.

**The stored data is structured and genuinely queryable.** Logs go into a fixed schema — service, severity, event type, user, timestamp, message, metadata — with database indexes built around the questions an admin actually asks. The query endpoint lets you filter by service, severity, event type, user, and time range, all at once, with pagination on top. So when something goes wrong and you're staring at thousands of events, you can narrow it down to the handful that matter in one request. And because the schema is strict about the security-critical fields but relaxed about the rest, one module sending a malformed event can't corrupt the store or take the pipeline down.

## Why I built it the way I did

Two things mattered most to me: the data being **trustworthy and easy to query**, and the system being **hard to quietly break**.

So that's where the effort went. A lot of it is in the schema — deciding what gets stored, how it's indexed, and how bad input gets rejected before it ever reaches the database. The rest is in verification — proving the stored history is actually intact rather than just assuming it. The hash-chaining gets the attention, but the thing I'm actually proudest of is that all of it is backed by a real test suite (61 tests) that treats every security guarantee as something to be proven, not taken on faith.

## How the chain works

```
entry #1 (genesis)     prev_hash = 000...000
entry #2               prev_hash = SHA-256(entry #1)
entry #3               prev_hash = SHA-256(entry #2)
...
```

To verify, you walk the chain oldest to newest, recompute each hash, and check it against what the next entry claims its predecessor was.

There are actually *two* verifiers doing this independently — one in Python on the server, one in JavaScript running in the admin's browser. They're written to produce byte-for-byte identical hashes from the same data. Doing it twice in two languages is deliberate: if the server's data has been tampered with, you can't fully trust the server to grade its own homework, so the browser checks the math on its own. If the two ever disagree, that disagreement is itself a red flag.

## Tech stack

- **Python 3.14** with **FastAPI** for the HTTP layer
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
| `metadata` | free-form structured extras |
| `prev_hash` | hash of the previous entry — the chain link |
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
tests/                 # 61 tests: auth, validation, chain integrity, tamper detection
```

## Running it

You'll need MongoDB running locally on the default port.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

And the tests:

```bash
pytest                    # everything
pytest -m "not timing"    # skip the slow timing-attack test
```

## Being honest about the edges

This is a class project and a few things are scoped to match that. It runs against a single standalone MongoDB rather than a replica set, the auth secrets come from config rather than a proper secrets manager, and the chain verifier lives as a function plus a browser view rather than a standalone public API. Where I'd push it further for a real production system, I've left notes in the code explaining what and why.

---

Part of a 17-module secure exam system · UET Lahore
