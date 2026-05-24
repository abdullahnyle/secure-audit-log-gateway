"""Hash chain primitives for tamper-evident audit logs.

Each entry's `prev_hash` is the SHA-256 of the *previous* entry's canonical
JSON representation (with its own `prev_hash` field excluded from the input).
Tampering with any historical entry breaks the chain at that point and forward.
"""
import hashlib
import json
from typing import Any

# Width of a SHA-256 hex digest. Genesis (first-ever entry) uses all zeros so
# verification code doesn't need a special case — it just hashes whatever
# precedes the entry and compares.
GENESIS_HASH = "0" * 64


def canonical_json(entry: dict[str, Any]) -> bytes:
    """Serialize an entry deterministically for hashing.

    Rules:
      - `prev_hash` is excluded (can't be part of its own input).
      - Keys sorted (so dict ordering differences don't change the hash).
      - No whitespace (compact separators).
      - UTF-8 bytes (json.dumps returns str; we encode for hashlib).

    Datetime/UUID/etc. fields must already be stringified by the caller —
    json.dumps doesn't know how to serialize them and would raise.
    """
    filtered = {k: v for k, v in entry.items() if k != "prev_hash"}
    return json.dumps(
        filtered,
        sort_keys=True,
        separators=(",", ":"),  # compact: no spaces after , or :
        ensure_ascii=False,     # keep unicode as-is rather than escaping
    ).encode("utf-8")


def compute_hash(entry: dict[str, Any]) -> str:
    """SHA-256 hex digest of the entry's canonical JSON. 64 hex chars."""
    return hashlib.sha256(canonical_json(entry)).hexdigest()
