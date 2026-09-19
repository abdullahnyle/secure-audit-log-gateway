"""Hash chain primitives for tamper-evident audit logs.

Each entry's `prev_hash` is the SHA-256 of the *previous* entry's canonical
JSON representation. The stored `prev_hash` is itself part of that canonical
representation, so changing a link changes the entry's hash and every
dependent link after it.
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
      - MongoDB's storage-only `_id` is excluded.
      - Keys use UTF-16 ordering, matching JavaScript's default key sort.
      - No whitespace (compact separators).
      - UTF-8 bytes (json.dumps returns str; we encode for hashlib).

    Datetime/UUID/etc. fields must already be stringified by the caller —
    json.dumps doesn't know how to serialize them and would raise.
    """
    def ordered(value: Any) -> Any:
        if isinstance(value, dict):
            keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
            return {key: ordered(value[key]) for key in keys}
        if isinstance(value, list):
            return [ordered(item) for item in value]
        return value

    filtered = {k: v for k, v in entry.items() if k != "_id"}
    return json.dumps(
        ordered(filtered),
        sort_keys=False,
        separators=(",", ":"),  # compact: no spaces after , or :
        ensure_ascii=False,     # keep unicode as-is rather than escaping
        allow_nan=False,
    ).encode("utf-8")


def compute_hash(entry: dict[str, Any]) -> str:
    """SHA-256 hex digest of the entry's canonical JSON. 64 hex chars."""
    return hashlib.sha256(canonical_json(entry)).hexdigest()
