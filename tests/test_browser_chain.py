"""Cross-language canonicalization checks using the dependency-free JS file."""
import json
import subprocess
from pathlib import Path

from app.core.hashing import canonical_json, compute_hash


CHAIN_JS = Path(__file__).parents[1] / "app" / "static" / "js" / "chain.js"


def _node_hash(entry: dict) -> str:
    script = (
        "const {computeHash} = require(process.argv[1]);"
        "const entry = JSON.parse(process.argv[2]);"
        "computeHash(entry).then(value => process.stdout.write(value));"
    )
    result = subprocess.run(
        ["node", "-e", script, str(CHAIN_JS), json.dumps(entry)],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def test_python_and_javascript_hash_supported_metadata_identically():
    entry = {
        "log_id": "11111111-1111-1111-1111-111111111111",
        "timestamp": "2026-05-27T12:00:00Z",
        "service": "svc",
        "severity": "INFO",
        "event_type": "test.event",
        "user_id": None,
        "message": "Unicode is supported: لاہور",
        "metadata": {"nested": [True, None, 42, {"z": "last", "a": "first"}]},
        "received_at": "2026-05-27T12:00:01Z",
        "schema_version": 1,
        "source_ip": "127.0.0.1",
        "prev_hash": "0" * 64,
    }

    assert _node_hash(entry) == compute_hash(entry)


def test_prev_hash_is_present_in_python_canonical_json():
    encoded = canonical_json({"message": "test", "prev_hash": "a" * 64})
    assert b'"prev_hash"' in encoded
