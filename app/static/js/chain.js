/**
 * Client-side chain verifier.
 *
 * Mirrors the server's hashing logic for the schema's supported JSON values:
 *   - exclude MongoDB's storage-only `_id`
 *   - include `prev_hash`
 *   - sort keys recursively
 *   - compact separators (no whitespace)
 *   - UTF-8 SHA-256
 *
 * This duplicate implementation is useful for catching implementation errors.
 * It is not an external trust anchor because the server supplies both the
 * application code and the entries being checked.
 */

const GENESIS_HASH = '0'.repeat(64);

/**
 * Recursively sort object keys. Arrays preserve order (they're sequences,
 * not sets). Primitives pass through unchanged.
 *
 * Matches Python's json.dumps(sort_keys=True) behavior — sorting applies
 * at every nested level.
 */
function sortKeysRecursive(value) {
  if (Array.isArray(value)) {
    return value.map(sortKeysRecursive);
  }
  if (value !== null && typeof value === 'object') {
    const sorted = {};
    for (const key of Object.keys(value).sort()) {
      sorted[key] = sortKeysRecursive(value[key]);
    }
    return sorted;
  }
  return value;
}

/**
 * Produce the canonical JSON bytes for an entry, matching the server's
 * canonical_json() function in app/core/hashing.py.
 *
 * Returns a Uint8Array (the UTF-8 bytes), suitable for hashing.
 */
function canonicalJson(entry) {
  // 1. Drop only MongoDB's storage-only identifier.
  const filtered = {};
  for (const [k, v] of Object.entries(entry)) {
    if (k !== '_id') filtered[k] = v;
  }

  // 2. Recursively sort keys
  const sorted = sortKeysRecursive(filtered);

  // 3. Stringify with no whitespace.
  //    JSON.stringify with no `space` argument already uses compact form,
  //    matching Python's separators=(',', ':').
  const json = JSON.stringify(sorted);

  // 4. Encode as UTF-8 bytes
  return new TextEncoder().encode(json);
}

/**
 * Compute SHA-256 of an entry's canonical JSON. Returns lowercase hex.
 *
 * Uses the browser's built-in SubtleCrypto API. async because crypto
 * operations are async on web.
 */
async function computeHash(entry) {
  const bytes = canonicalJson(entry);
  const digest = await crypto.subtle.digest('SHA-256', bytes);

  // Convert ArrayBuffer to hex string
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Verify a complete, newest-first chain.
 *
 * The caller must supply the complete unfiltered history. Entries from
 * /api/logs/query come back newest-first (received_at desc).
 * The chain links oldest -> newest: each entry's prev_hash is the hash
 * of the entry RECEIVED BEFORE IT. So we reverse to oldest-first, then
 * walk forward.
 *
 * Returns an array of { log_id, status, expected, actual } objects,
 * one per entry, in the same order as the input.
 *   status: 'ok'         — link verifies
 *           'broken'     — prev_hash doesn't match expected
 *           'genesis'    — first entry, prev_hash should be the genesis value
 */
async function verifyChain(entries) {
  if (entries.length === 0) return [];

  // Reverse to oldest-first for the walk
  const oldestFirst = [...entries].reverse();

  const results = [];
  let expectedPrevHash = GENESIS_HASH;

  for (const entry of oldestFirst) {
    let status;
    if (entry.prev_hash === expectedPrevHash) {
      status = expectedPrevHash === GENESIS_HASH ? 'genesis' : 'ok';
    } else {
      status = 'broken';
    }

    results.push({
      log_id: entry.log_id,
      status,
      expected: expectedPrevHash,
      actual: entry.prev_hash,
    });

    // The next entry's prev_hash should be the hash of THIS entry
    expectedPrevHash = await computeHash(entry);
  }

  // Restore original (newest-first) order to match how entries are displayed
  results.reverse();
  return results;
}

// Allow dependency-free regression checks under Node without changing the
// browser global functions used by the admin page.
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { canonicalJson, computeHash, verifyChain };
}
