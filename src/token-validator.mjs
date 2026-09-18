// Validates an OAuth bearer token against salt-api, once per incoming
// MCP request, with a short-lived cache so a client that fires several
// requests in quick succession doesn't make this server hit salt-api on
// every single one.
//
// Added after a 2026-09-18 security review found src/http.mjs's OAuth
// path would happily serve `tools/list` (and, unguarded, `tools/call`)
// for ANY bearer token shaped correctly enough to reach this server --
// including a garbage string -- with zero check against salt-api. A
// resource server that never asks its authorization server whether a
// token is real isn't checking authorization at all.
//
// `GET /api/v1/oauth2/grant` (src/salt-bearer-client.mjs's getGrant) is
// the validation call: salt-api 200s with `{scopes, wallets}` for a real,
// live token and 401s for anything else, so this doubles as both "is this
// token real" AND "what can it spend" (see keyless-tools.mjs's
// requireGrantedWalletId, which reuses the SAME result rather than
// fetching the grant a second time).
//
// The cache is keyed by a SHA-256 DIGEST of the token, never the raw
// token -- so a heap snapshot or an accidental log of this process's
// memory never hands over a live, still-valid access token, the way
// caching by the raw token itself would. Negative results (an invalid
// token) are cached for the SAME ttl -- a flood retrying one dead token
// doesn't re-ask salt-api every time either.
//
// 2026-09-19 availability review (N2): this cache is now a bounded LRU
// (default 10,000 entries) rather than an unbounded Map -- a flood of
// distinct garbage tokens used to be able to grow this cache without
// limit, one entry per unique garbage string, forever. `rest` moved from
// a constructor option to a per-call argument: the underlying fetch it
// makes carries THIS request's edge headers (src/edge-headers.mjs), which
// are per-caller-IP, so baking one `rest` in at construction time would
// have reported whichever caller happened to trigger the first cache miss
// as the source of every later one too.

import { createHash } from "node:crypto";
import { SaltBearerApiError } from "./salt-bearer-client.mjs";

const DEFAULT_MAX_ENTRIES = 10_000;

function digestFor(token) {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/**
 * @param {{ttlMs?: number, maxEntries?: number, now?: () => number}} options
 */
export function createTokenValidator({ ttlMs = 30_000, maxEntries = DEFAULT_MAX_ENTRIES, now = Date.now } = {}) {
  // Map iteration order is insertion order, which is exactly what an LRU
  // needs: `get` re-inserts a hit at the end (most-recently-used), `set`
  // evicts from the front (least-recently-used) once over maxEntries.
  const cache = new Map(); // digest -> { result, expiresAt }

  function readCache(key) {
    const cached = cache.get(key);
    if (!cached) return undefined;
    if (cached.expiresAt <= now()) {
      cache.delete(key);
      return undefined;
    }
    // Touch: move to the end so this entry looks recently-used.
    cache.delete(key);
    cache.set(key, cached);
    return cached.result;
  }

  function writeCache(key, result) {
    cache.delete(key); // re-insert at the end even on an update
    cache.set(key, { result, expiresAt: now() + ttlMs });
    while (cache.size > maxEntries) {
      const oldestKey = cache.keys().next().value;
      cache.delete(oldestKey);
    }
  }

  /**
   * @param {string} token
   * @param {{rest: object}} options the REST client scoped to the
   *   CURRENT request's edge headers (see src/edge-headers.mjs) -- used
   *   only on a cache miss.
   * @returns {Promise<{valid: true, scopes: string[], wallets: object[]} | {valid: false}>}
   */
  async function validate(token, { rest }) {
    const key = digestFor(token);
    const cached = readCache(key);
    if (cached) return cached;

    let result;
    try {
      const grant = await rest.getGrant(token);
      result = { valid: true, scopes: Array.isArray(grant?.scopes) ? grant.scopes : [], wallets: Array.isArray(grant?.wallets) ? grant.wallets : [] };
    } catch (err) {
      if (err instanceof SaltBearerApiError && err.status === 401) {
        result = { valid: false };
      } else {
        // A transient/other failure (salt-api unreachable, a 5xx, ...) is
        // NOT the same claim as "this token is invalid" -- caching that
        // would lock a client out with the wrong error for up to ttlMs
        // over what might be a one-off blip. Let the caller see it and
        // decide (src/http.mjs answers 502, not 401, for this case).
        throw err;
      }
    }
    writeCache(key, result);
    return result;
  }

  return { validate, size: () => cache.size };
}
