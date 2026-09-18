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
// caching by the raw token itself would.

import { createHash } from "node:crypto";
import { SaltBearerApiError } from "./salt-bearer-client.mjs";

function digestFor(token) {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/**
 * @param {{rest: object, ttlMs?: number, now?: () => number}} options
 */
export function createTokenValidator({ rest, ttlMs = 30_000, now = Date.now }) {
  const cache = new Map(); // digest -> { result, expiresAt }

  /**
   * @returns {Promise<{valid: true, scopes: string[], wallets: object[]} | {valid: false}>}
   */
  async function validate(token) {
    const key = digestFor(token);
    const cached = cache.get(key);
    if (cached && cached.expiresAt > now()) return cached.result;

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
    cache.set(key, { result, expiresAt: now() + ttlMs });
    return result;
  }

  return { validate };
}
