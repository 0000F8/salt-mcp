// Unit tests for src/token-validator.mjs -- validates a bearer against
// salt-api's GET /api/v1/oauth2/grant once per request, cached ~30s by
// token digest. Added by the 2026-09-18 security review that found the
// OAuth path serving tools/list/tools/call for any bearer shape at all,
// with zero check against salt-api.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createTokenValidator } from "../src/token-validator.mjs";
import { SaltBearerApiError } from "../src/salt-bearer-client.mjs";

test("validate() returns {valid: true, scopes, wallets} for a token salt-api accepts", async () => {
  const rest = { async getGrant() { return { scopes: ["chat", "money"], wallets: [{ id: "w1", chain: "ethereum", testnet: false }] }; } };
  const validator = createTokenValidator({ rest });
  const result = await validator.validate("sat_ok");
  assert.deepEqual(result, { valid: true, scopes: ["chat", "money"], wallets: [{ id: "w1", chain: "ethereum", testnet: false }] });
});

test("validate() returns {valid: false} for a token salt-api 401s, without throwing", async () => {
  const rest = {
    async getGrant() {
      throw new SaltBearerApiError("GET", "/api/v1/oauth2/grant", 401, { error: "invalid or expired token" });
    },
  };
  const validator = createTokenValidator({ rest });
  const result = await validator.validate("sat_expired");
  assert.deepEqual(result, { valid: false });
});

test("validate() re-throws any non-401 error rather than treating it as an invalid token", async () => {
  const rest = {
    async getGrant() {
      throw new SaltBearerApiError("GET", "/api/v1/oauth2/grant", 500, { error: "boom" });
    },
  };
  const validator = createTokenValidator({ rest });
  await assert.rejects(() => validator.validate("sat_whatever"), /boom/);
});

test("a repeated call for the SAME token within the ttl hits salt-api only once", async () => {
  let calls = 0;
  const rest = { async getGrant() { calls += 1; return { scopes: [], wallets: [] }; } };
  const validator = createTokenValidator({ rest, ttlMs: 30_000 });
  await validator.validate("sat_same");
  await validator.validate("sat_same");
  await validator.validate("sat_same");
  assert.equal(calls, 1);
});

test("two DIFFERENT tokens are validated independently (no cross-contamination in the cache)", async () => {
  const calls = [];
  const rest = { async getGrant(token) { calls.push(token); return { scopes: [token], wallets: [] }; } };
  const validator = createTokenValidator({ rest, ttlMs: 30_000 });
  const a = await validator.validate("sat_a");
  const b = await validator.validate("sat_b");
  assert.deepEqual(calls, ["sat_a", "sat_b"]);
  assert.deepEqual(a.scopes, ["sat_a"]);
  assert.deepEqual(b.scopes, ["sat_b"]);
});

test("a cached result expires after ttlMs and re-validates against salt-api", async () => {
  let calls = 0;
  let now = 1_000_000;
  const rest = { async getGrant() { calls += 1; return { scopes: [], wallets: [] }; } };
  const validator = createTokenValidator({ rest, ttlMs: 30_000, now: () => now });

  await validator.validate("sat_ttl");
  assert.equal(calls, 1);

  now += 10_000; // still within the 30s window
  await validator.validate("sat_ttl");
  assert.equal(calls, 1, "still cached before ttlMs elapses");

  now += 25_000; // total 35s since the first call -- past the 30s ttl
  await validator.validate("sat_ttl");
  assert.equal(calls, 2, "re-validated once the cache entry expired");
});

test("an invalid ({valid:false}) result is cached too -- salt-api isn't re-asked on every retry of a bad token", async () => {
  let calls = 0;
  const rest = {
    async getGrant() {
      calls += 1;
      throw new SaltBearerApiError("GET", "/api/v1/oauth2/grant", 401, { error: "nope" });
    },
  };
  const validator = createTokenValidator({ rest, ttlMs: 30_000 });
  await validator.validate("sat_bad");
  await validator.validate("sat_bad");
  assert.equal(calls, 1);
});

test("a transient (non-401) failure is NOT cached -- the next call retries against salt-api", async () => {
  let attempt = 0;
  const rest = {
    async getGrant() {
      attempt += 1;
      if (attempt === 1) throw new SaltBearerApiError("GET", "/api/v1/oauth2/grant", 503, { error: "temporarily down" });
      return { scopes: ["chat"], wallets: [] };
    },
  };
  const validator = createTokenValidator({ rest, ttlMs: 30_000 });
  await assert.rejects(() => validator.validate("sat_flaky"), /temporarily down/);
  const result = await validator.validate("sat_flaky");
  assert.deepEqual(result, { valid: true, scopes: ["chat"], wallets: [] });
  assert.equal(attempt, 2, "the failed attempt must not have been cached, or this second call would never have reached salt-api");
});
