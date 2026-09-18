// Unit tests for src/token-validator.mjs -- validates a bearer against
// salt-api's GET /api/v1/oauth2/grant once per request, cached ~30s by
// token digest, in a bounded LRU (2026-09-19 availability review, N2).
// Added by the 2026-09-18 security review that found the OAuth path
// serving tools/list/tools/call for any bearer shape at all, with zero
// check against salt-api.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createTokenValidator } from "../src/token-validator.mjs";
import { SaltBearerApiError } from "../src/salt-bearer-client.mjs";

function restReturning(fn) {
  return { async getGrant(token) { return fn(token); } };
}

function restThrowing(err) {
  return { async getGrant() { throw err; } };
}

test("validate() returns {valid: true, scopes, wallets} for a token salt-api accepts", async () => {
  const rest = restReturning(() => ({ scopes: ["chat", "money"], wallets: [{ id: "w1", chain: "ethereum", testnet: false }] }));
  const validator = createTokenValidator({});
  const result = await validator.validate("sat_ok", { rest });
  assert.deepEqual(result, { valid: true, scopes: ["chat", "money"], wallets: [{ id: "w1", chain: "ethereum", testnet: false }] });
});

test("validate() returns {valid: false} for a token salt-api 401s, without throwing", async () => {
  const rest = restThrowing(new SaltBearerApiError("GET", "/api/v1/oauth2/grant", 401, { error: "invalid or expired token" }));
  const validator = createTokenValidator({});
  const result = await validator.validate("sat_expired", { rest });
  assert.deepEqual(result, { valid: false });
});

test("validate() re-throws any non-401 error rather than treating it as an invalid token", async () => {
  const rest = restThrowing(new SaltBearerApiError("GET", "/api/v1/oauth2/grant", 500, { error: "boom" }));
  const validator = createTokenValidator({});
  await assert.rejects(() => validator.validate("sat_whatever", { rest }), /boom/);
});

test("a repeated call for the SAME token within the ttl hits salt-api only once", async () => {
  let calls = 0;
  const rest = restReturning(() => { calls += 1; return { scopes: [], wallets: [] }; });
  const validator = createTokenValidator({ ttlMs: 30_000 });
  await validator.validate("sat_same", { rest });
  await validator.validate("sat_same", { rest });
  await validator.validate("sat_same", { rest });
  assert.equal(calls, 1);
});

test("a cache hit uses whichever `rest` this particular call passed, never the one from an earlier miss -- but doesn't call it at all", async () => {
  // Regression for the exact reason `rest` moved from the constructor to
  // a per-call argument: if the validator baked in the FIRST request's
  // rest client (carrying THAT request's caller-IP edge headers), a
  // cache hit for a later request from a DIFFERENT caller IP would still
  // look, to salt-api, like it came from the first caller. A cache HIT
  // must not call rest.getGrant at all -- this proves the second `rest`
  // (which would throw if ever touched) is safely ignored.
  const rest1 = restReturning(() => ({ scopes: ["chat"], wallets: [] }));
  const rest2 = { async getGrant() { throw new Error("must never be called on a cache hit"); } };
  const validator = createTokenValidator({ ttlMs: 30_000 });
  const first = await validator.validate("sat_shared", { rest: rest1 });
  const second = await validator.validate("sat_shared", { rest: rest2 });
  assert.deepEqual(first, second);
});

test("two DIFFERENT tokens are validated independently (no cross-contamination in the cache)", async () => {
  const calls = [];
  const rest = restReturning((token) => { calls.push(token); return { scopes: [token], wallets: [] }; });
  const validator = createTokenValidator({ ttlMs: 30_000 });
  const a = await validator.validate("sat_a", { rest });
  const b = await validator.validate("sat_b", { rest });
  assert.deepEqual(calls, ["sat_a", "sat_b"]);
  assert.deepEqual(a.scopes, ["sat_a"]);
  assert.deepEqual(b.scopes, ["sat_b"]);
});

test("a cached result expires after ttlMs and re-validates against salt-api", async () => {
  let calls = 0;
  let now = 1_000_000;
  const rest = restReturning(() => { calls += 1; return { scopes: [], wallets: [] }; });
  const validator = createTokenValidator({ ttlMs: 30_000, now: () => now });

  await validator.validate("sat_ttl", { rest });
  assert.equal(calls, 1);

  now += 10_000; // still within the 30s window
  await validator.validate("sat_ttl", { rest });
  assert.equal(calls, 1, "still cached before ttlMs elapses");

  now += 25_000; // total 35s since the first call -- past the 30s ttl
  await validator.validate("sat_ttl", { rest });
  assert.equal(calls, 2, "re-validated once the cache entry expired");
});

test("an invalid ({valid:false}) result is cached too -- salt-api isn't re-asked on every retry of a bad token", async () => {
  let calls = 0;
  const rest = restThrowing(new SaltBearerApiError("GET", "/api/v1/oauth2/grant", 401, { error: "nope" }));
  const validator = createTokenValidator({ ttlMs: 30_000 });
  await validator.validate("sat_bad", { rest: { async getGrant() { calls += 1; throw new SaltBearerApiError("GET", "x", 401, {}); } } });
  await validator.validate("sat_bad", { rest: { async getGrant() { calls += 1; throw new SaltBearerApiError("GET", "x", 401, {}); } } });
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
  const validator = createTokenValidator({ ttlMs: 30_000 });
  await assert.rejects(() => validator.validate("sat_flaky", { rest }), /temporarily down/);
  const result = await validator.validate("sat_flaky", { rest });
  assert.deepEqual(result, { valid: true, scopes: ["chat"], wallets: [] });
  assert.equal(attempt, 2, "the failed attempt must not have been cached, or this second call would never have reached salt-api");
});

// --- bounded LRU (N2) -------------------------------------------------------

test("the cache never grows past maxEntries -- the least-recently-used entry is evicted", async () => {
  const rest = restReturning(() => ({ scopes: [], wallets: [] }));
  const validator = createTokenValidator({ ttlMs: 30_000, maxEntries: 3 });

  await validator.validate("sat_1", { rest });
  await validator.validate("sat_2", { rest });
  await validator.validate("sat_3", { rest });
  assert.equal(validator.size(), 3);

  await validator.validate("sat_4", { rest }); // pushes the cache over the bound
  assert.equal(validator.size(), 3, "the cache stays bounded at maxEntries");
});

test("a cache HIT counts as recent use -- the entry touched most recently survives eviction, not just the one written most recently", async () => {
  let calls = 0;
  const rest = restReturning((token) => { calls += 1; return { scopes: [token], wallets: [] }; });
  const validator = createTokenValidator({ ttlMs: 30_000, maxEntries: 2 });

  await validator.validate("sat_old", { rest }); // written 1st -- would be LRU-evicted next if untouched
  await validator.validate("sat_new", { rest }); // written 2nd
  await validator.validate("sat_old", { rest }); // HIT -- touches sat_old, making sat_new the least-recently-used
  assert.equal(calls, 2, "the repeat sat_old call was a cache hit, not a third salt-api call");

  await validator.validate("sat_third", { rest }); // forces one eviction
  assert.equal(calls, 3);

  // sat_new should have been evicted (least-recently-used); sat_old and
  // sat_third should still be cached (no further salt-api calls for them).
  await validator.validate("sat_old", { rest });
  await validator.validate("sat_third", { rest });
  assert.equal(calls, 3, "sat_old and sat_third were both still cached");

  await validator.validate("sat_new", { rest });
  assert.equal(calls, 4, "sat_new had to be re-validated -- it was the one evicted");
});
