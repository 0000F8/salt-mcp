// Unit tests for src/rate-limiter.mjs -- a per-IP fixed-window limiter
// sitting in front of /mcp, including token validation itself
// (2026-09-19 availability review, N2).

import { test } from "node:test";
import assert from "node:assert/strict";
import { createRateLimiter } from "../src/rate-limiter.mjs";

test("allows up to `limit` requests per IP within the window", () => {
  const limiter = createRateLimiter({ limit: 3, windowMs: 60_000 });
  for (let i = 0; i < 3; i++) {
    assert.deepEqual(limiter.check("203.0.113.7"), { allowed: true });
  }
});

test("the (limit + 1)th request in the window is refused with a retryAfterSeconds", () => {
  const limiter = createRateLimiter({ limit: 3, windowMs: 60_000 });
  for (let i = 0; i < 3; i++) limiter.check("203.0.113.7");
  const result = limiter.check("203.0.113.7");
  assert.equal(result.allowed, false);
  assert.ok(result.retryAfterSeconds >= 1);
  assert.ok(result.retryAfterSeconds <= 60);
});

test("the default is 60 requests per 60s window", () => {
  const limiter = createRateLimiter({});
  for (let i = 0; i < 60; i++) {
    assert.deepEqual(limiter.check("203.0.113.7"), { allowed: true }, `request ${i + 1}`);
  }
  assert.equal(limiter.check("203.0.113.7").allowed, false, "the 61st request in the window is refused");
});

test("different IPs are counted independently", () => {
  const limiter = createRateLimiter({ limit: 1, windowMs: 60_000 });
  assert.equal(limiter.check("203.0.113.7").allowed, true);
  assert.equal(limiter.check("203.0.113.7").allowed, false, "second request from the same IP");
  assert.equal(limiter.check("198.51.100.9").allowed, true, "a different IP has its own budget");
});

test("the window resets after windowMs, using an injectable clock", () => {
  let now = 0;
  const limiter = createRateLimiter({ limit: 1, windowMs: 10_000, now: () => now });
  assert.equal(limiter.check("203.0.113.7").allowed, true);
  assert.equal(limiter.check("203.0.113.7").allowed, false, "still within the window");

  now += 9_999;
  assert.equal(limiter.check("203.0.113.7").allowed, false, "one ms before the window resets");

  now += 2; // total 10_001ms elapsed -- past the 10s window
  assert.equal(limiter.check("203.0.113.7").allowed, true, "a fresh window opens");
});

test("retryAfterSeconds counts down to exactly when the window resets", () => {
  let now = 0;
  const limiter = createRateLimiter({ limit: 1, windowMs: 10_000, now: () => now });
  limiter.check("203.0.113.7"); // starts the window at t=0, resetAt=10_000
  now = 4_000;
  const result = limiter.check("203.0.113.7");
  assert.equal(result.allowed, false);
  assert.equal(result.retryAfterSeconds, 6, "6s remain until resetAt=10_000 from t=4_000");
});
