// Unit tests for src/caller-ip.mjs -- deriving the real end-user IP the
// way the ALB presents it (X-Forwarded-For's FIRST entry), with a
// fallback for when there's no ALB in front at all (2026-09-19
// availability review, N2).

import { test } from "node:test";
import assert from "node:assert/strict";
import { callerIpFromRequest } from "../src/caller-ip.mjs";

function fakeReq({ xff, ip, remoteAddress } = {}) {
  return {
    get(name) {
      if (name === "X-Forwarded-For" && xff !== undefined) return xff;
      return undefined;
    },
    ip,
    socket: { remoteAddress },
  };
}

test("a single-entry X-Forwarded-For is the caller IP", () => {
  assert.equal(callerIpFromRequest(fakeReq({ xff: "203.0.113.7" })), "203.0.113.7");
});

test("the FIRST entry of a multi-hop X-Forwarded-For is the caller -- the ALB's own appended hop is ignored", () => {
  // CloudFront forwards the true viewer as the first entry; the ALB then
  // APPENDS its own view of who connected to it (CloudFront's address).
  assert.equal(callerIpFromRequest(fakeReq({ xff: "203.0.113.7, 15.197.140.10" })), "203.0.113.7");
});

test("whitespace around entries is trimmed", () => {
  assert.equal(callerIpFromRequest(fakeReq({ xff: "  203.0.113.7  , 15.197.140.10" })), "203.0.113.7");
});

test("falls back to req.ip when there's no X-Forwarded-For at all (no ALB in front)", () => {
  assert.equal(callerIpFromRequest(fakeReq({ ip: "127.0.0.1" })), "127.0.0.1");
});

test("falls back to the raw socket address when neither X-Forwarded-For nor req.ip is set", () => {
  assert.equal(callerIpFromRequest(fakeReq({ remoteAddress: "::1" })), "::1");
});

test("returns null when nothing at all is available", () => {
  assert.equal(callerIpFromRequest(fakeReq({})), null);
});

test("an empty X-Forwarded-For header falls through to the other fallbacks", () => {
  assert.equal(callerIpFromRequest(fakeReq({ xff: "", ip: "10.0.0.5" })), "10.0.0.5");
});
