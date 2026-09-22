// Unit tests for src/caller-ip.mjs -- deriving the real end-user IP the way
// the ALB presents it.
//
// These tests were rewritten on 2026-09-22 (K5 security review). The
// original set asserted that the FIRST entry of X-Forwarded-For is the
// caller, on the premise that this service sits behind CloudFront -> ALB.
// It does not: mcp.saltapp.ai is a plain ALB host rule. X-Forwarded-For is
// client-supplied and an ALB only APPENDS, so the first entry is whatever
// the caller wrote and the LAST is the address AWS actually observed.
// Every test below that reads from the right is the fix for a forgeable
// value that was relayed to salt-api as CloudFront-Viewer-Address and used
// as the rate limiter's bucket key.

import { test } from "node:test";
import assert from "node:assert/strict";
import { callerIpFromRequest, trustedProxyHops } from "../src/caller-ip.mjs";

function fakeReq({ xff, remoteAddress } = {}) {
  return {
    get(name) {
      if (name === "X-Forwarded-For" && xff !== undefined) return xff;
      return undefined;
    },
    socket: { remoteAddress },
  };
}

test("a single-entry X-Forwarded-For is the caller IP", () => {
  assert.equal(callerIpFromRequest(fakeReq({ xff: "203.0.113.7" }), {}), "203.0.113.7");
});

test("the LAST entry is the caller -- a client-supplied prefix is ignored", () => {
  // The caller sent `X-Forwarded-For: 1.2.3.4`; the ALB appended the address
  // it actually saw. Taking the first entry here is precisely the bug.
  assert.equal(
    callerIpFromRequest(fakeReq({ xff: "1.2.3.4, 203.0.113.7" }), {}),
    "203.0.113.7",
  );
});

test("a long forged chain still resolves to the address AWS appended", () => {
  assert.equal(
    callerIpFromRequest(fakeReq({ xff: "9.9.9.9, 8.8.8.8, 7.7.7.7, 203.0.113.7" }), {}),
    "203.0.113.7",
  );
});

test("an attacker cannot pin a victim's address as the apparent source", () => {
  // The whole point: whatever they write, the value we act on is theirs.
  const victim = "198.51.100.42";
  const attacker = "203.0.113.7";
  assert.equal(
    callerIpFromRequest(fakeReq({ xff: `${victim}, ${attacker}` }), {}),
    attacker,
  );
});

test("whitespace and empty entries are trimmed and dropped", () => {
  assert.equal(
    callerIpFromRequest(fakeReq({ xff: "  1.2.3.4  , , 203.0.113.7 " }), {}),
    "203.0.113.7",
  );
});

test("TRUSTED_PROXY_HOPS=1 counts one hop in from the right (CloudFront back in front)", () => {
  // client -> CloudFront -> ALB -> here: CloudFront forwards the viewer,
  // the ALB appends CloudFront's own address, so the viewer is second-last.
  const env = { TRUSTED_PROXY_HOPS: "1" };
  assert.equal(
    callerIpFromRequest(fakeReq({ xff: "203.0.113.7, 15.197.140.10" }), env),
    "203.0.113.7",
  );
});

test("a chain shorter than the trusted topology falls back to the socket, never to the leftmost entry", () => {
  // With one trusted hop configured, a single-entry list means nothing in it
  // came from a proxy we trust. Picking that entry would hand the caller the
  // value outright.
  const env = { TRUSTED_PROXY_HOPS: "1" };
  assert.equal(
    callerIpFromRequest(fakeReq({ xff: "1.2.3.4", remoteAddress: "10.0.0.5" }), env),
    "10.0.0.5",
  );
});

test("falls back to the raw socket address when there is no X-Forwarded-For at all", () => {
  assert.equal(callerIpFromRequest(fakeReq({ remoteAddress: "::1" }), {}), "::1");
});

test("an empty X-Forwarded-For header falls through to the socket", () => {
  assert.equal(
    callerIpFromRequest(fakeReq({ xff: "", remoteAddress: "10.0.0.5" }), {}),
    "10.0.0.5",
  );
});

test("returns null when nothing at all is available", () => {
  assert.equal(callerIpFromRequest(fakeReq({}), {}), null);
});

test("trustedProxyHops defaults to 0 and refuses nonsense", () => {
  assert.equal(trustedProxyHops({}), 0);
  assert.equal(trustedProxyHops({ TRUSTED_PROXY_HOPS: "2" }), 2);
  assert.equal(trustedProxyHops({ TRUSTED_PROXY_HOPS: "-1" }), 0);
  assert.equal(trustedProxyHops({ TRUSTED_PROXY_HOPS: "banana" }), 0);
});
