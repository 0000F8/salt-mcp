// Unit tests for src/edge-headers.mjs -- relaying this task's edge secret
// and the real caller's IP on every outbound salt-api call (2026-09-19
// availability review, N2). "When EDGE_SECRET is unset (local dev), send
// neither" is the one hard rule; everything else follows from it.

import { test } from "node:test";
import assert from "node:assert/strict";
import { buildEdgeHeaders, withEdgeHeaders } from "../src/edge-headers.mjs";

function fakeReq(xff) {
  return { get: (name) => (name === "X-Forwarded-For" ? xff : undefined), ip: undefined, socket: {} };
}

test("EDGE_SECRET unset: sends neither the secret nor the IP headers", () => {
  assert.deepEqual(buildEdgeHeaders(fakeReq("203.0.113.7"), {}), {});
});

test("EDGE_SECRET set, a caller IP known: all three headers, exact shapes", () => {
  const headers = buildEdgeHeaders(fakeReq("203.0.113.7, 15.197.140.10"), { EDGE_SECRET: "top-secret" });
  assert.deepEqual(headers, {
    "X-Salt-Edge": "top-secret",
    "CloudFront-Viewer-Address": "203.0.113.7:0",
    "X-Forwarded-For": "203.0.113.7",
  });
});

test("EDGE_SECRET set but no IP could be determined: sends the secret alone, no IP headers", () => {
  const req = { get: () => undefined, ip: undefined, socket: {} };
  const headers = buildEdgeHeaders(req, { EDGE_SECRET: "top-secret" });
  assert.deepEqual(headers, { "X-Salt-Edge": "top-secret" });
});

test("an empty-string EDGE_SECRET counts as unset", () => {
  assert.deepEqual(buildEdgeHeaders(fakeReq("203.0.113.7"), { EDGE_SECRET: "" }), {});
});

test("withEdgeHeaders is a true no-op (returns the same function) when there's nothing to add", () => {
  const base = async () => new Response("{}");
  assert.equal(withEdgeHeaders(base, {}), base);
  assert.equal(withEdgeHeaders(base, undefined), base);
});

test("withEdgeHeaders merges the extra headers into every call", async () => {
  const calls = [];
  const base = async (url, init) => {
    calls.push({ url, headers: init.headers });
    return new Response("{}");
  };
  const wrapped = withEdgeHeaders(base, { "X-Salt-Edge": "s3cr3t", "X-Forwarded-For": "203.0.113.7" });
  await wrapped("https://api.example.test/x", { method: "GET", headers: { Authorization: "Bearer sat_x" } });
  assert.deepEqual(calls[0].headers, {
    "X-Salt-Edge": "s3cr3t",
    "X-Forwarded-For": "203.0.113.7",
    Authorization: "Bearer sat_x",
  });
});

test("withEdgeHeaders lets the caller's own headers win on a name collision (defensive; none should ever collide in practice)", async () => {
  const calls = [];
  const base = async (url, init) => {
    calls.push(init.headers);
    return new Response("{}");
  };
  const wrapped = withEdgeHeaders(base, { "X-Salt-Edge": "from-wrapper" });
  await wrapped("https://api.example.test/x", { headers: { "X-Salt-Edge": "from-caller" } });
  assert.equal(calls[0]["X-Salt-Edge"], "from-caller");
});
