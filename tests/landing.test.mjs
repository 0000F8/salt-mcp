// The bare host and unknown paths: JSON for a caller, a page for a browser,
// never Express's default "Cannot GET /".

import { test } from "node:test";
import assert from "node:assert/strict";
import { createApp } from "../src/http.mjs";

async function listen(app) {
  const server = app.listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  return { server, baseUrl: `http://127.0.0.1:${server.address().port}` };
}

async function withApp(fn) {
  const { server, baseUrl } = await listen(createApp({ host: "https://saltapp.ai" }));
  try { await fn(baseUrl); } finally { server.close(); }
}

test("GET / describes the MCP endpoint as JSON for a caller", async () => {
  await withApp(async (base) => {
    const res = await fetch(`${base}/`, { headers: { Accept: "application/json" } });
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type"), /application\/json/);
    const body = await res.json();
    assert.equal(body.mcp_url, "https://mcp.saltapp.ai/mcp");
    assert.equal(body.transport, "streamable-http");
    assert.equal(body.auth.type, "oauth2");
    assert.match(body.auth.protected_resource_metadata, /oauth-protected-resource/);
  });
});

test("GET / with no Accept (curl) is JSON; a browser gets the page", async () => {
  await withApp(async (base) => {
    assert.match((await fetch(`${base}/`, { headers: { Accept: "*/*" } })).headers.get("content-type"), /json/);
    const page = await fetch(`${base}/`, { headers: { Accept: "text/html,application/xhtml+xml,*/*;q=0.8" } });
    assert.match(page.headers.get("content-type"), /text\/html/);
    const html = await page.text();
    assert.ok(html.includes("https://mcp.saltapp.ai/mcp"));
    assert.ok(!html.includes("Cannot GET"));
  });
});

test("an unknown path is a JSON 404 for a caller and a page for a browser", async () => {
  await withApp(async (base) => {
    const res = await fetch(`${base}/nope`);
    assert.equal(res.status, 404);
    const body = await res.json();
    assert.equal(body.error, "not_found");
    assert.equal(body.code, "not_found");
    assert.ok(body.docs_url);
    const post = await fetch(`${base}/nope`, { method: "POST" });
    assert.equal(post.status, 404);
    const page = await fetch(`${base}/<b>x`, { headers: { Accept: "text/html" } });
    assert.equal(page.status, 404);
    assert.match(page.headers.get("content-type"), /text\/html/);
    assert.ok(!(await page.text()).includes("<b>x"), "the path is escaped");
  });
});

test("the real routes still answer", async () => {
  await withApp(async (base) => {
    assert.equal((await fetch(`${base}/health`)).status, 200);
    assert.equal((await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)).status, 200);
    assert.equal((await fetch(`${base}/mcp`)).status, 401);
  });
});
