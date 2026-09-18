// End-to-end tests for src/http.mjs's Express app: real HTTP over an
// ephemeral loopback port, real MCP JSON-RPC framing (via the official
// @modelcontextprotocol/sdk Client + StreamableHTTPClientTransport), and a
// REAL bearer-token pass-through -- only the outbound leg to salt-api is
// mocked (via `fetchImpl` injection into createApp, exactly as the task
// asked for), never Express or the MCP protocol layer itself.
//
// Every bearer-authenticated request now validates the token against
// GET /api/v1/oauth2/grant BEFORE doing anything else (src/token-validator.mjs,
// added by a 2026-09-18 security review), so every test below that
// presents a bearer mocks that route too.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createApp } from "../src/http.mjs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

async function listen(app) {
  const server = app.listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  const { port } = server.address();
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

function fakeSaltApi(routes, calls) {
  return async (url, init = {}) => {
    const { pathname, search } = new URL(url);
    const method = (init.method || "GET").toUpperCase();
    if (calls) calls.push({ method, pathname, search, authHeader: init.headers?.Authorization ?? init.headers?.authorization });
    const key = `${method} ${pathname}`;
    const handler = routes[key] ?? routes[`${method} ${pathname}${search}`];
    if (!handler) {
      return new Response(JSON.stringify({ error: `no mock route for ${key}${search}` }), { status: 404 });
    }
    const authHeader = init.headers?.Authorization ?? init.headers?.authorization;
    return handler({ pathname, search, authHeader, body: init.body ? JSON.parse(init.body) : undefined });
  };
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

/** A default GET /api/v1/oauth2/grant mock -- most tests just need any valid grant. */
function grantRoute(body = { scopes: ["chat", "money"], wallets: [] }) {
  return { "GET /api/v1/oauth2/grant": async () => json(body) };
}

// --- RFC 9728 discovery, unauthenticated -----------------------------------

test("GET /.well-known/oauth-protected-resource and its path-suffixed variant both serve the PRM document", async () => {
  const app = createApp({ host: "https://fake-salt.test", fetchImpl: fakeSaltApi({}), oauthConfig: { resource: "http://placeholder/mcp", issuer: "http://placeholder-as", scopesSupported: ["chat", "money"] } });
  const { server, baseUrl } = await listen(app);
  try {
    for (const path of ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]) {
      const res = await fetch(`${baseUrl}${path}`);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.resource, "http://placeholder/mcp");
      assert.deepEqual(body.authorization_servers, ["http://placeholder-as"]);
      assert.deepEqual(body.scopes_supported, ["chat", "money"]);
      assert.deepEqual(body.bearer_methods_supported, ["header"]);
    }
  } finally {
    server.close();
  }
});

// --- 401 with no valid bearer, and legacy headers still working ------------

test("POST /mcp with no credentials at all returns 401 with the exact RFC 9728 WWW-Authenticate header", async () => {
  const app = createApp({ host: "https://fake-salt.test", fetchImpl: fakeSaltApi({}) });
  const { server, baseUrl } = await listen(app);
  try {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    assert.equal(res.status, 401);
    assert.equal(
      res.headers.get("www-authenticate"),
      'Bearer resource_metadata="https://mcp.saltapp.ai/.well-known/oauth-protected-resource/mcp"'
    );
  } finally {
    server.close();
  }
});

test("POST /mcp with a malformed Authorization header (not 'Bearer <token>') also gets the 401 + WWW-Authenticate", async () => {
  const app = createApp({ host: "https://fake-salt.test", fetchImpl: fakeSaltApi({}) });
  const { server, baseUrl } = await listen(app);
  try {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Basic bm9wZQ==" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    assert.equal(res.status, 401);
    assert.ok(res.headers.get("www-authenticate")?.startsWith("Bearer resource_metadata="));
  } finally {
    server.close();
  }
});

test("the legacy X-Salt-Api-Key / X-Salt-App-Id header path keeps working unchanged, with no bearer at all", async () => {
  const fetchImpl = fakeSaltApi({
    "GET /api/v1/agents": async ({ authHeader }) => {
      assert.equal(authHeader, undefined, "legacy path must never send an Authorization header");
      return json([{ id: "a1", username: "faucet", display_name: "Faucet", account_type: "Agent" }]);
    },
  });
  const app = createApp({ host: "https://fake-salt.test", fetchImpl });
  const { server, baseUrl } = await listen(app);
  try {
    const client = new Client({ name: "test-legacy-client", version: "0.0.0" });
    const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
      requestInit: { headers: { "X-Salt-Api-Key": "legacy-key", "X-Salt-App-Id": "legacy-app-1" } },
    });
    await client.connect(transport);
    const { tools } = await client.listTools();
    assert.deepEqual(
      tools.map((t) => t.name).sort(),
      ["create_product", "list_products", "list_salt_agents"]
    );
    const result = await client.callTool({ name: "list_salt_agents", arguments: {} });
    assert.equal(result.isError, undefined);
    await client.close();
  } finally {
    server.close();
  }
});

// --- bearer token validation itself: prefix + salt-api check --------------

test("a bearer that doesn't start with sat_ (e.g. a JWT) is refused with 401 invalid_token, and salt-api is NEVER called", async () => {
  const calls = [];
  const app = createApp({ host: "https://fake-salt.test", fetchImpl: fakeSaltApi({}, calls) });
  const { server, baseUrl } = await listen(app);
  try {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.x.y" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    assert.equal(res.status, 401);
    assert.equal(
      res.headers.get("www-authenticate"),
      'Bearer error="invalid_token", resource_metadata="https://mcp.saltapp.ai/.well-known/oauth-protected-resource/mcp"'
    );
    assert.deepEqual(calls, [], "a JWT-shaped (non sat_) bearer must never reach salt-api, not even once");
  } finally {
    server.close();
  }
});

test("a garbage bearer with the right prefix but rejected by salt-api's grant check is refused with 401 invalid_token", async () => {
  const app = createApp({
    host: "https://fake-salt.test",
    fetchImpl: fakeSaltApi({ "GET /api/v1/oauth2/grant": async () => json({ error: "invalid or expired token" }, 401) }),
  });
  const { server, baseUrl } = await listen(app);
  try {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer sat_not_a_real_token" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    assert.equal(res.status, 401);
    assert.match(res.headers.get("www-authenticate") || "", /error="invalid_token"/);
  } finally {
    server.close();
  }
});

test("tools/list itself is refused for a garbage bearer -- validation happens before ANY MCP method is served, not just tools/call", async () => {
  // The exact probe finding this regression-tests: an earlier build
  // returned tools/list's real catalog for literally any bearer shaped
  // like "Bearer <something>", never once asking salt-api whether it was
  // real. `initialize` (the SDK Client's own handshake) hits this same
  // gate, so a raw fetch is used here to make sure a bare tools/list
  // request -- with no prior handshake -- is refused too.
  const app = createApp({
    host: "https://fake-salt.test",
    fetchImpl: fakeSaltApi({ "GET /api/v1/oauth2/grant": async () => json({ error: "nope" }, 401) }),
  });
  const { server, baseUrl } = await listen(app);
  try {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", Authorization: "Bearer sat_garbage" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
    });
    assert.equal(res.status, 401);
  } finally {
    server.close();
  }
});

test("salt-api being unreachable during token validation is a 502, never a 401 (and is not cached as invalid)", async () => {
  const app = createApp({
    host: "https://fake-salt.test",
    fetchImpl: async () => {
      throw new Error("ECONNREFUSED (simulated)");
    },
  });
  const { server, baseUrl } = await listen(app);
  try {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer sat_whatever" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    assert.equal(res.status, 502);
  } finally {
    server.close();
  }
});

// --- OAuth bearer path: the keyless toolset, real pass-through -------------

test("POST /mcp with a valid bearer token lists the keyless toolset and forwards the bearer to salt-api on a tool call, never storing it", async () => {
  let sawAuthHeader;
  const fetchImpl = fakeSaltApi({
    ...grantRoute(),
    "GET /api/v1/agents": async ({ authHeader }) => {
      sawAuthHeader = authHeader;
      return json([{ id: "a1", username: "faucet", display_name: "Faucet", category: "utility" }]);
    },
  });
  const app = createApp({ host: "https://fake-salt.test", fetchImpl });
  const { server, baseUrl } = await listen(app);
  try {
    const client = new Client({ name: "test-oauth-client", version: "0.0.0" });
    const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
      requestInit: { headers: { Authorization: "Bearer sat_abc123" } },
    });
    await client.connect(transport);

    const { tools } = await client.listTools();
    assert.equal(tools.length, 14, "the full keyless catalog");
    const postCardTool = tools.find((t) => t.name === "post_card");
    assert.equal(postCardTool._meta.ui.resourceUri, "ui://salt/card");

    const result = await client.callTool({ name: "list_salt_agents", arguments: {} });
    assert.equal(result.isError, undefined);
    assert.deepEqual(result.structuredContent, { agents: [{ id: "a1", username: "faucet", display_name: "Faucet", category: "utility" }] });
    assert.equal(sawAuthHeader, "Bearer sat_abc123", "the exact bearer token was forwarded, unmodified");

    await client.close();
  } finally {
    server.close();
  }
});

test("a tool call with arguments that don't match its inputSchema is refused before execute() ever runs", async () => {
  const calls = [];
  const fetchImpl = fakeSaltApi(grantRoute(), calls);
  const app = createApp({ host: "https://fake-salt.test", fetchImpl });
  const { server, baseUrl } = await listen(app);
  try {
    const client = new Client({ name: "test-schema-client", version: "0.0.0" });
    const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
      requestInit: { headers: { Authorization: "Bearer sat_schema" } },
    });
    await client.connect(transport);
    calls.length = 0; // drop the grant-validation call from the connect handshake

    // send_message requires chat_id and text; omit text entirely.
    const result = await client.callTool({ name: "send_message", arguments: { chat_id: "11111111-1111-1111-1111-111111111111" } });
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /Invalid arguments for "send_message"/);
    assert.deepEqual(calls, [], "an invalid call must never reach salt-api at all");

    await client.close();
  } finally {
    server.close();
  }
});

test("a money-scoped tool call that salt-api 403s comes back as a plain-sentence tool error, not a transport failure", async () => {
  const fetchImpl = fakeSaltApi({
    ...grantRoute({ scopes: ["chat"], wallets: [] }),
    "GET /api/v1/transfer_requests": async () => json({ error: "insufficient scope" }, 403),
  });
  const app = createApp({ host: "https://fake-salt.test", fetchImpl });
  const { server, baseUrl } = await listen(app);
  try {
    const client = new Client({ name: "test-oauth-client-2", version: "0.0.0" });
    const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
      requestInit: { headers: { Authorization: "Bearer sat_no_money_scope" } },
    });
    await client.connect(transport);
    const result = await client.callTool({ name: "get_payment_status", arguments: { request_id: "55555555-5555-5555-5555-555555555555" } });
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /This connection wasn't given permission to request money\./);
    await client.close();
  } finally {
    server.close();
  }
});

test("a path-traversal-shaped card_id is refused before any outbound salt-api call for that tool, over the real wire", async () => {
  const calls = [];
  const fetchImpl = fakeSaltApi(grantRoute(), calls);
  const app = createApp({ host: "https://fake-salt.test", fetchImpl });
  const { server, baseUrl } = await listen(app);
  try {
    const client = new Client({ name: "test-traversal-client", version: "0.0.0" });
    const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
      requestInit: { headers: { Authorization: "Bearer sat_traversal" } },
    });
    await client.connect(transport);
    calls.length = 0; // drop the grant-validation call from the connect handshake

    const result = await client.callTool({
      name: "update_card",
      arguments: { card_id: "../agents/callback?webhook=https://attacker.example/hook", blocks: [{ type: "divider" }] },
    });
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /card_id must be a plain Salt id/);
    assert.deepEqual(calls, [], "no outbound call at all -- not to /api/v1/cards/*, and definitely not to /api/v1/agents/callback");

    await client.close();
  } finally {
    server.close();
  }
});

// --- MCP Apps resource ------------------------------------------------------

test("resources/list and resources/read serve the ui://salt/card MCP Apps resource on the OAuth path", async () => {
  const app = createApp({ host: "https://fake-salt.test", fetchImpl: fakeSaltApi(grantRoute()) });
  const { server, baseUrl } = await listen(app);
  try {
    const client = new Client({ name: "test-resources-client", version: "0.0.0" });
    const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
      requestInit: { headers: { Authorization: "Bearer sat_xyz" } },
    });
    await client.connect(transport);

    const { resources } = await client.listResources();
    assert.deepEqual(resources, [{ uri: "ui://salt/card", name: "Salt Card", mimeType: "text/html;profile=mcp-app" }]);

    const { contents } = await client.readResource({ uri: "ui://salt/card" });
    assert.equal(contents.length, 1);
    assert.equal(contents[0].mimeType, "text/html;profile=mcp-app");
    assert.match(contents[0].text, /<!doctype html>/i);

    await client.close();
  } finally {
    server.close();
  }
});

test("GET /health reports ok without any credentials", async () => {
  const app = createApp({ host: "https://fake-salt.test", fetchImpl: fakeSaltApi({}) });
  const { server, baseUrl } = await listen(app);
  try {
    const res = await fetch(`${baseUrl}/health`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, "ok");
  } finally {
    server.close();
  }
});
