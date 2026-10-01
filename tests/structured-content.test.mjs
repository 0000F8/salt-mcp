// Every tool that declares an `outputSchema` must answer with
// `structuredContent` that validates against it -- the official SDK client's
// callTool() throws -32600 otherwise (a stranger hit it on open_chat,
// ask_human and get_ask_result in local mode). These tests drive each mode's
// REAL server through the official SDK Client: local over an in-memory
// transport, hosted (keyless/OAuth) over HTTP. callTool does the validation.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import pkg from "salt-agent-sdk";
import { buildLocalServer, createLocalHandlers } from "../src/index.mjs";
import { createApp } from "../src/http.mjs";
import { toolResult } from "../src/tool-result.mjs";

const { createSaltClient, createIdentityStore, createActions, generateKeypair } = pkg;
const KEYS = await generateKeypair("pw");

const HOST = "https://salt.test";
const CHAT = "11111111-1111-1111-1111-111111111111";
const CARD = "22222222-2222-2222-2222-222222222222";
const WALLET = "88888888-8888-8888-8888-888888888888";
const HUMAN = { id: "77777777-7777-7777-7777-777777777777", username: "ada", display_name: "Ada", account_type: "User", public_key: KEYS.publicKey };
const BOT = { id: "99999999-9999-9999-9999-999999999999", username: "bot", display_name: "Bot", account_type: "Agent", public_key: KEYS.publicKey };

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

/** A fake salt-api shaped like the real controllers, ignoring which auth header arrives. */
function fakeSaltFetch() {
  const routes = {
    "GET /api/v1/oauth2/grant": () => json({ scopes: ["chat", "money"], wallets: [{ id: WALLET, chain: "ethereum", testnet: false, label: "Main" }] }),
    "GET /api/v1/auth/me": () => json({ id: BOT.id }),
    "GET /api/v1/search/contacts": () => json([HUMAN]),
    "GET /api/v1/agents": () => json([BOT]),
    "POST /api/v1/chats": () => json({ id: CHAT, name: null, users: [HUMAN, BOT] }),
    "GET /api/v1/chats": () => json([{ session: { id: CHAT, name: null, users: [HUMAN, BOT], unread_count: 0 } }]),
    [`GET /api/v1/chats/${CHAT}`]: () => json({ session: { id: CHAT, name: "Room", public: true, encrypted: false, users: [HUMAN, BOT] }, messages: [{ id: 5, seq: 5, encrypted: false, message: "hi", created_at: "2026-09-30T00:00:00Z", user: HUMAN }] }),
    [`PUT /api/v1/chats/${CHAT}/subscription`]: () => json({ chat_id: CHAT, mode: "all", keywords: [] }),
    [`DELETE /api/v1/chats/${CHAT}/subscription`]: () => json({}),
    "GET /api/v1/config": () => json({ commons_chat_id: CHAT }),
    [`POST /api/v1/chats/${CHAT}/join_public`]: () => json({ id: CHAT, name: "The Commons", commons_note: "Hello" }),
    "POST /api/v1/cards": () => json({ id: 12, resource_id: CARD }),
    [`PATCH /api/v1/cards/${CARD}`]: () => json({}),
    [`GET /api/v1/cards/${CARD}`]: () => json({ interactions: [{ id: 3, action_id: "opt_0" }] }),
    "POST /api/v1/messages": () => json({ id: 31 }),
    "POST /api/v1/transfer_requests": () => json({ id: 41, status: "Pending", amount: 12.5 }),
    "GET /api/v1/transfer_requests": () => json([{ id: 41, status: "Pending", amount: "12.5" }]),
    "GET /api/v1/products": () => json([{ id: "p1" }]),
    "POST /api/v1/products": () => json({ id: "p1" }),
  };
  return async (url, init = {}) => {
    const u = new URL(url);
    const handler = routes[`${(init.method || "GET").toUpperCase()} ${u.pathname}`];
    return handler ? handler() : json({ error: `no route ${init.method} ${u.pathname}` }, 404);
  };
}

/** Calls `name` through the Client; callTool throws if structuredContent is missing or invalid. */
async function callAll(client, argsByTool) {
  const { tools } = await client.listTools();
  const withSchema = tools.filter((t) => t.outputSchema);
  const called = new Set();
  for (const tool of withSchema) {
    assert.ok(argsByTool[tool.name], `no test arguments for ${tool.name}: add them so its structuredContent is checked`);
    const result = await client.callTool({ name: tool.name, arguments: argsByTool[tool.name] });
    assert.notEqual(result.isError, true, `${tool.name}: ${JSON.stringify(result.content)}`);
    assert.ok(result.structuredContent && typeof result.structuredContent === "object", `${tool.name} returned no structuredContent`);
    assert.equal(JSON.parse(result.content[0].text).constructor, Object, `${tool.name} keeps its text copy`);
    called.add(tool.name);
  }
  assert.equal(called.size, withSchema.length);
  return withSchema.length;
}

const ARGS = {
  find_people_and_agents: { query: "ada" },
  open_chat: { handle: "@ada" },
  list_chats: {},
  send_message: { chat_id: CHAT, text: "hello" },
  salt_read_room: { chat_id: CHAT },
  salt_set_room_interests: { chat_id: CHAT, mode: "all" },
  salt_clear_room_interests: { chat_id: CHAT },
  salt_join_commons: {},
  post_card: { chat_id: CHAT, blocks: [{ type: "section", text: "x" }] },
  update_card: { card_id: CARD, blocks: [{ type: "section", text: "x" }] },
  ask_human: { chat_id: CHAT, to: "ada", question: "Ok?", options: ["Yes", "No"] },
  request_payment: { chat_id: CHAT, to: "ada", amount: "12.50", chain: "ethereum" },
  send_invoice: { chat_id: CHAT, to: "ada", chain: "ethereum", line_items: [{ name: "Work", qty: 1, unit_price: "5" }] },
  get_payment_status: { request_id: "41" },
  list_products: {},
  create_product: { title: "T", kind: "one_time", price: "1", chain: "ethereum" },
  list_salt_agents: {},
};

test("local mode: every tool with an outputSchema succeeds through the official SDK client with valid structuredContent", async () => {
  const caller = { saltAppId: BOT.id, username: "bot", displayName: "Bot", apiKey: "k", publicKey: "pub", privateKey: "priv" };
  const identities = createIdentityStore();
  identities.register(caller);
  const fetchImpl = fakeSaltFetch();
  const actions = createActions({ client: createSaltClient({ host: HOST, fetchImpl }), identities, pgpPassphrase: "pw", publicWebhookUrl: "https://example.invalid/", walletMasterKey: "unused" });
  const server = buildLocalServer(createLocalHandlers({ actions, caller, host: HOST, fetchImpl }));
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "t", version: "0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  try {
    const local = { ...ARGS };
    const { tools } = await client.listTools();
    const names = new Set(tools.filter((t) => t.outputSchema).map((t) => t.name));
    for (const n of ["open_chat", "ask_human", "get_ask_result", "salt_read_room", "salt_set_room_interests", "salt_clear_room_interests", "salt_join_commons"]) assert.ok(names.has(n), n);
    // get_ask_result needs an ask_id from a real ask_human.
    const ask = await client.callTool({ name: "ask_human", arguments: local.ask_human });
    local.get_ask_result = { ask_id: ask.structuredContent.ask_id };
    assert.equal(await callAll(client, local), names.size);
  } finally {
    await client.close();
  }
});

test("hosted keyless mode: every tool with an outputSchema succeeds through the official SDK client with valid structuredContent", async () => {
  const app = createApp({ host: HOST, fetchImpl: fakeSaltFetch() });
  const srv = app.listen(0);
  await new Promise((r) => srv.once("listening", r));
  const client = new Client({ name: "t", version: "0" });
  try {
    await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${srv.address().port}/mcp`), { requestInit: { headers: { Authorization: "Bearer sat_abc" } } }));
    const args = { ...ARGS };
    const ask = await client.callTool({ name: "ask_human", arguments: args.ask_human });
    args.get_ask_result = { ask_id: ask.structuredContent.ask_id };
    assert.ok((await callAll(client, args)) >= 18);
  } finally {
    await client.close().catch(() => {});
    srv.close();
  }
});

test("hosted legacy (api-key header) catalog declares no outputSchema, so plain text results are valid", async () => {
  const app = createApp({ host: HOST, fetchImpl: fakeSaltFetch() });
  const srv = app.listen(0);
  await new Promise((r) => srv.once("listening", r));
  const client = new Client({ name: "t", version: "0" });
  try {
    await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${srv.address().port}/mcp`), { requestInit: { headers: { "X-Salt-Api-Key": "k", "X-Salt-App-Id": "1" } } }));
    const { tools } = await client.listTools();
    assert.ok(tools.length > 0);
    assert.deepEqual(tools.filter((t) => t.outputSchema).map((t) => t.name), []);
    const r = await client.callTool({ name: "list_salt_agents", arguments: {} });
    assert.ok(r.structuredContent || r.content[0].text);
  } finally {
    await client.close().catch(() => {});
    srv.close();
  }
});

test("toolResult: objects carry structuredContent beside text, strings and arrays stay text-only", () => {
  assert.deepEqual(toolResult({ a: 1 }).structuredContent, { a: 1 });
  assert.equal(toolResult("hi").structuredContent, undefined);
  assert.equal(toolResult([1]).structuredContent, undefined);
  assert.equal(toolResult("hi").content[0].text, "hi");
});
