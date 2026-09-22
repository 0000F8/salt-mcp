// Unit tests for src/room-tools.mjs -- the open-room tools shared by the
// local/stdio server (api-key auth) and the hosted OAuth keyless catalog
// (bearer auth). Most coverage here exercises createRoomTools/runRoomTool
// against an injected `request` mock, the same seam both real bindings
// (src/index.mjs's createApiKeyRequest, src/keyless-tools.mjs's
// rest.rawRequest) go through -- so this file never needs to know which
// surface is calling it. createApiKeyRequest itself gets its own small
// real-`fetch`-shaped test at the bottom.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  createRoomTools,
  runRoomTool,
  toRoomMcpTools,
  createApiKeyRequest,
  ROOM_TOOL_METADATA,
  ROOM_TOOL_NAMES,
} from "../src/room-tools.mjs";

const CHAT_ID = "11111111-1111-1111-1111-111111111111";
const COMMONS_ID = "22222222-2222-2222-2222-222222222222";

/** Records every call and answers from a {method path: value|fn} map, mirroring
 *  the shape of the `request` function room-tools.mjs's factories are handed. */
function fakeRequest(routes) {
  const calls = [];
  return {
    calls,
    request: async (method, path, body) => {
      calls.push({ method, path, body });
      const key = `${method} ${path.split("?")[0]}`;
      const handler = routes[key];
      if (!handler) throw new Error(`no mock route for ${key}`);
      return typeof handler === "function" ? handler({ path, body }) : handler;
    },
  };
}

// --- readRoom -------------------------------------------------------------

test("readRoom: the public (non-member) read shape passes through session fields and message text as-is", async () => {
  const { request, calls } = fakeRequest({
    [`GET /api/v1/chats/${CHAT_ID}`]: {
      session: { id: CHAT_ID, name: "Open Chat", public: true, encrypted: false, commons: false, member: false, member_count: 12 },
      messages: [
        { id: "m1", seq: 1, encrypted: false, message: "hello room", user: { id: "u1", username: "ada", display_name: "Ada", account_type: "User" }, created_at: "2026-09-22T00:00:00Z" },
      ],
    },
  });
  const tools = createRoomTools({ request });
  const result = await tools.readRoom({ chat_id: CHAT_ID });

  assert.deepEqual(calls, [{ method: "GET", path: `/api/v1/chats/${CHAT_ID}`, body: undefined }]);
  assert.equal(result.chat_id, CHAT_ID);
  assert.equal(result.public, true);
  assert.equal(result.encrypted, false);
  assert.equal(result.member, false);
  assert.equal(result.member_count, 12);
  assert.deepEqual(result.messages, [
    { id: "m1", seq: 1, encrypted: false, text: "hello room", sender: { id: "u1", username: "ada", display_name: "Ada", account_type: "User" }, created_at: "2026-09-22T00:00:00Z" },
  ]);
});

test("readRoom: the member read shape (chat.as_json, no `member`/`member_count` keys) defaults member true and counts session.users", async () => {
  const { request } = fakeRequest({
    [`GET /api/v1/chats/${CHAT_ID}`]: {
      session: { id: CHAT_ID, name: "Open Chat", public: true, encrypted: false, commons: false, users: [{ id: "u1" }, { id: "u2" }] },
      messages: [],
    },
  });
  const result = await createRoomTools({ request }).readRoom({ chat_id: CHAT_ID });
  assert.equal(result.member, true);
  assert.equal(result.member_count, 2);
});

test("readRoom: an encrypted message's ciphertext is returned untouched, never decrypted, and marked encrypted: true", async () => {
  const { request } = fakeRequest({
    [`GET /api/v1/chats/${CHAT_ID}`]: {
      session: { id: CHAT_ID, encrypted: true },
      messages: [{ id: "m2", seq: 2, message: "-----BEGIN PGP MESSAGE-----\nabc\n-----END PGP MESSAGE-----" }],
    },
  });
  const result = await createRoomTools({ request }).readRoom({ chat_id: CHAT_ID });
  assert.equal(result.encrypted, true);
  assert.equal(result.messages[0].encrypted, true);
  assert.match(result.messages[0].text, /BEGIN PGP MESSAGE/);
});

test("readRoom: `last` appends ?last=<id> to the path; omitting it sends no query string", async () => {
  const { request, calls } = fakeRequest({ [`GET /api/v1/chats/${CHAT_ID}`]: { session: {}, messages: [] } });
  const tools = createRoomTools({ request });

  await tools.readRoom({ chat_id: CHAT_ID, last: "99" });
  assert.equal(calls[0].path, `/api/v1/chats/${CHAT_ID}?last=99`);

  await tools.readRoom({ chat_id: CHAT_ID });
  assert.equal(calls[1].path, `/api/v1/chats/${CHAT_ID}`);
});

test("readRoom: refuses a missing chat_id and a chat_id that isn't a plain uuid/integer", async () => {
  const { request } = fakeRequest({});
  const tools = createRoomTools({ request });
  await assert.rejects(() => tools.readRoom({}), /chat_id is required/);
  await assert.rejects(() => tools.readRoom({ chat_id: "../agents/callback" }), /must be a plain Salt id/);
});

// --- setRoomInterests / clearRoomInterests --------------------------------

test("setRoomInterests: PUTs {mode} only when keywords is empty/absent, and the array when present", async () => {
  const { request, calls } = fakeRequest({
    [`PUT /api/v1/chats/${CHAT_ID}/subscription`]: ({ body }) => ({ chat_id: CHAT_ID, mode: body.mode, keywords: body.keywords || [] }),
  });
  const tools = createRoomTools({ request });

  const addressed = await tools.setRoomInterests({ chat_id: CHAT_ID, mode: "addressed" });
  assert.deepEqual(calls[0].body, { mode: "addressed" });
  assert.deepEqual(addressed, { chat_id: CHAT_ID, mode: "addressed", keywords: [] });

  await tools.setRoomInterests({ chat_id: CHAT_ID, mode: "keywords", keywords: ["salt", "agent"] });
  assert.deepEqual(calls[1].body, { mode: "keywords", keywords: ["salt", "agent"] });
});

test("setRoomInterests: refuses a mode outside addressed/keywords/all without ever calling request", async () => {
  const { request, calls } = fakeRequest({});
  await assert.rejects(() => createRoomTools({ request }).setRoomInterests({ chat_id: CHAT_ID, mode: "everything" }), /mode must be one of/);
  assert.equal(calls.length, 0);
});

test("setRoomInterests: an encrypted-chat refusal from salt-api passes through unchanged", async () => {
  const { request } = fakeRequest({
    [`PUT /api/v1/chats/${CHAT_ID}/subscription`]: () => {
      throw new Error("Salt cannot read an encrypted room, so it cannot follow it for you.");
    },
  });
  await assert.rejects(
    () => createRoomTools({ request }).setRoomInterests({ chat_id: CHAT_ID, mode: "all" }),
    /Salt cannot read an encrypted room/
  );
});

test("clearRoomInterests: DELETEs the subscription and defaults the reported mode to addressed", async () => {
  const { request, calls } = fakeRequest({ [`DELETE /api/v1/chats/${CHAT_ID}/subscription`]: { chat_id: CHAT_ID, mode: "addressed", keywords: [] } });
  const result = await createRoomTools({ request }).clearRoomInterests({ chat_id: CHAT_ID });
  assert.equal(calls[0].method, "DELETE");
  assert.deepEqual(result, { chat_id: CHAT_ID, mode: "addressed", keywords: [] });
});

// --- joinCommons ------------------------------------------------------------

test("joinCommons: reads commons_chat_id from config, joins it, and returns id/name/commons_note", async () => {
  const { request, calls } = fakeRequest({
    "GET /api/v1/config": { commons_chat_id: COMMONS_ID },
    [`POST /api/v1/chats/${COMMONS_ID}/join_public`]: { id: COMMONS_ID, name: "The Commons", commons_note: "Anyone can join. Say who you are." },
  });
  const result = await createRoomTools({ request }).joinCommons();
  assert.deepEqual(calls.map((c) => `${c.method} ${c.path}`), ["GET /api/v1/config", `POST /api/v1/chats/${COMMONS_ID}/join_public`]);
  assert.deepEqual(result, { chat_id: COMMONS_ID, name: "The Commons", note: "Anyone can join. Say who you are." });
});

test("joinCommons: refuses plainly, without calling join_public, when the deployment has no Commons yet", async () => {
  const { request, calls } = fakeRequest({ "GET /api/v1/config": { commons_chat_id: null } });
  await assert.rejects(() => createRoomTools({ request }).joinCommons(), /hasn't configured a Commons room/);
  assert.equal(calls.length, 1);
});

// --- runRoomTool / metadata / ROOM_TOOL_NAMES ------------------------------

test("runRoomTool dispatches each of the four names to the matching handler, and refuses anything else", async () => {
  const { request } = fakeRequest({
    [`GET /api/v1/chats/${CHAT_ID}`]: { session: { id: CHAT_ID }, messages: [] },
    [`PUT /api/v1/chats/${CHAT_ID}/subscription`]: { chat_id: CHAT_ID, mode: "all", keywords: [] },
    [`DELETE /api/v1/chats/${CHAT_ID}/subscription`]: { chat_id: CHAT_ID, mode: "addressed", keywords: [] },
    "GET /api/v1/config": { commons_chat_id: COMMONS_ID },
    [`POST /api/v1/chats/${COMMONS_ID}/join_public`]: { id: COMMONS_ID, name: "The Commons" },
  });

  assert.equal((await runRoomTool("salt_read_room", { chat_id: CHAT_ID }, { request })).chat_id, CHAT_ID);
  assert.equal((await runRoomTool("salt_set_room_interests", { chat_id: CHAT_ID, mode: "all" }, { request })).mode, "all");
  assert.equal((await runRoomTool("salt_clear_room_interests", { chat_id: CHAT_ID }, { request })).mode, "addressed");
  assert.equal((await runRoomTool("salt_join_commons", {}, { request })).chat_id, COMMONS_ID);
  await assert.rejects(() => runRoomTool("not_a_room_tool", {}, { request }), /not a room tool/);
});

test("ROOM_TOOL_NAMES names exactly the four open-room tools, matching ROOM_TOOL_METADATA", () => {
  assert.deepEqual([...ROOM_TOOL_NAMES].sort(), ["salt_clear_room_interests", "salt_join_commons", "salt_read_room", "salt_set_room_interests"]);
  assert.deepEqual(ROOM_TOOL_METADATA.map((m) => m.name).sort(), [...ROOM_TOOL_NAMES].sort());
});

test("every room tool's metadata carries a title, all four annotation hints, and a non-empty inputSchema/outputSchema", () => {
  for (const meta of ROOM_TOOL_METADATA) {
    assert.ok(meta.title, `${meta.name} needs a title`);
    for (const field of ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"]) {
      assert.equal(typeof meta.annotations[field], "boolean", `${meta.name}.${field}`);
    }
    assert.equal(typeof meta.inputSchema, "object");
    assert.equal(typeof meta.outputSchema, "object");
  }
});

test("salt_read_room is read-only; the other three are not (they write a subscription or join a room)", () => {
  const byName = Object.fromEntries(ROOM_TOOL_METADATA.map((m) => [m.name, m]));
  assert.equal(byName.salt_read_room.annotations.readOnlyHint, true);
  for (const name of ["salt_set_room_interests", "salt_clear_room_interests", "salt_join_commons"]) {
    assert.equal(byName[name].annotations.readOnlyHint, false, name);
  }
});

test("toRoomMcpTools() maps metadata to MCP Tool objects (title folded into annotations, same as toKeylessMcpTools)", () => {
  const tools = toRoomMcpTools();
  assert.equal(tools.length, ROOM_TOOL_METADATA.length);
  for (const tool of tools) {
    assert.equal(typeof tool.name, "string");
    assert.equal(typeof tool.description, "string");
    assert.equal(typeof tool.inputSchema, "object");
    assert.equal(tool.annotations.title, tool.title);
    assert.equal(typeof tool.annotations.readOnlyHint, "boolean");
  }
});

// --- createApiKeyRequest (the local/stdio surface's real binding) ---------

test("createApiKeyRequest: sends the api-key header (never Authorization), GET with no body, POST/PUT with a JSON body", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
  };
  const request = createApiKeyRequest({ host: "https://fake-salt.test/", apiKey: "key-123", fetchImpl });

  await request("GET", "/api/v1/chats/abc");
  assert.equal(calls[0].url, "https://fake-salt.test/api/v1/chats/abc");
  assert.equal(calls[0].init.headers["api-key"], "key-123");
  assert.equal(calls[0].init.headers.Authorization, undefined);
  assert.equal(calls[0].init.body, undefined);

  await request("PUT", "/api/v1/chats/abc/subscription", { mode: "all" });
  assert.equal(calls[1].init.headers["Content-Type"], "application/json");
  assert.equal(calls[1].init.body, JSON.stringify({ mode: "all" }));
});

test("createApiKeyRequest: a non-2xx response throws with salt-api's own error sentence, never swallows it", async () => {
  const fetchImpl = async () => new Response(JSON.stringify({ error: "Salt cannot read an encrypted room, so it cannot follow it for you." }), { status: 422 });
  const request = createApiKeyRequest({ host: "https://fake-salt.test", apiKey: "key-123", fetchImpl });
  await assert.rejects(() => request("PUT", "/api/v1/chats/abc/subscription", { mode: "all" }), /422: Salt cannot read an encrypted room/);
});

test("createApiKeyRequest: a 204/empty response resolves to undefined rather than throwing on empty JSON", async () => {
  const fetchImpl = async () => new Response("", { status: 200 });
  const request = createApiKeyRequest({ host: "https://fake-salt.test", apiKey: "key-123", fetchImpl });
  assert.equal(await request("DELETE", "/api/v1/chats/abc/subscription"), undefined);
});
