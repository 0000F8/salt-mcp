// `salt-mcp --as-me` end to end against a fake Salt (tests/me-fixtures.mjs): real PBKDF2/AES-GCM vault, real PGP, a
// mock HTTP layer, and the MCP server driven by a real MCP client over an in-memory transport. Nothing here touches
// the network, the Keychain or the screen.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMeHandlers, McpContent } from "../src/me-tools.mjs";
import { buildMeServer } from "../src/me-cli.mjs";
import { SIGN_IN_FAILED, UNLOCK_FAILED, createMeSession } from "../src/me-session.mjs";
import { loadOpenpgp } from "../src/local-decrypt.mjs";
import {
  makeWorld, secretsOf, EMAIL, HOST, PASSWORD,
  CHAT_ADA, CHAT_GROUP, CHAT_OPEN, CHAT_LEGACY, CHAT_REQUEST, ME_ID, ADA_ID, BOT_ID,
} from "./me-fixtures.mjs";

const decryptWith = async (armoredPrivateKey, armoredMessage) => {
  const openpgp = await loadOpenpgp();
  const { data } = await openpgp.decrypt({
    message: await openpgp.readMessage({ armoredMessage }),
    decryptionKeys: await openpgp.readPrivateKey({ armoredKey: armoredPrivateKey }),
  });
  return String(data);
};

function handlersFor(world, { allowSend = false, confirmSend } = {}) {
  return createMeHandlers({ session: world.session, allowSend, confirmSend, host: HOST });
}

/** Connects a real MCP client to the as-me server; collects everything the server writes to stderr. */
async function connect(world, opts) {
  const handlers = handlersFor(world, opts);
  const server = buildMeServer(handlers);
  const client = new Client({ name: "test", version: "0" }, { capabilities: {} });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return { client, handlers, close: () => Promise.all([client.close(), server.close()]) };
}

const textOf = (result) => result.content.filter((c) => c.type === "text").map((c) => c.text).join("\n");

test("nothing happens until the first tool call: no sign-in, no Keychain read", async () => {
  const world = await makeWorld();
  const handlers = handlersFor(world);
  assert.equal(world.requests.length, 0);
  assert.deepEqual(world.secretCalls, []);
  const who = await handlers.callTool("salt_me_whoami");
  assert.equal(who.unlocked, false);
  assert.equal(who.send_enabled, false);
  assert.equal(world.requests.length, 0, "whoami reads no network either");
});

test("tools: five read tools, and salt_me_send only with --allow-send; every tool is annotated", async () => {
  const world = await makeWorld();
  const names = (h) => h.listTools().map((t) => t.name).sort();
  assert.deepEqual(names(handlersFor(world)), ["salt_me_find_chat", "salt_me_list_chats", "salt_me_read_attachment", "salt_me_read_chat", "salt_me_whoami"]);
  const withSend = handlersFor(world, { allowSend: true });
  assert.ok(names(withSend).includes("salt_me_send"));
  for (const tool of withSend.listTools()) {
    assert.ok(tool.annotations && typeof tool.annotations.readOnlyHint === "boolean", `${tool.name} has annotations`);
    assert.equal(tool.annotations.readOnlyHint, tool.name !== "salt_me_send", tool.name);
  }
});

test("sign-in sends the auth string (never the password) and unlocks lazily on the first call", async () => {
  const world = await makeWorld();
  const handlers = handlersFor(world);
  await handlers.callTool("salt_me_list_chats");
  const signIn = world.requests.find((r) => r.path === "/auth/sign_in");
  const body = JSON.parse(signIn.body);
  assert.equal(body.user.email, EMAIL);
  assert.notEqual(body.user.password, PASSWORD);
  assert.ok(!signIn.body.includes(PASSWORD));
  assert.equal(world.state.signIns, 1);
  const authed = world.requests.filter((r) => r.path !== "/auth/sign_in");
  assert.ok(authed.every((r) => r.headers.Authorization === "Bearer test.jwt.token"), "the JWT is sent back verbatim");
  const who = await handlers.callTool("salt_me_whoami");
  assert.equal(who.unlocked, true);
  assert.equal(who.lock_mode, "login");
  assert.equal(who.account.username, "owner");
  assert.equal(who.token_age_days, 0);
});

test("lock modes: login never asks for a second secret; separate reads the vault item", async () => {
  const login = await makeWorld({ lockMode: "login" });
  await handlersFor(login).callTool("salt_me_list_chats");
  assert.deepEqual(login.secretCalls, ["salt-mcp-me"]);

  const separate = await makeWorld({ lockMode: "separate" });
  await handlersFor(separate).callTool("salt_me_list_chats");
  assert.deepEqual(separate.secretCalls, ["salt-mcp-me", "salt-mcp-me-vault"]);
  assert.equal((await handlersFor(separate).callTool("salt_me_whoami")).lock_mode, "separate");
});

test("a legacy key account unlocks without any vault request", async () => {
  const world = await makeWorld({ scheme: "legacy", lockMode: null });
  const chats = await handlersFor(world).callTool("salt_me_list_chats");
  assert.ok(chats.length > 0);
  assert.ok(!world.requests.some((r) => r.path === "/api/v1/vault"));
});

test("list_chats: names, kinds, members, unread, last activity and a decrypted one-line preview", async () => {
  const world = await makeWorld();
  const chats = await handlersFor(world).callTool("salt_me_list_chats");
  const byId = Object.fromEntries(chats.map((c) => [c.id, c]));
  assert.equal(chats.length, 4);

  assert.equal(byId[CHAT_ADA].kind, "person");
  assert.equal(byId[CHAT_ADA].name, "Ada Lovelace", "a 1:1 wears the other person's name, never its stored name");
  assert.deepEqual(byId[CHAT_ADA].members, [{ name: "Ada Lovelace", handle: "@ada", type: "person" }]);
  assert.equal(byId[CHAT_ADA].unread_count, 2);
  assert.equal(byId[CHAT_ADA].preview, "message number 25");
  assert.match(byId[CHAT_ADA].last_activity, /^2026-10-14T/);

  assert.equal(byId[CHAT_GROUP].kind, "group");
  assert.equal(byId[CHAT_GROUP].name, "Launch crew");
  assert.deepEqual(byId[CHAT_GROUP].members.map((m) => m.handle), ["@ada", "@helperbot"]);
  assert.equal(byId[CHAT_GROUP].preview, "Ada called. No answer.");

  assert.equal(byId[CHAT_OPEN].preview, "hello open room", "an open room's plain text passes through");
  assert.equal(byId[CHAT_OPEN].unread_count, 5);
  assert.equal(byId[CHAT_LEGACY].preview, "my own legacy message", "own legacy message opens from sender_message");
});

test("list_chats filters: groups, people, agents, requests, and a query", async () => {
  const world = await makeWorld();
  const h = handlersFor(world);
  assert.deepEqual((await h.callTool("salt_me_list_chats", { filter: "groups" })).map((c) => c.id).sort(), [CHAT_GROUP, CHAT_OPEN].sort());
  assert.deepEqual((await h.callTool("salt_me_list_chats", { filter: "people" })).map((c) => c.id).sort(), [CHAT_ADA, CHAT_LEGACY].sort());
  assert.deepEqual(await h.callTool("salt_me_list_chats", { filter: "agents" }), []);
  const requests = await h.callTool("salt_me_list_chats", { filter: "requests" });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].id, CHAT_REQUEST);
  assert.equal(requests[0].kind, "agent");
  assert.equal(requests[0].request_state, "pending");
  assert.equal(requests[0].preview, "hello, may I introduce myself?");
  assert.ok(world.requests.some((r) => r.search === "?requests=1"));
  assert.deepEqual((await h.callTool("salt_me_list_chats", { query: "crew" })).map((c) => c.id), [CHAT_GROUP]);
  assert.deepEqual((await h.callTool("salt_me_list_chats", { query: "@helperbot" })).map((c) => c.id), [CHAT_GROUP]);
  await assert.rejects(h.callTool("salt_me_list_chats", { filter: "everything" }), /filter must be/);
});

test("read_chat: oldest to newest, [Encrypted] before the owner joined, whole history in one call", async () => {
  const world = await makeWorld({ messageCount: 25 });
  const out = await handlersFor(world).callTool("salt_me_read_chat", { chat_id: CHAT_ADA, limit: 200 });
  assert.equal(out.chat.name, "Ada Lovelace");
  assert.equal(out.returned, 26);
  assert.equal(out.messages[0].text, "[Encrypted]");
  assert.deepEqual(out.messages.slice(1).map((m) => m.text), Array.from({ length: 25 }, (_, i) => `message number ${i + 1}`));
  assert.equal(out.has_earlier, false);
  const times = out.messages.map((m) => Date.parse(m.time));
  assert.deepEqual(times, [...times].sort((a, b) => a - b));
  const mine = out.messages.filter((m) => m.from.me);
  assert.ok(mine.length > 0 && mine.every((m) => m.from.handle === "@owner"));
  assert.ok(out.messages.every((m) => m.from.type === "person"));
});

test("read_chat pages through /previous to reach the limit, then pages back with before_message_id", async () => {
  const world = await makeWorld({ messageCount: 25 });
  const h = handlersFor(world);
  const first = await h.callTool("salt_me_read_chat", { chat_id: CHAT_ADA, limit: 12 });
  assert.equal(first.returned, 12);
  assert.deepEqual(first.messages.map((m) => m.text), Array.from({ length: 12 }, (_, i) => `message number ${i + 14}`));
  assert.ok(world.requests.some((r) => r.path === `/api/v1/chats/${CHAT_ADA}/previous`), "went to /previous for the extra messages");
  assert.equal(first.has_earlier, true);
  assert.equal(first.earlier_cursor, first.messages[0].id);

  const second = await h.callTool("salt_me_read_chat", { chat_id: CHAT_ADA, limit: 12, before_message_id: first.earlier_cursor });
  assert.deepEqual(second.messages.map((m) => m.text), Array.from({ length: 12 }, (_, i) => `message number ${i + 2}`));
  const third = await h.callTool("salt_me_read_chat", { chat_id: CHAT_ADA, limit: 12, before_message_id: second.earlier_cursor });
  assert.deepEqual(third.messages.map((m) => m.text), ["[Encrypted]", "message number 1"]);
  assert.equal(third.has_earlier, false);
});

test("read_chat limit must be 1..200", async () => {
  const world = await makeWorld();
  const h = handlersFor(world);
  for (const limit of [0, 201, 1.5, "lots"]) await assert.rejects(h.callTool("salt_me_read_chat", { chat_id: CHAT_ADA, limit }), /limit must be/);
  await assert.rejects(h.callTool("salt_me_read_chat", { chat_id: "../../etc/passwd" }), /plain Salt id/);
  await assert.rejects(h.callTool("salt_me_read_chat", {}), /chat_id or name/);
});

test("read_chat on a group: markers stripped, reply and mention resolved, attachment summarised without its key, events kept", async () => {
  const world = await makeWorld();
  const out = await handlersFor(world).callTool("salt_me_read_chat", { chat_id: CHAT_GROUP });
  const [plan, review, ...rest] = out.messages;
  assert.equal(plan.text, "please review the plan");
  assert.equal(review.text, "reviewing now, @owner", "the thinking block is gone");
  assert.deepEqual(review.from, { name: "Helper Bot", handle: "@helperbot", type: "agent", me: false });
  assert.equal(review.reply_to.id, plan.id);
  assert.equal(review.reply_to.from, "Ada Lovelace");
  assert.equal(review.reply_to.text, "please review the plan");
  assert.deepEqual(review.mentions, ["@owner"]);
  const attachments = rest.filter((m) => m.attachment);
  assert.deepEqual(attachments.map((m) => m.attachment.filename), ["notes.txt", "dot.png", "data.bin", "big.zip"]);
  assert.equal(attachments[0].text, "[Attachment]");
  assert.equal(attachments[0].attachment.content_type, "text/plain");
  const event = rest.at(-1);
  assert.equal(event.event, "call_unanswered");
  assert.equal(event.text, "Ada called. No answer.");
  const raw = JSON.stringify(out);
  assert.ok(!/"key"|"iv"|encrypted_key|BEGIN PGP/.test(raw), "no attachment key material and no ciphertext in the result");
  assert.ok(!raw.includes("SALT-"), "no wire marker survives");
});

test("find_chat: fuzzy on chat names and on member names and handles", async () => {
  const world = await makeWorld();
  const h = handlersFor(world);
  const top = async (name) => (await h.callTool("salt_me_find_chat", { name }))[0]?.id;
  assert.equal(await top("launch"), CHAT_GROUP);
  assert.equal(await top("Launch Crew"), CHAT_GROUP);
  assert.equal(await top("lanch crew"), CHAT_GROUP, "tolerates a typo");
  assert.equal(await top("helperbot"), CHAT_GROUP, "finds a chat by a member's handle");
  assert.equal(await top("lovelace"), CHAT_ADA);
  assert.equal(await top("OPEN LOUNGE"), CHAT_OPEN);
  assert.deepEqual(await h.callTool("salt_me_find_chat", { name: "zzzzqqqq" }), []);
  assert.ok((await h.callTool("salt_me_find_chat", { name: "ada" })).length <= 5);
  await assert.rejects(h.callTool("salt_me_find_chat", {}), /name is required/);
});

test("read_chat by name resolves one match, refuses an ambiguous one, and says when nothing matches", async () => {
  const world = await makeWorld();
  const h = handlersFor(world);
  assert.equal((await h.callTool("salt_me_read_chat", { name: "launch crew", limit: 1 })).chat.id, CHAT_GROUP);
  await assert.rejects(h.callTool("salt_me_read_chat", { name: "ada" }), /More than one chat matches/);
  await assert.rejects(h.callTool("salt_me_read_chat", { name: "qqqqzzzz" }), /No chat matches/);
});

test("read_attachment: text as text, images as MCP image content, other files as metadata, oversized files never downloaded", async () => {
  const world = await makeWorld();
  const h = handlersFor(world);
  const id = (n) => world.attachmentMessages[n].id;

  const note = await h.callTool("salt_me_read_attachment", { message_id: id("note") });
  assert.deepEqual({ ...note }, { filename: "notes.txt", content_type: "text/plain", size: 23, shown: true, truncated: false, text: "first line\nsecond line\n" });

  const pic = await h.callTool("salt_me_read_attachment", { message_id: id("pic") });
  assert.ok(pic instanceof McpContent);
  const image = pic.content.find((c) => c.type === "image");
  assert.equal(image.mimeType, "image/png");
  assert.equal(Buffer.from(image.data, "base64").toString("hex"), "89504e470d0a1a0a");

  const blob = await h.callTool("salt_me_read_attachment", { message_id: id("blob") });
  assert.equal(blob.shown, false);
  assert.equal(blob.filename, "data.bin");
  assert.ok(!("text" in blob));

  const before = world.requests.length;
  const huge = await h.callTool("salt_me_read_attachment", { message_id: id("huge") });
  assert.equal(huge.shown, false);
  assert.match(huge.note, /15 MB/);
  assert.ok(!world.requests.slice(before).some((r) => r.path.endsWith("/attachment")), "the file was not downloaded");

  for (const out of [note, blob, huge]) assert.ok(!/"key"|"iv"/.test(JSON.stringify(out)));
  await assert.rejects(h.callTool("salt_me_read_attachment", { message_id: "abc" }), /plain Salt message id/);
});

test("read_attachment works for a message id never read before (fetches the message)", async () => {
  const world = await makeWorld();
  const note = await handlersFor(world).callTool("salt_me_read_attachment", { message_id: world.attachmentMessages.note.id });
  assert.equal(note.text, "first line\nsecond line\n");
  assert.ok(world.requests.some((r) => r.method === "GET" && r.path === `/api/v1/messages/${world.attachmentMessages.note.id}`));
});

test("READ MODE NEVER WRITES: a full session makes no request but GETs (and the one sign-in)", async () => {
  const world = await makeWorld();
  const h = handlersFor(world);
  await h.callTool("salt_me_list_chats");
  await h.callTool("salt_me_list_chats", { filter: "requests" });
  await h.callTool("salt_me_find_chat", { name: "crew" });
  for (const chat of [CHAT_ADA, CHAT_GROUP, CHAT_OPEN, CHAT_LEGACY]) await h.callTool("salt_me_read_chat", { chat_id: chat, limit: 200 });
  await h.callTool("salt_me_read_attachment", { message_id: world.attachmentMessages.note.id });
  const writes = world.requests.filter((r) => r.method !== "GET");
  assert.deepEqual(writes.map((r) => `${r.method} ${r.path}`), ["POST /auth/sign_in"]);
  assert.ok(!world.requests.some((r) => /mark_read|typing|reaction|read_receipt/.test(r.path)));
  assert.equal(world.posted.length, 0);
});

test("the read-mode session has no way to write: the send tool is absent and refused if called", async () => {
  const world = await makeWorld();
  const { client, close } = await connect(world);
  const names = (await client.listTools()).tools.map((t) => t.name);
  assert.ok(!names.includes("salt_me_send"));
  const res = await client.callTool({ name: "salt_me_send", arguments: { chat_id: CHAT_ADA, text: "hi" } });
  assert.equal(res.isError, true);
  assert.equal(world.posted.length, 0);
  assert.ok(!world.requests.some((r) => r.method === "POST" && r.path === "/api/v1/messages"));
  await close();
});

test("send gate: refused without --allow-send, nothing posted", async () => {
  const world = await makeWorld();
  let asked = 0;
  const h = handlersFor(world, { allowSend: false, confirmSend: async () => (asked++, true) });
  await assert.rejects(h.callTool("salt_me_send", { chat_id: CHAT_ADA, text: "hello" }), /--allow-send/);
  assert.equal(asked, 0);
  assert.equal(world.posted.length, 0);
});

test("send gate: the owner pressing Don't send posts nothing", async () => {
  const world = await makeWorld();
  const dialogs = [];
  const h = handlersFor(world, { allowSend: true, confirmSend: async (d) => (dialogs.push(d), false) });
  const out = await h.callTool("salt_me_send", { chat_id: CHAT_GROUP, text: "ship it" });
  assert.deepEqual(out, { sent: false, reason: "The owner chose not to send it." });
  assert.deepEqual(dialogs, [{ chatName: "Launch crew", text: "ship it" }], "the dialog got the chat name and the full text");
  assert.equal(world.posted.length, 0);
});

test("send gate: no dialog function at all means no send", async () => {
  const world = await makeWorld();
  const out = await handlersFor(world, { allowSend: true }).callTool("salt_me_send", { chat_id: CHAT_ADA, text: "hello" });
  assert.equal(out.sent, false);
  assert.equal(world.posted.length, 0);
});

test("send: after Send, encrypted for every member including the owner, with an Idempotency-Key and mention ids", async () => {
  const world = await makeWorld();
  const h = handlersFor(world, { allowSend: true, confirmSend: async () => true });
  const out = await h.callTool("salt_me_send", { chat_id: CHAT_GROUP, text: "thanks @helperbot, looks good", mentions: ["@ada"] });
  assert.deepEqual(out, { sent: true, message_id: "9001", chat_id: CHAT_GROUP, chat_name: "Launch crew" });
  assert.equal(world.posted.length, 1);
  const { body, headers } = world.posted[0];
  assert.equal(body.chat_id, CHAT_GROUP);
  assert.match(headers["Idempotency-Key"], /^[0-9a-f-]{36}$/);
  assert.deepEqual([...body.mentions].sort(), [ADA_ID, BOT_ID].sort());
  assert.ok(body.message.startsWith("-----BEGIN PGP MESSAGE-----"));
  assert.ok(!body.message.includes("looks good"));
  for (const who of ["me", "ada", "bot"]) assert.equal(await decryptWith(world.keys[who].privateKey, body.message), "thanks @helperbot, looks good", `${who} can read it`);
  await assert.rejects(decryptWith(world.keys.stranger.privateKey, body.message));
});

test("send into an open room is plain text; a second send gets a fresh Idempotency-Key", async () => {
  const world = await makeWorld();
  const h = handlersFor(world, { allowSend: true, confirmSend: async () => true });
  await h.callTool("salt_me_send", { chat_id: CHAT_OPEN, text: "hi lounge" });
  await h.callTool("salt_me_send", { chat_id: CHAT_OPEN, text: "hi again" });
  assert.equal(world.posted[0].body.message, "hi lounge");
  assert.notEqual(world.posted[0].headers["Idempotency-Key"], world.posted[1].headers["Idempotency-Key"]);
});

test("send validates: empty text, over-long text, unknown mention, bad chat id", async () => {
  const world = await makeWorld();
  const h = handlersFor(world, { allowSend: true, confirmSend: async () => true });
  await assert.rejects(h.callTool("salt_me_send", { chat_id: CHAT_ADA, text: "   " }), /text is required/);
  await assert.rejects(h.callTool("salt_me_send", { chat_id: CHAT_ADA, text: "x".repeat(8001) }), /over 8000/);
  await assert.rejects(h.callTool("salt_me_send", { chat_id: CHAT_ADA, text: "hi", mentions: ["@nobody"] }), /not in that chat/);
  await assert.rejects(h.callTool("salt_me_send", { chat_id: "x/../y", text: "hi" }), /plain Salt id/);
  assert.equal(world.posted.length, 0);
});

test("a wrong password stops at sign-in with one plain sentence, and the next calls do not sign in again", async () => {
  const world = await makeWorld({ password: PASSWORD });
  const wrong = createMeSession({ host: HOST, email: EMAIL, fetchImpl: world.fetchImpl, signInIterations: 1000, readPassword: async () => "not the password" });
  const h = createMeHandlers({ session: wrong, host: HOST });
  await assert.rejects(h.callTool("salt_me_list_chats"), (err) => err.message === SIGN_IN_FAILED);
  await assert.rejects(h.callTool("salt_me_read_chat", { chat_id: CHAT_ADA }), (err) => err.message === SIGN_IN_FAILED);
  await assert.rejects(h.callTool("salt_me_list_chats"));
  assert.equal(world.state.signIns, 1, "Rack::Attack allows 5 sign-ins per 20 s: a bad password costs exactly one");
});

test("a wrong vault password reads as the single unlock sentence", async () => {
  const world = await makeWorld({ lockMode: "separate" });
  const session = createMeSession({
    host: HOST, email: EMAIL, fetchImpl: world.fetchImpl, signInIterations: 1000,
    readPassword: async (service) => (service === "salt-mcp-me-vault" ? "wrong lock password" : PASSWORD),
  });
  await assert.rejects(createMeHandlers({ session, host: HOST }).callTool("salt_me_list_chats"), (err) => err.message === UNLOCK_FAILED);
});

test("a missing saved password reads as the single unlock sentence", async () => {
  const world = await makeWorld();
  const session = createMeSession({
    host: HOST, email: EMAIL, fetchImpl: world.fetchImpl, signInIterations: 1000,
    readPassword: async () => { throw new Error("No password is saved in the Keychain for salt-mcp-me."); },
  });
  await assert.rejects(createMeHandlers({ session, host: HOST }).callTool("salt_me_list_chats"), (err) => err.message === UNLOCK_FAILED);
  assert.equal(world.state.signIns, 0);
});

test("an expired session (401 mid-use) signs in once more and carries on", async () => {
  const world = await makeWorld();
  const h = handlersFor(world);
  await h.callTool("salt_me_list_chats");
  world.state.expireNextRequest = true;
  const chats = await h.callTool("salt_me_list_chats");
  assert.equal(chats.length, 4);
  assert.equal(world.state.signIns, 2);
});

test("over MCP: results are JSON text with structuredContent, an image comes back as image content, errors are isError", async () => {
  const world = await makeWorld();
  const { client, close } = await connect(world, { allowSend: true, confirmSend: async () => false });
  const tools = (await client.listTools()).tools;
  assert.equal(tools.length, 6);
  const list = await client.callTool({ name: "salt_me_list_chats", arguments: {} });
  assert.equal(JSON.parse(textOf(list)).length, 4);
  const pic = await client.callTool({ name: "salt_me_read_attachment", arguments: { message_id: world.attachmentMessages.pic.id } });
  assert.ok(pic.content.some((c) => c.type === "image" && c.mimeType === "image/png"));
  const bad = await client.callTool({ name: "salt_me_read_chat", arguments: { chat_id: "nope/nope" } });
  assert.equal(bad.isError, true);
  assert.match(textOf(bad), /plain Salt id/);
  await close();
});

test("SECRETS NEVER APPEAR: not the password, the DEK, the auth string or the JWT, in any tool output, error or log", async () => {
  const world = await makeWorld({ lockMode: "separate" });
  const logged = [];
  const original = { error: console.error, log: console.log, warn: console.warn, info: console.info, debug: console.debug };
  for (const k of Object.keys(original)) console[k] = (...a) => logged.push(a.map(String).join(" "));
  const outputs = [];
  try {
    const { client, close } = await connect(world, { allowSend: true, confirmSend: async () => true });
    const call = async (name, args) => outputs.push(JSON.stringify(await client.callTool({ name, arguments: args })));
    await call("salt_me_whoami", {});
    await call("salt_me_list_chats", {});
    await call("salt_me_list_chats", { filter: "requests" });
    await call("salt_me_find_chat", { name: "crew" });
    for (const chat of [CHAT_ADA, CHAT_GROUP, CHAT_OPEN, CHAT_LEGACY]) await call("salt_me_read_chat", { chat_id: chat, limit: 200 });
    for (const n of ["note", "pic", "blob", "huge"]) await call("salt_me_read_attachment", { message_id: world.attachmentMessages[n].id });
    await call("salt_me_send", { chat_id: CHAT_GROUP, text: "ok" });
    await call("salt_me_read_chat", { chat_id: "bad id" });
    await call("salt_me_whoami", {});
    await close();
  } finally {
    Object.assign(console, original);
  }
  const everything = [...outputs, ...logged].join("\n");
  for (const secret of secretsOf(world)) assert.ok(!everything.includes(secret), `a secret leaked: ${secret.slice(0, 6)}...`);
  assert.ok(!/BEGIN PGP PRIVATE KEY/.test(everything));
  assert.ok(outputs.length > 10 && outputs.every((o) => o.length > 10), "the scan covered real output");
});

test("failure output is plain sentences with no secrets either", async () => {
  const world = await makeWorld({ signInStatus: 401 });
  const { client, close } = await connect(world);
  const res = await client.callTool({ name: "salt_me_list_chats", arguments: {} });
  assert.equal(res.isError, true);
  assert.match(textOf(res), /Couldn't sign in/);
  for (const secret of secretsOf(world)) assert.ok(!textOf(res).includes(secret));
  await close();
});

test("ids from the fixtures are what the owner sees as 'me'", async () => {
  const world = await makeWorld();
  const h = handlersFor(world);
  const out = await h.callTool("salt_me_read_chat", { chat_id: CHAT_LEGACY });
  assert.equal(out.messages[0].from.me, true);
  assert.equal(out.messages[0].text, "my own legacy message");
  assert.equal(world.session.me.id, ME_ID);
});
