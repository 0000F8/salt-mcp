// The LOCAL (stdio, api-key + agent key) server: it can open a chat with a
// human, ask a question and get the answer (api-key REST client, the card's
// own poll), post a card with an explicit chat_id, and decrypt salt_read_room
// with the agent's own key. Everything runs against a fake fetch, never the
// network; crypto is real openpgp via salt-agent-sdk.

import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createRequire } from "node:module";
import pkg from "salt-agent-sdk";
import { createLocalHandlers } from "../src/index.mjs";
import { createDecryptor } from "../src/local-decrypt.mjs";
import { checkCredentials } from "../src/startup-check.mjs";
import { LOCAL_TOOL_NAMES, toLocalMcpTools } from "../src/local-tools.mjs";
import { TOOL_ANNOTATIONS } from "../src/annotations.mjs";

const { createSaltClient, createIdentityStore, createActions, generateKeypair, encryptFor } = pkg;
const openpgp = createRequire(import.meta.resolve("salt-agent-sdk"))("openpgp");

const HOST = "https://salt.test";
const API_KEY = "secret-agent-key";
const CHAT = "11111111-1111-1111-1111-111111111111";
const CARD = "22222222-2222-2222-2222-222222222222";
const HUMAN = { id: "u-human", username: "ada", display_name: "Ada", account_type: "User" };

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function buildActions(caller, fetchImpl) {
  const identities = createIdentityStore();
  identities.register(caller);
  return createActions({
    client: createSaltClient({ host: HOST, fetchImpl }),
    identities,
    pgpPassphrase: "pw",
    publicWebhookUrl: "https://example.invalid/",
    walletMasterKey: "unused",
  });
}

const caller = { saltAppId: "agent-1", username: "bot", displayName: "Bot", apiKey: API_KEY, publicKey: "pub", privateKey: "priv" };

/** A tiny fake salt-api. `routes` maps "METHOD /path" to a handler(req) -> Response; every request must carry the api-key header. */
function fakeSalt(routes) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url);
    const key = `${init.method || "GET"} ${u.pathname}`;
    const headers = init.headers || {};
    calls.push({ key, headers, body: init.body ? JSON.parse(init.body) : undefined, search: u.search });
    assert.equal(headers["api-key"], API_KEY, `${key} must authenticate with the api-key header`);
    assert.equal(headers.Authorization, undefined, `${key} must not send a bearer header`);
    const handler = routes[key];
    if (!handler) return json({ error: `no route ${key}` }, 404);
    return handler({ body: init.body ? JSON.parse(init.body) : undefined, search: u.search });
  };
  return { calls, fetchImpl };
}

test("the local catalog lists open_chat, ask_human, get_ask_result, each annotated", () => {
  const handlers = createLocalHandlers({ actions: buildActions(caller), caller, host: HOST });
  const names = handlers.listTools().map((t) => t.name);
  for (const n of LOCAL_TOOL_NAMES) assert.ok(names.includes(n), `${n} missing from the local catalog`);
  assert.equal(handlers.toolCount, names.length);
  for (const tool of toLocalMcpTools()) {
    for (const f of ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"]) assert.equal(typeof tool.annotations[f], "boolean", `${tool.name}.${f}`);
    assert.doesNotMatch(tool.description, /keyless/i, "local descriptions must not claim the connection is keyless");
  }
  assert.equal(TOOL_ANNOTATIONS.open_chat, undefined, "local tools are annotated by the keyless entries, never double-registered as SDK actions");
});

test("open_chat then ask_human over the api-key client: card restricted to the human, answer read from the card's own poll, card marked Answered", async () => {
  const salt = fakeSalt({
    "GET /api/v1/search/contacts": () => json([HUMAN]),
    "GET /api/v1/agents": () => json([]),
    "POST /api/v1/chats": ({ body }) => {
      assert.deepEqual(body, { contact_id: "u-human" });
      return json({ id: CHAT, name: null, users: [HUMAN, { id: "agent-1", username: "bot" }] });
    },
    [`GET /api/v1/chats/${CHAT}`]: () => json({ session: { id: CHAT, users: [HUMAN, { id: "agent-1", username: "bot" }] }, messages: [] }),
    "POST /api/v1/cards": () => json({ id: "m1", resource_id: CARD }),
    [`GET /api/v1/cards/${CARD}`]: () => json({ interactions: [{ id: "i1", action_id: "opt_1" }] }),
    [`PATCH /api/v1/cards/${CARD}`]: () => json({}),
  });
  const handlers = createLocalHandlers({ actions: buildActions(caller), caller, host: HOST, fetchImpl: salt.fetchImpl });

  const opened = await handlers.callTool("open_chat", { handle: "@ada" });
  assert.equal(opened.chat_id, CHAT);

  const answer = await handlers.callTool("ask_human", { chat_id: CHAT, to: "ada", question: "Ship it?", options: ["Yes", "No"] });
  assert.equal(answer.answer, "No");

  const posted = salt.calls.find((c) => c.key === "POST /api/v1/cards");
  const buttons = posted.body.blocks.find((b) => b.type === "actions").elements;
  assert.deepEqual(buttons.map((b) => b.restricted_to), [["u-human"], ["u-human"]]);
  const patched = salt.calls.find((c) => c.key === `PATCH /api/v1/cards/${CARD}`);
  assert.equal(patched.body.blocks[1].text, "Answered: No");
  assert.ok(!salt.calls.some((c) => c.key.includes("/agent/updates")), "never touches the shared outbox cursor");
});

test("get_ask_result resumes a pending ask from its ask_id", async () => {
  let answered = false;
  const salt = fakeSalt({
    [`GET /api/v1/chats/${CHAT}`]: () => json({ session: { users: [HUMAN] } }),
    "POST /api/v1/cards": () => json({ resource_id: CARD }),
    [`GET /api/v1/cards/${CARD}`]: () => json({ interactions: answered ? [{ id: "i9", action_id: "opt_0" }] : [] }),
    [`PATCH /api/v1/cards/${CARD}`]: () => json({}),
  });
  const handlers = createLocalHandlers({ actions: buildActions(caller), caller, host: HOST, fetchImpl: salt.fetchImpl });
  const pending = await handlers.callTool("ask_human", { chat_id: CHAT, to: "ada", question: "Ok?", options: ["Yes", "No"] }, { maxTotalMsOverride: 5, minEmptyPollMsOverride: 1 });
  assert.equal(pending.status, "pending");
  answered = true;
  const result = await handlers.callTool("get_ask_result", { ask_id: pending.ask_id }, { minEmptyPollMsOverride: 1 });
  assert.equal(result.answer, "Yes");
});

test("post_card posts into the chat named by chat_id, as this agent; without one it says to open a chat first", async () => {
  const salt = fakeSalt({ "POST /api/v1/cards": () => json({ id: "m1", resource_id: CARD }) });
  const handlers = createLocalHandlers({ actions: buildActions(caller, salt.fetchImpl), caller, host: HOST, fetchImpl: salt.fetchImpl });
  {
    const out = await handlers.callTool("post_card", { chat_id: CHAT, blocks: [{ type: "section", text: "hi" }] });
    assert.equal(out.posted, true);
    assert.equal(out.card_id, CARD);
    assert.equal(salt.calls.find((c) => c.key === "POST /api/v1/cards").body.chat_id, CHAT);
    await assert.rejects(handlers.callTool("post_card", { blocks: [{ type: "section", text: "x" }] }), /chat_id.*open_chat/);
    await assert.rejects(handlers.callTool("post_card", { chat_id: "../agents/callback", blocks: [] }), /plain Salt id/);
  }
  const card = handlers.listTools().find((t) => t.name === "post_card");
  assert.ok(card.inputSchema.properties.chat_id);
});

// --- salt_read_room decryption --------------------------------------------

async function unprotectedKey() {
  const { privateKey, publicKey } = await openpgp.generateKey({ type: "ecc", userIDs: [{ name: "x" }], format: "armored" });
  return { privateKey, publicKey };
}

test("salt_read_room (local) decrypts messages the agent was a recipient of -- passphrase-protected AND unprotected keys -- and marks the rest [encrypted]", async () => {
  for (const make of [() => generateKeypair("pw").then((k) => ({ ...k, passphrase: "pw" })), () => unprotectedKey().then((k) => ({ ...k, passphrase: undefined }))]) {
    const mine = await make();
    const stranger = await unprotectedKey();
    const forMe = await encryptFor("hello agent", [mine.publicKey, stranger.publicKey]);
    const notForMe = await encryptFor("not yours", [stranger.publicKey]);
    const salt = fakeSalt({
      [`GET /api/v1/chats/${CHAT}`]: () =>
        json({
          session: { id: CHAT, encrypted: true },
          messages: [
            { id: "1", encrypted: true, message: forMe, user: HUMAN },
            { id: "2", encrypted: true, message: notForMe, user: HUMAN },
            { id: "3", encrypted: true, message: "garbage", user: HUMAN },
            { id: "4", encrypted: false, message: "plain open text", user: HUMAN },
          ],
        }),
    });
    const decrypt = createDecryptor({ privateKey: mine.privateKey, passphrase: mine.passphrase });
    const handlers = createLocalHandlers({ actions: buildActions(caller), caller, host: HOST, decrypt, fetchImpl: salt.fetchImpl });
    const room = await handlers.callTool("salt_read_room", { chat_id: CHAT });
    assert.deepEqual(room.messages.map((m) => m.text), ["hello agent", "[encrypted]", "[encrypted]", "plain open text"]);
    assert.equal(room.messages[0].decrypted, true);
    assert.equal(room.messages[1].decrypted, false);
    assert.equal(room.messages[3].decrypted, undefined);
    assert.match(handlers.listTools().find((t) => t.name === "salt_read_room").description, /decrypted/);
  }
});

test("without a decryptor (the hosted server's shape) salt_read_room returns ciphertext untouched", async () => {
  const mine = await generateKeypair("pw");
  const ct = await encryptFor("secret", [mine.publicKey]);
  const salt = fakeSalt({ ["GET /api/v1/chats/" + CHAT]: () => json({ session: {}, messages: [{ id: "1", encrypted: true, message: ct }] }) });
  const handlers = createLocalHandlers({ actions: buildActions(caller), caller, host: HOST, fetchImpl: salt.fetchImpl });
  const room = await handlers.callTool("salt_read_room", { chat_id: CHAT });
  assert.equal(room.messages[0].text, ct);
});

// --- startup credential check ---------------------------------------------

function listen(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", () => resolve({ server, host: `http://127.0.0.1:${server.address().port}` }));
  });
}

test("checkCredentials: 401 is unauthorized and names SALT_API_KEY", async () => {
  const { server, host } = await listen((req, res) => {
    res.writeHead(req.headers["api-key"] === "good" ? 200 : 401, { "Content-Type": "application/json" });
    res.end(JSON.stringify(req.headers["api-key"] === "good" ? { agent_id: "agent-1", webhook_secret: "s" } : { error: "no" }));
  });
  try {
    const bad = await checkCredentials({ host, apiKey: "bad", appId: "agent-1" });
    assert.equal(bad.status, "unauthorized");
    assert.match(bad.message, /SALT_API_KEY/);

    const ok = await checkCredentials({ host, apiKey: "good", appId: "agent-1" });
    assert.equal(ok.status, "ok");
    assert.equal(ok.mismatch, false);

    const mismatch = await checkCredentials({ host, apiKey: "good", appId: "12345" });
    assert.equal(mismatch.status, "ok");
    assert.equal(mismatch.mismatch, true);
    assert.match(mismatch.message, /SALT_APP_ID is 12345.*agent-1/);
    assert.doesNotMatch(JSON.stringify(mismatch), /"s"/, "never echoes the webhook secret");
  } finally {
    server.close();
  }
});

test("checkCredentials: an unreachable host warns and does not block", async () => {
  const { server, host } = await listen(() => {});
  await new Promise((r) => server.close(r));
  const result = await checkCredentials({ host, apiKey: "k", appId: "a", timeoutMs: 500 });
  assert.equal(result.status, "unreachable");
  assert.match(result.message, /continuing/);
});

test("the server process exits non-zero with a one-line SALT_API_KEY error when the api key is rejected", async () => {
  const { spawn } = await import("node:child_process");
  const { server, host } = await listen((req, res) => {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end('{"error":"nope"}');
  });
  try {
    const child = spawn(process.execPath, [new URL("../src/index.mjs", import.meta.url).pathname], {
      env: { PATH: process.env.PATH, HOST: host, SALT_API_KEY: "wrong", SALT_APP_ID: "a", APP_PUBLIC_KEY: "pub", APP_PRIVATE_KEY: "priv" },
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (d) => (stderr += d));
    const code = await new Promise((resolve) => child.on("close", resolve));
    assert.notEqual(code, 0);
    assert.match(stderr, /SALT_API_KEY was rejected/);
    assert.doesNotMatch(stderr, /ready as agent/);
  } finally {
    server.close();
  }
});

test("the README's stated local tool count matches the code", async () => {
  const { readFileSync } = await import("node:fs");
  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
  const stated = Number(/Tools exposed by this local server \((\d+):/.exec(readme)?.[1]);
  const handlers = createLocalHandlers({ actions: buildActions(caller), caller, host: HOST });
  assert.equal(stated, handlers.listTools().length);
  for (const file of ["llms-install.md", "skills/salt/SKILL.md"]) {
    const text = readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
    assert.match(text, new RegExp(`\\b${stated}\\b[- ]tools?`), `${file} should state ${stated} local tools`);
  }
});
