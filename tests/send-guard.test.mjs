// The opt-in send guard (KEY_RESET_DESIGN.md 7) on every salt-mcp sender: the keyless send_message, the --channel
// reply, the bearer client's postMessage and --as-me salt_me_send. Fingerprints go out; one stale_recipient_keys
// refusal means one re-encrypt and resend; a second refusal is thrown (no loop).

import { test } from "node:test";
import assert from "node:assert/strict";
import { buildGuard, guardBody, staleMembers, applyFresh, sendWithFreshKeys } from "../src/send-guard.mjs";
import { createSaltBearerClient, SaltBearerApiError } from "../src/salt-bearer-client.mjs";
import { runKeylessTool } from "../src/keyless-tools.mjs";
import { createChannelBridge } from "../src/channel.mjs";
import { createMeHandlers } from "../src/me-tools.mjs";

const stale = (members, extra = {}) => Object.assign(new Error("409"), { status: 409, body: { code: "stale_recipient_keys", members }, ...extra });
const fresh = [
  { id: "ada", public_key: "KEY-ada-2", public_fingerprint: "FP-ada-2" },
  { id: "bot", public_key: "KEY-bot", public_fingerprint: "FP-bot" },
];
const roster = () => [
  { id: "bot", username: "bot", public_key: "KEY-bot", public_fingerprint: "FP-bot" },
  { id: "ada", username: "ada", public_key: "KEY-ada", public_fingerprint: "FP-ada" },
];

test("buildGuard: others in the map, own row as sender_fingerprint; whole roster when self is unknown; empty without fingerprints", () => {
  assert.deepEqual(buildGuard(roster(), "bot"), { recipientFingerprints: { ada: "FP-ada" }, senderFingerprint: "FP-bot" });
  assert.deepEqual(buildGuard(roster()), { recipientFingerprints: { bot: "FP-bot", ada: "FP-ada" } });
  assert.deepEqual(buildGuard([{ id: "ada", public_key: "K" }], "bot"), {});
  assert.deepEqual(guardBody(buildGuard(roster(), "bot")), { recipient_fingerprints: { ada: "FP-ada" }, sender_fingerprint: "FP-bot" });
  assert.deepEqual(guardBody({}), {});
});

test("staleMembers reads every error shape and ignores other refusals", () => {
  assert.deepEqual(staleMembers(stale(fresh)), fresh);
  assert.deepEqual(staleMembers(new SaltBearerApiError("POST", "/x", 409, { code: "stale_recipient_keys", members: fresh })), fresh);
  assert.equal(staleMembers(Object.assign(new Error("p"), { status: 409, body: { code: "pickup_required" } })), null);
  assert.equal(staleMembers(Object.assign(new Error("s"), { status: 500, body: { code: "stale_recipient_keys" } })), null);
  assert.deepEqual(applyFresh(roster(), fresh).find((u) => u.id === "ada").public_key, "KEY-ada-2");
});

test("sendWithFreshKeys retries once and does not loop", async () => {
  let calls = 0;
  await assert.rejects(sendWithFreshKeys(roster(), async () => { calls++; throw stale(fresh); }), /409/);
  assert.equal(calls, 2);
  calls = 0;
  await assert.rejects(sendWithFreshKeys(roster(), async () => { calls++; throw new Error("boom"); }), /boom/);
  assert.equal(calls, 1);
});

test("bearer client postMessage sends sender_message and the guard fields", async () => {
  const bodies = [];
  const client = createSaltBearerClient({
    host: "https://salt.test",
    fetchImpl: async (_url, init) => {
      bodies.push(JSON.parse(init.body));
      return new Response("{}", { status: 200 });
    },
  });
  await client.postMessage("tok", "c1", "CIPHER");
  await client.postMessage("tok", "c1", "CIPHER", "SELF", { recipientFingerprints: { ada: "FP-ada" }, senderFingerprint: "FP-bot" });
  assert.deepEqual(bodies[0], { chat_id: "c1", message: "CIPHER" });
  assert.deepEqual(bodies[1], { chat_id: "c1", message: "CIPHER", sender_message: "SELF", recipient_fingerprints: { ada: "FP-ada" }, sender_fingerprint: "FP-bot" });
});

test("keyless send_message: fingerprints out, one re-encrypt on stale_recipient_keys", async () => {
  const sent = [];
  let current;
  const rest = { getChat: async () => ({ session: { users: current } }) };
  // encryptFor needs real armored keys.
  const pkg = (await import("salt-agent-sdk")).default;
  const a = await pkg.generateKeypair("p1");
  const b = await pkg.generateKeypair("p2");
  const b2 = await pkg.generateKeypair("p3");
  current = [
    { id: "bot", public_key: a.publicKey, public_fingerprint: "FP-bot" },
    { id: "ada", public_key: b.publicKey, public_fingerprint: "FP-ada" },
  ];
  const freshMembers = [{ id: "ada", public_key: b2.publicKey, public_fingerprint: "FP-ada-2" }];
  rest.postMessage = async (_t, _c, message, senderMessage, guard) => {
    sent.push({ message, senderMessage, guard });
    if (sent.length === 1) throw new SaltBearerApiError("POST", "/api/v1/messages", 409, { code: "stale_recipient_keys", members: freshMembers });
    return { id: "m1" };
  };
  const out = await runKeylessTool("send_message", { chat_id: "11111111-1111-4111-8111-111111111111", text: "hi" }, { rest, bearerToken: "tok" });
  assert.equal(out.sent, true);
  assert.equal(sent.length, 2);
  assert.deepEqual(sent[0].guard, { recipientFingerprints: { bot: "FP-bot", ada: "FP-ada" } });
  assert.equal(sent[0].senderMessage, undefined);
  assert.deepEqual(sent[1].guard, { recipientFingerprints: { bot: "FP-bot", ada: "FP-ada-2" } });
  assert.notEqual(sent[0].message, sent[1].message);
});

test("keyless send_message does not loop on a second stale refusal", async () => {
  const pkg = (await import("salt-agent-sdk")).default;
  const a = await pkg.generateKeypair("p1");
  let posts = 0;
  const rest = {
    getChat: async () => ({ session: { users: [{ id: "ada", public_key: a.publicKey, public_fingerprint: "FP" }] } }),
    postMessage: async () => {
      posts++;
      throw new SaltBearerApiError("POST", "/api/v1/messages", 409, { code: "stale_recipient_keys", members: [{ id: "ada", public_key: a.publicKey, public_fingerprint: "FP2" }] });
    },
  };
  await assert.rejects(runKeylessTool("send_message", { chat_id: "11111111-1111-4111-8111-111111111111", text: "hi" }, { rest, bearerToken: "tok" }), /409/);
  assert.equal(posts, 2);
});

test("--channel reply: fingerprints out, one re-encrypt on stale_recipient_keys, no loop", async () => {
  const posts = [];
  let mode = "once";
  const users = () => [
    { id: "bot", username: "bot", account_type: "Agent", public_key: "KEY-bot", public_fingerprint: "FP-bot" },
    { id: "ada", username: "ada", account_type: "User", public_key: "KEY-ada", public_fingerprint: "FP-ada" },
  ];
  const client = {
    getChat: async () => ({ id: "c1", encrypted: true, users: users() }),
    postMessage: async (key, chatId, message, senderMessage, delegations, mentions, opts) => {
      posts.push({ message, senderMessage, opts });
      if (mode === "always" || (mode === "once" && posts.length === 1)) {
        throw Object.assign(new Error("409"), { status: 409, body: { code: "stale_recipient_keys", members: [{ id: "ada", public_key: "KEY-ada-2", public_fingerprint: "FP-ada-2" }] } });
      }
      return {};
    },
  };
  const make = () =>
    createChannelBridge({
      client,
      caller: { saltAppId: "bot", apiKey: "k", publicKey: "KEY-bot" },
      allowedIds: new Set(["ada"]),
      notify: async () => {},
      createSocket: () => ({ start() {}, async stop() {} }),
      encrypt: async (text, keys) => `ENC[${keys.join("|")}]${text}`,
    });
  const prime = async (bridge) => bridge.onMessage({ chatId: "c1", senderId: "ada", sender: { id: "ada", username: "ada" }, text: "yo", encrypted: true, messageId: "1" });

  let bridge = make();
  await prime(bridge);
  await bridge.reply({ chat_id: "c1", text: "hello" });
  assert.equal(posts.length, 2);
  assert.deepEqual(posts[0].opts, { recipientFingerprints: { ada: "FP-ada" }, senderFingerprint: "FP-bot" });
  assert.equal(posts[1].message, "ENC[KEY-ada-2]hello");
  assert.deepEqual(posts[1].opts, { recipientFingerprints: { ada: "FP-ada-2" }, senderFingerprint: "FP-bot" });

  posts.length = 0;
  mode = "always";
  bridge = make();
  await prime(bridge);
  await assert.rejects(bridge.reply({ chat_id: "c1", text: "hello" }), /409/);
  assert.equal(posts.length, 2);
});

test("salt_me_send: guard in the body, one re-encrypt with the same Idempotency-Key, no loop", async () => {
  const pkg = (await import("salt-agent-sdk")).default;
  const me = await pkg.generateKeypair("m");
  const ada = await pkg.generateKeypair("a");
  const ada2 = await pkg.generateKeypair("a2");
  const posted = [];
  let mode = "once";
  const session = {
    me: { id: "me" },
    status: { unlocked: true },
    get: async () => ({
      session: {
        id: "c1",
        encrypted: true,
        users: [
          { id: "me", username: "me", public_key: me.publicKey, public_fingerprint: "FP-me" },
          { id: "ada", username: "ada", account_type: "User", public_key: ada.publicKey, public_fingerprint: "FP-ada" },
        ],
      },
    }),
    post: async (path, body, headers) => {
      posted.push({ path, body, headers });
      if (mode === "always" || (mode === "once" && posted.length === 1)) {
        throw Object.assign(new Error("Salt refused the message (409)"), { status: 409, body: { code: "stale_recipient_keys", members: [{ id: "ada", public_key: ada2.publicKey, public_fingerprint: "FP-ada-2" }] } });
      }
      return { id: "9001" };
    },
  };
  const h = createMeHandlers({ session, readOnly: false, host: "https://salt.test" });
  const out = await h.callTool("salt_me_send", { chat_id: "c0000000-0000-4000-8000-000000000001", text: "hello" });
  assert.equal(out.sent, true);
  assert.equal(posted.length, 2);
  assert.equal(posted[0].body.sender_fingerprint, "FP-me");
  assert.deepEqual(posted[0].body.recipient_fingerprints, { ada: "FP-ada" });
  assert.deepEqual(posted[1].body.recipient_fingerprints, { ada: "FP-ada-2" });
  assert.equal(posted[1].headers["Idempotency-Key"], posted[0].headers["Idempotency-Key"]);
  assert.notEqual(posted[0].body.message, posted[1].body.message);

  posted.length = 0;
  mode = "always";
  await assert.rejects(h.callTool("salt_me_send", { chat_id: "c0000000-0000-4000-8000-000000000001", text: "hello" }), /409/);
  assert.equal(posted.length, 2);
});
