// `salt-mcp --as-me` live reading: the socket, the ring, waiters, watches and the catch-up, against a fake WebSocket
// and a fake session. Nothing here touches the network or a timer loop of its own making.

import { test } from "node:test";
import assert from "node:assert/strict";
import { z } from "zod";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createLive, isMessageFrame } from "../src/me-live.mjs";
import { parseWorkReport } from "../src/me-work.mjs";
import { createMeHandlers, DATA_LABEL } from "../src/me-tools.mjs";
import { buildMeServer } from "../src/me-cli.mjs";
import { makeWorld, CHAT_ADA, ME_ID, ADA_ID } from "./me-fixtures.mjs";

class FakeWS {
  static all = [];
  constructor(url, protocols) {
    this.url = url;
    this.protocols = protocols;
    this.sent = [];
    this.closed = false;
    FakeWS.all.push(this);
  }
  send(data) {
    this.sent.push(JSON.parse(data));
  }
  close() {
    this.closed = true;
  }
  frame(obj) {
    this.onmessage?.({ data: JSON.stringify(obj) });
  }
  hello() {
    this.frame({ type: "welcome" });
  }
  confirm() {
    this.frame({ type: "confirm_subscription", identifier: JSON.stringify({ channel: "UserChannel" }) });
  }
  data(message) {
    this.frame({ identifier: JSON.stringify({ channel: "UserChannel" }), message });
  }
  drop() {
    this.onclose?.({});
  }
}
const tick = (ms = 5) => new Promise((r) => setTimeout(r, ms));
const until = async (fn, ms = 1500) => {
  const end = Date.now() + ms;
  while (!fn()) {
    if (Date.now() > end) throw new Error("timed out waiting for the condition");
    await tick(2);
  }
};
const lastSocket = () => FakeWS.all.at(-1);

const msg = (id, chat, text, from = "ada", extra = {}) => ({ id: String(id), chat_id: chat, seq: Number(id), created_by: from, created_at: "2026-10-22T10:00:00Z", encrypted: false, message: text, user: { id: from, username: from, display_name: from }, ...extra });

function setup({ me = "me", get = async () => ({ messages: [] }), meta = async () => ({ name: "Chat", newestId: null }), pingTimeoutMs, livenessCheckMs } = {}) {
  FakeWS.all = [];
  const gets = [];
  const session = {
    get: async (path) => {
      gets.push(path);
      return get(path);
    },
    liveAuth: async () => ({ url: "wss://salt.test/cable", token: "sld_secret" }),
  };
  const notes = [];
  const live = createLive({
    session,
    WebSocketImpl: FakeWS,
    backoff: { base: 5, max: 20 },
    pingTimeoutMs,
    livenessCheckMs,
    notify: (p) => notes.push(p),
    chatMeta: meta,
    decodeWork: async (m) => {
      const r = parseWorkReport(m.message);
      return r ? { mine: m.created_by === me, title: r.title, out: { type: "work", id: r.id, status: r.status, title: `${DATA_LABEL} ${r.title}`, text: `${DATA_LABEL} ${r.title}`, chat: { id: String(m.coaching_for_chat_id) }, lane_id: String(m.chat_id) } } : null;
    },
    decode: async (m) => ({
      mine: m.created_by === me,
      text: m.deleted_at ? "[deleted]" : m.message,
      deleted: Boolean(m.deleted_at),
      out: { id: String(m.id), chat: { id: String(m.chat_id) }, from: { name: m.user?.display_name, handle: `@${m.user?.username}`, type: "person", me: m.created_by === me }, text: `${DATA_LABEL} ${m.message}`, time: m.created_at },
    }),
  });
  const open = async () => {
    const p = live.ensureOpen();
    await until(() => FakeWS.all.length > 0);
    const ws = lastSocket();
    ws.hello();
    ws.confirm();
    await p;
    return ws;
  };
  return { live, gets, notes, open };
}

test("the socket subscribes with the token as the LAST subprotocol and the UserChannel subscribe command", async () => {
  const { live, open } = setup();
  const ws = await open();
  assert.equal(ws.url, "wss://salt.test/cable");
  assert.deepEqual(ws.protocols, ["actioncable-v1-json", "sld_secret"]);
  assert.deepEqual(ws.sent, [{ command: "subscribe", identifier: JSON.stringify({ channel: "UserChannel" }) }]);
  assert.equal(live.status().connected, true);
  live.stop();
});

test("isMessageFrame: no type, chat_id and id", () => {
  assert.equal(isMessageFrame({ id: 1, chat_id: 2 }), true);
  assert.equal(isMessageFrame({ type: "typing", id: 1, chat_id: 2 }), false);
  assert.equal(isMessageFrame({ chat_id: 2 }), false);
});

test("a message frame resolves a pending wait for any chat; the result is the labelled shape", async () => {
  const { live, open } = setup();
  const ws = await open();
  const waiting = live.wait({ timeout_s: 5 });
  await tick();
  ws.data(msg(1, "c1", "hello there"));
  const res = await waiting;
  assert.equal(res.timed_out, false);
  assert.equal(res.messages.length, 1);
  assert.equal(res.messages[0].text, `${DATA_LABEL} hello there`);
  live.stop();
});

test("a wait on one chat ignores other chats", async () => {
  const { live, open } = setup();
  const ws = await open();
  const waiting = live.wait({ chat_id: "c1", timeout_s: 5 });
  await tick();
  ws.data(msg(1, "c2", "elsewhere"));
  await tick();
  ws.data(msg(2, "c1", "here"));
  const res = await waiting;
  assert.deepEqual(res.messages.map((m) => m.id), ["2"]);
  live.stop();
});

test("dedupe by id: the same frame twice is delivered once", async () => {
  const { live, open, notes } = setup();
  const ws = await open();
  await live.watch("c1");
  ws.data(msg(1, "c1", "once"));
  ws.data(msg(1, "c1", "once"));
  await tick(20);
  assert.equal(notes.length, 1);
  live.stop();
});

test("an edit and a tombstone of a known id are delivered as events", async () => {
  const { live, open, notes } = setup();
  const ws = await open();
  await live.watch("c1");
  ws.data(msg(1, "c1", "first"));
  ws.data(msg(1, "c1", "second"));
  ws.data(msg(1, "c1", "second", "ada", { deleted_at: "2026-10-22T11:00:00Z" }));
  await tick(20);
  assert.deepEqual(notes.map((n) => n.meta.event), ["new", "edited", "deleted"]);
  live.stop();
});

test("the owner's own messages are excluded unless from is anyone", async () => {
  const { live, open } = setup();
  const ws = await open();
  const others = live.wait({ chat_id: "c1", timeout_s: 0.05 });
  const anyone = live.wait({ chat_id: "c1", from: "anyone", timeout_s: 5 });
  await tick();
  ws.data(msg(1, "c1", "mine", "me"));
  assert.deepEqual(await others, { messages: [], timed_out: true });
  assert.deepEqual((await anyone).messages.map((m) => m.id), ["1"]);
  live.stop();
});

test("observer and request_state frames are skipped for an unwatched chat, delivered for a watched one", async () => {
  const { live, open, notes } = setup();
  const ws = await open();
  const waiting = live.wait({ timeout_s: 0.05 });
  await tick();
  ws.data(msg(1, "c9", "observed", "ada", { observer: true }));
  ws.data(msg(2, "c9", "request", "ada", { request_state: "pending" }));
  assert.equal((await waiting).timed_out, true);
  await live.watch("c9");
  ws.data(msg(3, "c9", "now watched", "ada", { observer: true }));
  await tick(20);
  assert.deepEqual(notes.map((n) => n.meta.message_id), ["3"]);
  live.stop();
});

test("a wait times out with {messages: [], timed_out: true}", async () => {
  const { live, open } = setup();
  await open();
  assert.deepEqual(await live.wait({ timeout_s: 0.03 }), { messages: [], timed_out: true });
  live.stop();
});

test("a watched chat emits exactly one channel notification, labelled, with the meta; an unwatched chat none", async () => {
  const { live, open, notes } = setup({ meta: async () => ({ name: "Launch crew", newestId: "5" }) });
  const ws = await open();
  assert.deepEqual(await live.watch("c1"), [{ chat_id: "c1", name: "Launch crew" }]);
  ws.data(msg(6, "c1", "ship it"));
  ws.data(msg(7, "c2", "stranger chatter"));
  await tick(20);
  assert.equal(notes.length, 1);
  assert.equal(notes[0].content, `${DATA_LABEL} ship it`);
  assert.deepEqual(notes[0].meta, { chat_id: "c1", chat_name: "Launch crew", message_id: "6", sender: "ada", sender_handle: "@ada", sender_type: "person", time: "2026-10-22T10:00:00Z", event: "new" });
  live.stop();
});

test("after a drop it reconnects, resubscribes and catches up with ?last=<newest id seen>", async () => {
  const served = [msg(11, "c1", "missed while down")];
  const { live, open, gets, notes } = setup({ get: async (p) => (p.includes("?last=") ? { messages: served } : { messages: [] }), meta: async () => ({ name: "C", newestId: "10" }) });
  const ws = await open();
  await live.watch("c1");
  ws.drop();
  await until(() => FakeWS.all.length === 2);
  const second = lastSocket();
  second.hello();
  second.confirm();
  await until(() => notes.length === 1);
  assert.ok(gets.includes("/api/v1/chats/c1?last=10"), gets.join(","));
  assert.equal(notes[0].meta.message_id, "11");
  assert.equal(live.status().reconnects, 1);
  assert.deepEqual(second.protocols, ["actioncable-v1-json", "sld_secret"]);
  live.stop();
});

test("wait with after_message_id returns at once what the catch-up finds", async () => {
  const { live, open, gets } = setup({ get: async () => ({ messages: [msg(21, "c1", "already there")] }) });
  await open();
  const res = await live.wait({ chat_id: "c1", after_message_id: "20", timeout_s: 5 });
  assert.deepEqual(res.messages.map((m) => m.id), ["21"]);
  assert.ok(gets.includes("/api/v1/chats/c1?last=20"));
  live.stop();
});

test("disconnect with reconnect:false stops and the next call surfaces a plain error", async () => {
  const { live, open } = setup();
  const ws = await open();
  const waiting = live.wait({ timeout_s: 5 });
  await tick();
  ws.frame({ type: "disconnect", reason: "unauthorized", reconnect: false });
  await assert.rejects(waiting, /ended the live connection/);
  await assert.rejects(live.wait({ timeout_s: 1 }), /ended the live connection/);
  await tick(30);
  assert.equal(FakeWS.all.length, 1, "no reconnect after a final disconnect");
  assert.match(live.status().error, /unauthorized/);
});

test("no ping for 15 s counts as dead: the socket is closed and a new one opened (liveness, not polling)", async () => {
  const { live, open } = setup({ pingTimeoutMs: 20, livenessCheckMs: 5 });
  const ws = await open();
  await until(() => FakeWS.all.length === 2);
  assert.equal(ws.closed, true);
  live.stop();
});

test("handlers: salt_me_wait over a real session returns labelled text; salt_me_watch pushes a channel notification; tools are read-only", async () => {
  FakeWS.all = [];
  const world = await makeWorld();
  const handlers = createMeHandlers({ session: world.session, host: "https://salt.test", liveOptions: { WebSocketImpl: FakeWS, backoff: { base: 5, max: 20 } } });
  const server = buildMeServer(handlers);
  const client = new Client({ name: "test", version: "0" }, { capabilities: {} });
  const notes = [];
  client.setNotificationHandler(z.object({ method: z.literal("notifications/claude/channel"), params: z.any() }), (n) => notes.push(n.params));
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);

  for (const name of ["salt_me_wait", "salt_me_watch", "salt_me_live_status"]) {
    assert.equal((await client.listTools()).tools.find((t) => t.name === name).annotations.readOnlyHint, true, name);
  }
  assert.ok(client.getServerCapabilities().experimental?.["claude/channel"]);

  const ada = { id: ADA_ID, username: "ada", display_name: "Ada Lovelace", account_type: "User" };
  const waiting = client.callTool({ name: "salt_me_wait", arguments: { chat_id: CHAT_ADA, timeout_s: 5 } });
  await until(() => FakeWS.all.length > 0);
  const ws = lastSocket();
  assert.deepEqual(ws.protocols, ["actioncable-v1-json", "test.jwt.token"]);
  ws.hello();
  ws.confirm();
  await tick(30);
  ws.data(msg(5001, CHAT_ADA, "hi owner", ADA_ID, { user: ada }));
  const body = JSON.parse((await waiting).content[0].text);
  assert.equal(body.timed_out, false);
  assert.equal(body.messages[0].text, `${DATA_LABEL} hi owner`);
  assert.equal(body.messages[0].from.handle, "@ada");

  const watched = JSON.parse((await client.callTool({ name: "salt_me_watch", arguments: { chat_id: CHAT_ADA } })).content[0].text);
  assert.equal(watched.watching[0].chat_id, CHAT_ADA);
  ws.data(msg(5002, CHAT_ADA, "pushed", ADA_ID, { user: ada }));
  ws.data(msg(5003, CHAT_ADA, "my own words", ME_ID, { user: { id: ME_ID, username: "owner", display_name: "Owner", account_type: "User" } }));
  await until(() => notes.length >= 1);
  await tick(30);
  assert.equal(notes.length, 1);
  assert.equal(notes[0].content, `${DATA_LABEL} pushed`);
  const status = JSON.parse((await client.callTool({ name: "salt_me_live_status", arguments: {} })).content[0].text);
  assert.equal(status.connected, true);
  assert.equal(status.watching.length, 1);

  handlers.live.stop();
  await Promise.all([client.close(), server.close()]);
});

const laneMsg = (id, text, extra = {}) => msg(id, "lane-1", text, "agent", { coaching_for_chat_id: "c1", ...extra });

test("a work report in a lane under a WATCHED chat is pushed once as a work notification, never as message text", async () => {
  const { live, open, notes } = setup({ meta: async () => ({ name: "Trip", newestId: "1" }) });
  const ws = await open();
  await live.watch("c1");
  ws.data(laneMsg(30, "[[SALT-WORK id=w_1 status=running]]\nChecking flights"));
  ws.data(laneMsg(30, "[[SALT-WORK id=w_1 status=running]]\nChecking flights"));
  ws.data(laneMsg(31, "just chatter in the lane"));
  ws.data(laneMsg(32, "[[SALT-WORK id=w_1 status=done]]\nBooked", { created_by: "me" }));
  await tick(30);
  assert.equal(notes.length, 1);
  assert.equal(notes[0].meta.kind, "work");
  assert.equal(notes[0].meta.status, "running");
  assert.equal(notes[0].meta.title, "Checking flights");
  assert.equal(notes[0].meta.chat_id, "c1");
  assert.ok(!notes[0].content.includes("SALT-WORK"));
  live.stop();
});

test("a report under an unwatched chat is not pushed; include_work resolves a wait on the parent chat, a plain wait does not", async () => {
  const { live, open, notes } = setup();
  const ws = await open();
  const plain = live.wait({ chat_id: "c1", timeout_s: 0.08 });
  const withWork = live.wait({ chat_id: "c1", include_work: true, timeout_s: 5 });
  await tick();
  ws.data(laneMsg(40, "[[SALT-WORK id=w_9 status=waiting]]\nWhich one?"));
  const res = await withWork;
  assert.equal(res.messages[0].type, "work");
  assert.equal(res.messages[0].status, "waiting");
  assert.deepEqual(await plain, { messages: [], timed_out: true });
  assert.equal(notes.length, 0);
  live.stop();
});
