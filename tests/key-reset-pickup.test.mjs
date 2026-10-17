// Key-reset phase 2: a linked computer picks up a v2 re-seal (dual signature, user_id, ack), reads old and new history,
// and on 409 pickup_required picks up and retries the send once.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadOpenpgp } from "../src/local-decrypt.mjs";
import { createLinkClient, hostSlug } from "../src/me-link.mjs";
import { createMeSession } from "../src/me-session.mjs";
import { encryptForKeys } from "../src/me-crypto.mjs";

const HOST = "https://salt.test";
const TOKEN = "sld_pickup-token-0123456789";
const USER = { id: "user-1", handle: "owner", name: "Owner" };
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

async function genKey() {
  const openpgp = await loadOpenpgp();
  const { privateKey, publicKey } = await openpgp.generateKey({ type: "ecc", curve: "curve25519", userIDs: [{ name: "t" }], format: "armored" });
  return { privateKey, publicKey, fingerprint: (await openpgp.readKey({ armoredKey: publicKey })).getFingerprint() };
}

const entry = (k, generation, active) => ({ private_key: k.privateKey, fingerprint: k.fingerprint, generation, active });

async function seal(payload, device, signers) {
  const openpgp = await loadOpenpgp();
  return openpgp.encrypt({
    message: await openpgp.createMessage({ text: JSON.stringify(payload) }),
    encryptionKeys: await openpgp.readKey({ armoredKey: device.publicKey }),
    signingKeys: await Promise.all(signers.map((s) => openpgp.readPrivateKey({ armoredKey: s.privateKey }))),
  });
}

async function setup() {
  const openpgp = await loadOpenpgp();
  const [device, oldK, newK, stranger] = await Promise.all([genKey(), genKey(), genKey(), genKey()]);
  const baseDir = join(mkdtempSync(join(tmpdir(), "salt-pickup-")), "salt-mcp");
  mkdirSync(baseDir, { mode: 0o700 });
  const heldSealed = await seal({ v: 1, private_key: oldK.privateKey, user_id: USER.id, fingerprint: oldK.fingerprint }, device, [oldK]);
  const st = { serverKey: oldK, pending: null, acked: [], posts: 0, ackedOnce: false, sendAnswers: [], calls: [] };
  const file = join(baseDir, `link-${hostSlug(HOST)}.json`);
  writeFileSync(file, JSON.stringify({ v: 1, host: HOST, token: TOKEN, device_private_key: device.privateKey, key_store: "file", sealed_key: heldSealed, user: USER, linked_device: { id: "dev-1", name: "Claude on Test" }, linked_at: "2026-10-01T00:00:00Z" }), { mode: 0o600 });

  const fetchImpl = async (url, init = {}) => {
    const path = new URL(url).pathname;
    const method = init.method || "GET";
    st.calls.push(`${method} ${path}`);
    if (init.headers?.Authorization !== `Bearer ${TOKEN}`) return json({ error: "unauthorized" }, 401);
    if (path === "/api/v1/userkeys") return json({ public_key: st.serverKey.publicKey, public_fingerprint: st.serverKey.fingerprint });
    if (method === "GET" && path === "/api/v1/linked_devices/self/sealed_key") return st.pending ? json(st.pending) : new Response(null, { status: 204 });
    if (method === "POST" && path === "/api/v1/linked_devices/self/sealed_key/ack") {
      st.acked.push(JSON.parse(init.body).generation);
      st.pending = null;
      return new Response(null, { status: 204 });
    }
    if (method === "POST" && path === "/api/v1/messages") {
      st.posts++;
      if (st.mustPickup && !st.acked.length) return json({ code: "pickup_required", error: "Open Salt on your phone." }, 409);
      return json({ id: "m1" }, 201);
    }
    return json({}, 404);
  };
  const mk = () => createLinkClient({ host: HOST, baseDir, fetchImpl, platform: "linux", log: () => {} });
  const linkClient = mk();
  const pend = async (payload, signers, generation = 2) => {
    st.pending = { sealed_key: await seal(payload, device, signers), generation };
  };
  const v2 = (keys, userId = USER.id) => ({ v: 2, user_id: userId, keys });
  return { st, device, oldK, newK, stranger, linkClient, fetchImpl, mk, file, pend, v2, openpgp, stored: () => JSON.parse(readFileSync(file, "utf8")) };
}

test("pickup: a v2 re-seal signed by the held generation AND the new key is stored and acked; old and new history both read", async () => {
  const t = await setup();
  await t.pend(t.v2([entry(t.newK, 2, true), entry(t.oldK, 1, false)]), [t.oldK, t.newK]);
  const out = await t.linkClient.pickup(t.linkClient.read());
  assert.deepEqual(out, { status: "picked_up", generation: 2 });
  assert.deepEqual(t.st.acked, [2]);
  const file = t.stored();
  assert.equal(file.sealed_key_generation, 2);
  assert.equal(file.held_fingerprint, t.newK.fingerprint);

  // A fresh session on the stored link decrypts a message to the new key and one to the old key.
  t.st.serverKey = t.newK;
  const session = createMeSession({ host: HOST, fetchImpl: t.fetchImpl, linkClient: t.mk() });
  const toNew = await encryptForKeys("hello new", [t.newK.publicKey]);
  const toOld = await encryptForKeys("hello old", [t.oldK.publicKey]);
  assert.equal(await session.decrypt(toNew), "hello new");
  assert.equal(await session.decrypt(toOld), "hello old");
});

test("pickup refuses a payload signed only by the new key (a planted key): nothing stored, nothing acked", async () => {
  const t = await setup();
  const before = t.stored();
  await t.pend(t.v2([entry(t.stranger, 2, true), entry(t.oldK, 1, false)]), [t.stranger]);
  const out = await t.linkClient.pickup(t.linkClient.read());
  assert.equal(out.status, "refused");
  assert.deepEqual(t.st.acked, []);
  assert.deepEqual(t.stored(), before);
});

test("pickup refuses a payload signed only by the held generation (the new key never vouched for itself)", async () => {
  const t = await setup();
  await t.pend(t.v2([entry(t.newK, 2, true), entry(t.oldK, 1, false)]), [t.oldK]);
  assert.equal((await t.linkClient.pickup(t.linkClient.read())).status, "refused");
  assert.deepEqual(t.st.acked, []);
});

test("pickup refuses a payload for a different user_id", async () => {
  const t = await setup();
  await t.pend(t.v2([entry(t.newK, 2, true), entry(t.oldK, 1, false)], "someone-else"), [t.oldK, t.newK]);
  assert.equal((await t.linkClient.pickup(t.linkClient.read())).status, "refused");
  assert.deepEqual(t.st.acked, []);
  assert.equal(t.stored().sealed_key_generation, undefined);
});

test("pickup refuses a payload whose key does not match its fingerprint, or that drops the held key", async () => {
  const t = await setup();
  await t.pend(t.v2([{ ...entry(t.newK, 2, true), fingerprint: "0".repeat(40) }, entry(t.oldK, 1, false)]), [t.oldK, t.newK]);
  assert.equal((await t.linkClient.pickup(t.linkClient.read())).status, "refused");
  await t.pend(t.v2([entry(t.newK, 2, true)]), [t.oldK, t.newK]);
  assert.equal((await t.linkClient.pickup(t.linkClient.read())).status, "refused");
  assert.deepEqual(t.st.acked, []);
});

test("nothing pending is not an error; a 401 device_unlinked is surfaced", async () => {
  const t = await setup();
  assert.deepEqual(await t.linkClient.pickup(t.linkClient.read()), { status: "none" });
  const gone = createLinkClient({ host: HOST, baseDir: join(tmpdir(), "x"), platform: "linux", log: () => {}, fetchImpl: async () => json({ code: "device_unlinked" }, 401) });
  await assert.rejects(gone.pickup({ token: TOKEN, sealed_key: "x", device_private_key: "x" }), (e) => e.kind === "unlinked");
});

test("unlocking picks up a waiting re-seal first, even while the server already serves the new key", async () => {
  const t = await setup();
  t.st.serverKey = t.newK;
  await t.pend(t.v2([entry(t.newK, 2, true), entry(t.oldK, 1, false)]), [t.oldK, t.newK]);
  const session = createMeSession({ host: HOST, fetchImpl: t.fetchImpl, linkClient: t.linkClient });
  assert.equal(await session.decrypt(await encryptForKeys("fresh", [t.newK.publicKey])), "fresh");
  assert.deepEqual(t.st.acked, [2]);
});

test("a stored link still opens after the server moved to a new key and before pickup: old history reads (links made before this release too)", async () => {
  const t = await setup();
  t.st.serverKey = t.newK; // reset happened, nothing picked up yet, nothing pending
  const session = createMeSession({ host: HOST, fetchImpl: t.fetchImpl, linkClient: t.linkClient });
  assert.equal(await session.decrypt(await encryptForKeys("old", [t.oldK.publicKey])), "old");
  // But a stored payload signed by neither the server's key nor its own is not trusted.
  const bad = await setup();
  bad.st.serverKey = bad.newK;
  writeFileSync(bad.file, JSON.stringify({ ...bad.stored(), sealed_key: await seal({ v: 1, private_key: bad.oldK.privateKey, user_id: USER.id, fingerprint: bad.oldK.fingerprint }, bad.device, [bad.stranger]) }), { mode: 0o600 });
  await assert.rejects(createMeSession({ host: HOST, fetchImpl: bad.fetchImpl, linkClient: bad.mk() }).decrypt("x"));
});

test("409 pickup_required on a send: pick up, then retry once", async () => {
  const t = await setup();
  const session = createMeSession({ host: HOST, fetchImpl: t.fetchImpl, linkClient: t.linkClient });
  await session.decrypt("plain"); // unlock: nothing pending yet
  assert.deepEqual(t.st.acked, []);
  t.st.mustPickup = true;
  t.st.serverKey = t.newK;
  await t.pend(t.v2([entry(t.newK, 2, true), entry(t.oldK, 1, false)]), [t.oldK, t.newK]);
  const posted = await session.post("/api/v1/messages", { chat_id: "c", message: "hi" });
  assert.equal(posted.id, "m1");
  assert.equal(t.st.posts, 2, "one refused, one retried");
  assert.deepEqual(t.st.acked, [2]);
});

test("409 pickup_required with a refused pickup does not loop: the send fails after one try", async () => {
  const t = await setup();
  const session = createMeSession({ host: HOST, fetchImpl: t.fetchImpl, linkClient: t.linkClient });
  await session.decrypt("plain");
  t.st.mustPickup = true;
  await t.pend(t.v2([entry(t.stranger, 2, true), entry(t.oldK, 1, false)]), [t.stranger]);
  await assert.rejects(session.post("/api/v1/messages", { chat_id: "c", message: "hi" }), (e) => e.status === 409);
  assert.equal(t.st.posts, 1);
});
