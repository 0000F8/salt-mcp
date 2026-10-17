// The phone link of --as-me (src/me-link.mjs and link mode in src/me-session.mjs) against a fake Salt that serves the
// contract's device_links / linked_devices endpoints around the same fake world as the other --as-me tests, with
// real openpgp sealing. Time is a fake clock and timer; the browser is a recorder; the directory is a temp one.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadOpenpgp } from "../src/local-decrypt.mjs";
import { createMeSession } from "../src/me-session.mjs";
import { createMeHandlers } from "../src/me-tools.mjs";
import { createLinkClient, hostSlug, LINK_FIRST, POLL_MS } from "../src/me-link.mjs";
import { checkPlatform, runAsMe } from "../src/me-cli.mjs";
import { makeWorld, HOST, CHAT_ADA, ME_ID } from "./me-fixtures.mjs";

const TOKEN = "sld_test-token-0123456789";
const DEVICE_ID = "dddddddd-0000-4000-8000-000000000001";
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

async function setup({ sealWith, sealedFingerprint } = {}) {
  const world = await makeWorld();
  const openpgp = await loadOpenpgp();
  const baseDir = join(mkdtempSync(join(tmpdir(), "salt-link-")), "salt-mcp");
  const st = { links: 0, status: "pending", devicePublicKey: null, unlinked: false, calls: [], deleted: [], opened: [], timers: [], clock: 1_000_000 };

  async function seal() {
    const signer = await openpgp.readPrivateKey({ armoredKey: (sealWith ?? world.keys.me).privateKey });
    const fingerprint = sealedFingerprint ?? world.keys.me.fingerprint;
    return openpgp.encrypt({
      message: await openpgp.createMessage({ text: JSON.stringify({ v: 1, private_key: world.keys.me.privateKey, user_id: ME_ID, fingerprint }) }),
      encryptionKeys: await openpgp.readKey({ armoredKey: st.devicePublicKey }),
      signingKeys: signer,
    });
  }

  const fetchImpl = async (url, init = {}) => {
    const path = new URL(url).pathname;
    const method = init.method || "GET";
    st.calls.push({ method, path, auth: init.headers?.Authorization });
    if (path.startsWith("/auth/") || path === "/api/v1/vault") throw new Error(`link mode must not call ${path}`);
    if (method === "POST" && path === "/api/v1/device_links") {
      st.links++;
      st.devicePublicKey = JSON.parse(init.body).public_key;
      st.name = JSON.parse(init.body).name;
      st.status = "pending";
      return json({ id: `link-${st.links}`, poll_secret: "poll-secret", expires_at: new Date(st.clock + 15 * 60000).toISOString() }, 201);
    }
    if (method === "POST" && /^\/api\/v1\/device_links\/[^/]+\/claim$/.test(path)) {
      if (JSON.parse(init.body).poll_secret !== "poll-secret") return json({}, 404);
      if (st.status === "pending") return json({ status: "pending" }, 202);
      if (st.status === "approved") {
        st.status = "claimed";
        return json({ status: "approved", token: TOKEN, sealed_key: await seal(), user: { id: ME_ID, handle: "owner", name: "Owner" }, linked_device: { id: DEVICE_ID, name: st.name } });
      }
      return json({ status: st.status }, 410);
    }
    if (method === "DELETE" && path === `/api/v1/linked_devices/${DEVICE_ID}`) {
      st.deleted.push(init.headers.Authorization);
      return new Response(null, { status: 204 });
    }
    if (init.headers?.Authorization !== `Bearer ${TOKEN}`) return json({ error: "unauthorized" }, 401);
    if (st.unlinked) return json({ error: "This computer was unlinked.", code: "device_unlinked" }, 401);
    const res = await world.fetchImpl(url, { ...init, headers: { ...init.headers, Authorization: "Bearer test.jwt.token" } });
    if (path === "/api/v1/userkeys") return json({ ...(await res.json()), public_key: world.keys.me.publicKey });
    return res;
  };

  const linkOptions = {
    baseDir, hostname: "Test-Mac", fetchImpl,
    openBrowser: async (url) => { st.opened.push(url); },
    setTimer: (fn, ms) => { st.timers.push({ fn, ms }); return st.timers.length; },
    clearTimer: () => {},
    now: () => st.clock,
  };
  const linkClient = createLinkClient({ host: HOST, ...linkOptions });
  const session = createMeSession({ host: HOST, fetchImpl, linkClient });
  /** Runs the next scheduled poll, as the 3 s timer would. */
  const tick = async () => { const t = st.timers.shift(); assert.equal(t.ms, POLL_MS); await t.fn(); };
  return { world, st, linkClient, session, linkOptions, tick, fetchImpl, baseDir };
}

const linkFirst = (p) => assert.rejects(p, (err) => err.kind === "link_pending" && err.message === LINK_FIRST);

test("first use opens the code page and returns at once; a second call reuses the pending link", async () => {
  const { st, session } = await setup();
  await linkFirst(session.get("/api/v1/chats"));
  assert.equal(st.opened.length, 1);
  const url = new URL(st.opened[0]);
  assert.equal(`${url.origin}${url.pathname}`, `${HOST}/link/show`);
  const frag = new URLSearchParams(url.hash.slice(1));
  assert.equal(frag.get("id"), "link-1");
  assert.match(frag.get("fp"), /^[0-9a-f]{40}$/i);
  assert.equal(frag.get("name"), "Claude on Test-Mac");
  await linkFirst(session.get("/api/v1/chats"));
  assert.equal(st.links, 1, "no second link was started");
  assert.equal(st.opened.length, 1);
});

test("approval: polled every 3 s, stored 0600 in a 0700 directory, then every call carries the sld_ token and never signs in", async () => {
  const { st, session, linkClient, tick, baseDir, world } = await setup();
  await linkFirst(session.get("/api/v1/chats"));
  await tick();
  await tick();
  assert.equal(existsSync(linkClient.path), false, "still pending: nothing stored");
  st.status = "approved";
  await tick();
  assert.equal(st.timers.length, 0, "polling stopped");
  assert.match(linkClient.path, /link-salt-test\.json$/);
  assert.equal(statSync(linkClient.path).mode & 0o777, 0o600);
  assert.equal(statSync(baseDir).mode & 0o777, 0o700);
  assert.deepEqual(readdirSync(baseDir), ["link-salt-test.json"], "no temp file left");
  const stored = JSON.parse(readFileSync(linkClient.path, "utf8"));
  assert.equal(stored.v, 1);
  assert.equal(stored.token, TOKEN);
  assert.deepEqual(stored.linked_device, { id: DEVICE_ID, name: "Claude on Test-Mac" });
  assert.ok(stored.device_private_key && stored.sealed_key && stored.linked_at);

  const handlers = createMeHandlers({ session, host: HOST });
  const chat = await handlers.callTool("salt_me_read_chat", { chat_id: CHAT_ADA, limit: 3 });
  assert.match(JSON.stringify(chat), /message number/);
  assert.ok(st.calls.filter((c) => c.path.startsWith("/api/v1/chats")).every((c) => c.auth === `Bearer ${TOKEN}`));
  assert.ok(world.requests.length > 0);
  const who = await handlers.callTool("salt_me_whoami", {});
  assert.equal(who.linked, true);
  assert.equal(who.device_name, "Claude on Test-Mac");
  assert.equal(who.linked_at, stored.linked_at);
  assert.ok(!JSON.stringify(who).includes(TOKEN));
});

test("whoami before linking says linked: false", async () => {
  const { session } = await setup();
  const who = await createMeHandlers({ session, host: HOST }).callTool("salt_me_whoami", {});
  assert.equal(who.linked, false);
  assert.equal(who.device_name, null);
});

test("--read-only still removes the send tool in link mode", async () => {
  const { session } = await setup();
  assert.ok(!createMeHandlers({ session, host: HOST, readOnly: true }).listTools().some((t) => t.name === "salt_me_send"));
});

test("denied, expired or claimed ends the polling; the next call starts a fresh link", async () => {
  const { st, session, tick } = await setup();
  await linkFirst(session.get("/api/v1/chats"));
  st.status = "denied";
  await tick();
  assert.equal(st.timers.length, 0);
  await linkFirst(session.get("/api/v1/chats"));
  assert.equal(st.links, 2);
  assert.equal(st.opened.length, 2);
});

test("a link that outlives its expiry stops polling", async () => {
  const { st, session, tick } = await setup();
  await linkFirst(session.get("/api/v1/chats"));
  st.clock += 16 * 60000;
  await tick();
  assert.equal(st.timers.length, 0);
});

test("a sealed key not signed by the owner's key is refused and nothing is stored", async () => {
  const { world } = await setup();
  const { st, session, linkClient, tick } = await setup({ sealWith: world.keys.stranger });
  await linkFirst(session.get("/api/v1/chats"));
  st.status = "approved";
  await tick();
  assert.equal(existsSync(linkClient.path), false);
  assert.equal(st.timers.length, 0);
});

test("a fingerprint in the sealed key that is not the owner's is refused and nothing is stored", async () => {
  const { st, session, linkClient, tick } = await setup({ sealedFingerprint: "0".repeat(40) });
  await linkFirst(session.get("/api/v1/chats"));
  st.status = "approved";
  await tick();
  assert.equal(existsSync(linkClient.path), false);
});

test("401 device_unlinked deletes the link file and the next call starts linking", async () => {
  const { st, session, linkClient, tick } = await setup();
  await linkFirst(session.get("/api/v1/chats"));
  st.status = "approved";
  await tick();
  await session.get("/api/v1/chats");
  assert.ok(existsSync(linkClient.path));
  st.unlinked = true;
  await linkFirst(session.get("/api/v1/chats"));
  assert.equal(existsSync(linkClient.path), false);
  assert.equal(st.links, 2, "a new link was started");
});

test("a restart with a stored link opens it with no browser and no sign-in", async () => {
  const { st, session, linkClient, tick, linkOptions, fetchImpl } = await setup();
  await linkFirst(session.get("/api/v1/chats"));
  st.status = "approved";
  await tick();
  const again = createMeSession({ host: HOST, fetchImpl, linkClient: createLinkClient({ host: HOST, ...linkOptions }) });
  st.opened.length = 0;
  await again.get("/api/v1/chats");
  assert.equal(st.opened.length, 0);
  assert.equal(st.links, 1);
  assert.ok(linkClient.read());
});

test("--unlink deletes the device with its own token and removes the file; the client falls back to the file alone without an id", async () => {
  const { st, session, linkClient, tick, linkOptions } = await setup();
  await linkFirst(session.get("/api/v1/chats"));
  st.status = "approved";
  await tick();
  await runAsMe({ argv: ["--as-me", "--unlink"], env: { HOST }, platform: "linux", linkOptions });
  assert.deepEqual(st.deleted, [`Bearer ${TOKEN}`]);
  assert.equal(existsSync(linkClient.path), false);
  assert.equal(await linkClient.unlinkRemote({ token: TOKEN }), false);
});

test("the link needs no password dialog, so it runs anywhere; the password path still needs one off macOS", () => {
  assert.doesNotThrow(() => checkPlatform({ platform: "linux", env: {}, password: false }));
  assert.throws(() => checkPlatform({ platform: "linux", env: {}, password: true }));
});

test("the host slug keeps the port so a local server has its own link", () => {
  assert.equal(hostSlug("https://saltapp.ai"), "saltapp-ai");
  assert.equal(hostSlug("http://127.0.0.1:3000"), "127-0-0-1-3000");
});
