// The phone link of --as-me (src/me-link.mjs and link mode in src/me-session.mjs) against a fake Salt that serves the
// contract's device_links / linked_devices endpoints around the same fake world as the other --as-me tests, with
// real openpgp sealing. Time is a fake clock and timer; the browser is a recorder; the directory is a temp one.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { join } from "node:path";
import { loadOpenpgp } from "../src/local-decrypt.mjs";
import { createMeSession } from "../src/me-session.mjs";
import { createMeHandlers } from "../src/me-tools.mjs";
import { renderLinkPage } from "../src/link-store.mjs";
import { createLinkClient, hostSlug, LINK_FIRST, POLL_MS } from "../src/me-link.mjs";
import { checkPlatform, runAsMe } from "../src/me-cli.mjs";
import { makeWorld, HOST, CHAT_ADA, ME_ID } from "./me-fixtures.mjs";

const TOKEN = "sld_test-token-0123456789";
const DEVICE_ID = "dddddddd-0000-4000-8000-000000000001";
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

async function setup({ sealWith, sealedFingerprint, sealedUserId = ME_ID, pinHandle = null, platform = "darwin" } = {}) {
  const world = await makeWorld();
  const openpgp = await loadOpenpgp();
  const baseDir = join(mkdtempSync(join(tmpdir(), "salt-link-")), "salt-mcp");
  const st = { keychain: new Map(), commands: [], logs: [], links: 0, status: "pending", devicePublicKey: null, unlinked: false, calls: [], deleted: [], opened: [], pages: [], timers: [], clock: 1_000_000 };

  async function seal() {
    const signer = await openpgp.readPrivateKey({ armoredKey: (sealWith ?? world.keys.me).privateKey });
    const fingerprint = sealedFingerprint ?? world.keys.me.fingerprint;
    return openpgp.encrypt({
      message: await openpgp.createMessage({ text: JSON.stringify({ v: 1, private_key: world.keys.me.privateKey, user_id: sealedUserId, fingerprint }) }),
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

  // A fake macOS keychain behind `security`, recording every command line and stdin so a test can look for the secret.
  const runCommand = async (file, args, { input } = {}) => {
    st.commands.push({ file, args, input });
    if (file === "/usr/bin/security" && args[0] === "-i") {
      const [, , , service, , account, , b64] = input.trim().split(" ");
      assert.equal(input.trim().split(" ")[0], "add-generic-password");
      st.keychain.set(`${service}/${account}`, b64);
      return "";
    }
    if (file === "/usr/bin/security" && args[0] === "find-generic-password") {
      const v = st.keychain.get(`${args[2]}/${args[4]}`);
      if (!v) throw new Error("not found");
      return `${v}\n`;
    }
    if (file === "/usr/bin/security" && args[0] === "delete-generic-password") {
      st.keychain.delete(`${args[2]}/${args[4]}`);
      return "";
    }
    return "";
  };

  const linkOptions = {
    pinHandle, runCommand, platform, log: (m) => st.logs.push(m),
    baseDir, hostname: "Test-Mac", fetchImpl,
    openBrowser: async (url) => { st.opened.push(url); const f = fileURLToPath(url); st.pages.push({ html: readFileSync(f, "utf8"), fileMode: statSync(f).mode & 0o777, dirMode: statSync(dirname(f)).mode & 0o777 }); },
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
  assert.match(st.opened[0], /^file:\/\/\/.*salt-link-[^/]+\/link\.html$/);
  assert.ok(!st.opened[0].includes("/link/show"), "no web page of Salt draws the code");
  const page = st.pages[0];
  assert.equal(page.fileMode, 0o600);
  assert.equal(page.dirMode, 0o700);
  assert.match(page.html, /<svg/);
  assert.match(page.html, /<title>Link this computer<\/title>/);
  assert.match(page.html, /Claude on Test-Mac/);
  assert.match(page.html, /On your phone, open Salt's menu, tap Devices, then Link a computer, and scan this\./);
  assert.ok(!page.html.includes(TOKEN) && !page.html.includes("poll-secret") && !page.html.includes("PRIVATE KEY"));
  // The code carries {host}/link/<id>/<fp>: decode-free check by re-rendering the same value.
  const fp = (await (await loadOpenpgp()).readKey({ armoredKey: st.devicePublicKey })).getFingerprint();
  assert.equal(page.html, renderLinkPage({ value: `${HOST}/link/link-1/${fp}`, name: "Claude on Test-Mac" }));
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
  assert.ok(stored.sealed_key && stored.linked_at);
  assert.equal(stored.device_private_key, undefined, "the device key is not in the file");
  assert.equal(stored.key_store, "keychain");
  assert.equal(st.keychain.size, 1);

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
  assert.deepEqual(st.deleted, [`Bearer ${TOKEN}`], "the token just issued was cancelled");
  assert.equal(st.keychain.size, 0);
});

test("a fingerprint in the sealed key that is not the owner's is refused and nothing is stored", async () => {
  const { st, session, linkClient, tick } = await setup({ sealedFingerprint: "0".repeat(40) });
  await linkFirst(session.get("/api/v1/chats"));
  st.status = "approved";
  await tick();
  assert.equal(existsSync(linkClient.path), false);
  assert.deepEqual(st.deleted, [`Bearer ${TOKEN}`]);
});

test("a sealed key for a different user id than the claim's is refused, stored nowhere, and the token cancelled", async () => {
  const { st, session, linkClient, tick } = await setup({ sealedUserId: "someone-else" });
  await linkFirst(session.get("/api/v1/chats"));
  st.status = "approved";
  await tick();
  assert.equal(existsSync(linkClient.path), false);
  assert.equal(st.keychain.size, 0);
  assert.deepEqual(st.deleted, [`Bearer ${TOKEN}`]);
});

test("SALT_ME_HANDLE pins the account: another handle is refused and cancelled, the right one (with or without @) links", async () => {
  const wrong = await setup({ pinHandle: "somebody" });
  await linkFirst(wrong.session.get("/api/v1/chats"));
  wrong.st.status = "approved";
  await wrong.tick();
  assert.equal(existsSync(wrong.linkClient.path), false);
  assert.deepEqual(wrong.st.deleted, [`Bearer ${TOKEN}`]);
  const right = await setup({ pinHandle: "@Owner" });
  await linkFirst(right.session.get("/api/v1/chats"));
  right.st.status = "approved";
  await right.tick();
  assert.ok(existsSync(right.linkClient.path));
  assert.deepEqual(right.st.deleted, []);
});

test("the device key goes to the Keychain through stdin: never on a command line, not in the file; unlink removes both; the file is excluded from backups", async () => {
  const { st, session, linkClient, tick, linkOptions } = await setup();
  await linkFirst(session.get("/api/v1/chats"));
  st.status = "approved";
  await tick();
  const [, b64] = [...st.keychain.entries()][0];
  const armored = Buffer.from(b64, "base64").toString("utf8");
  assert.match(armored, /BEGIN PGP PRIVATE KEY BLOCK/);
  assert.deepEqual([...st.keychain.keys()], ["salt-mcp-link/salt-test"]);
  for (const c of st.commands) {
    const argv = [c.file, ...c.args].join(" ");
    assert.ok(!argv.includes(b64) && !argv.includes("PRIVATE KEY") && !argv.includes(armored.slice(60, 100)), "no secret in argv");
  }
  assert.ok(st.commands.some((c) => c.args[0] === "-i" && c.input.includes(b64)), "the secret went in on stdin");
  assert.ok(!readFileSync(linkClient.path, "utf8").includes("PRIVATE KEY"));
  assert.ok(st.commands.some((c) => c.file === "/usr/bin/tmutil" && c.args[0] === "addexclusion" && c.args[1] === linkClient.path));
  await runAsMe({ argv: ["--as-me", "--unlink"], env: { HOST }, platform: "darwin", linkOptions });
  assert.equal(existsSync(linkClient.path), false);
  assert.equal(st.keychain.size, 0);
});

test("a Keychain that will not take the key refuses the link and cancels the token", async () => {
  const { st, tick, linkOptions } = await setup();
  const failing = createLinkClient({ host: HOST, ...linkOptions, runCommand: async () => { throw new Error("locked"); } });
  const s2 = createMeSession({ host: HOST, fetchImpl: linkOptions.fetchImpl, linkClient: failing });
  await linkFirst(s2.get("/api/v1/chats"));
  st.status = "approved";
  await tick();
  assert.equal(existsSync(failing.path), false);
  assert.deepEqual(st.deleted, [`Bearer ${TOKEN}`]);
});

test("off macOS the device key falls back to the file, with a line saying so", async () => {
  const { st, session, linkClient, tick } = await setup({ platform: "linux" });
  await linkFirst(session.get("/api/v1/chats"));
  st.status = "approved";
  await tick();
  assert.ok(JSON.parse(readFileSync(linkClient.path, "utf8")).device_private_key);
  assert.equal(st.keychain.size, 0);
  assert.ok(st.logs.some((l) => /no macOS Keychain/.test(l)));
  await session.get("/api/v1/chats");
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
  assert.equal(st.keychain.size, 0, "the Keychain item went too");
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

test("after a link, stderr names the account and the first tool result starts with one line saying so; later results do not", async () => {
  const { st, session, tick } = await setup();
  await linkFirst(session.get("/api/v1/chats"));
  st.status = "approved";
  await tick();
  assert.ok(st.logs.includes("Linked as @owner (Owner)"));
  const handlers = createMeHandlers({ session, host: HOST });
  const first = await handlers.callTool("salt_me_list_chats", {});
  assert.equal(first.content[0].text, "Linked to Salt as @owner.");
  assert.ok(first.content.length > 1);
  const second = await handlers.callTool("salt_me_list_chats", {});
  assert.ok(Array.isArray(second) || !second.content?.[0]?.text?.startsWith("Linked to Salt"));
});

test("self-pin: the first reopen writes the linked handle into the file; a reopened file for another user is refused, as is a different SALT_ME_HANDLE", async () => {
  const { st, session, linkClient, tick, linkOptions, fetchImpl } = await setup();
  await linkFirst(session.get("/api/v1/chats"));
  st.status = "approved";
  await tick();
  assert.equal(linkClient.read().pin_handle, undefined);
  await session.get("/api/v1/chats");
  assert.equal(linkClient.read().pin_handle, "owner");
  const reopen = (extra = {}) => createMeSession({ host: HOST, fetchImpl, linkClient: createLinkClient({ host: HOST, ...linkOptions, ...extra }) });
  await reopen().get("/api/v1/chats");
  await assert.rejects(reopen({ pinHandle: "somebody" }).get("/api/v1/chats"), /different account/);
  const file = JSON.parse(readFileSync(linkClient.path, "utf8"));
  file.user.handle = "mallory";
  (await import("node:fs")).writeFileSync(linkClient.path, JSON.stringify(file));
  await assert.rejects(reopen().get("/api/v1/chats"), /different account/);
});

test("the code page's temp dir is deleted when the link reaches a final state; an open failure puts the path in stderr and the message", async () => {
  const { st, session, tick, linkOptions } = await setup();
  await linkFirst(session.get("/api/v1/chats"));
  const dir = dirname(fileURLToPath(st.opened[0]));
  assert.ok(existsSync(dir));
  st.status = "denied";
  await tick();
  assert.equal(existsSync(dir), false);

  const failing = await setup();
  failing.linkOptions.openBrowser = async () => { throw new Error("no browser"); };
  const client = createLinkClient({ host: HOST, ...failing.linkOptions });
  const started = await client.begin();
  assert.equal(started.opened, false);
  assert.ok(existsSync(started.url) && started.url.endsWith("link.html"));
  assert.ok(failing.st.logs.some((l) => l.includes(started.url)));
  client.cancel();
  assert.equal(existsSync(started.url), false);
});
