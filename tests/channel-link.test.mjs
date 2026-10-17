// Link mode of `salt-mcp --channel` (src/channel-link.mjs) against a fake Salt serving the contract's `agent`
// device_links kind. Time and the browser are fakes; the Keychain is a recorder; the directory is a temp one.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadOpenpgp } from "../src/local-decrypt.mjs";
import { createChannelLink, channelLinkEnv, isChannelLinkMode, runChannelUnlink, KEY_PASSPHRASE } from "../src/channel-link.mjs";
import { loadChannelConfig } from "../src/channel.mjs";
import { hostSlug } from "../src/me-link.mjs";

const HOST = "https://api.saltapp.test";
const API_KEY = "sk_agent_secret_0123456789";
const AGENT = { id: "abababab-0000-4000-8000-000000000001", handle: "claude-code-x", name: "Claude Code" };
const OWNER = { id: "0a0a0a0a-0000-4000-8000-000000000002", handle: "owner", name: "Owner" };
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

function setup({ pendingPolls = 2, finalStatus = 200, platform = "darwin", claimBody } = {}) {
  const baseDir = join(mkdtempSync(join(tmpdir(), "salt-chlink-")), "salt-mcp");
  const st = { calls: [], created: null, polls: 0, opened: [], logs: [], commands: [], keychain: new Map() };
  const fetchImpl = async (url, init = {}) => {
    const path = new URL(url).pathname;
    const method = init.method || "GET";
    st.calls.push({ method, path });
    if (method === "POST" && path === "/api/v1/device_links") {
      st.created = JSON.parse(init.body);
      return json({ id: "link-1", poll_secret: "poll-secret", expires_at: new Date(1_000_000 + 15 * 60000).toISOString() }, 201);
    }
    if (method === "POST" && path === "/api/v1/device_links/link-1/claim") {
      assert.equal(JSON.parse(init.body).poll_secret, "poll-secret");
      st.polls++;
      if (st.polls <= pendingPolls) return json({ status: "pending" }, 202);
      if (finalStatus !== 200) return json({ status: "denied" }, finalStatus);
      return json(claimBody ?? { status: "approved", api_key: API_KEY, agent: AGENT, owner: OWNER });
    }
    throw new Error(`unexpected ${method} ${path}`);
  };
  const runCommand = async (file, args, { input } = {}) => {
    st.commands.push({ file, args, input });
    if (args[0] === "-i") {
      const parts = input.trim().split(" ");
      assert.equal(parts[0], "add-generic-password");
      st.keychain.set(`${parts[3]}/${parts[5]}`, parts[7]);
      return "";
    }
    if (args[0] === "find-generic-password") {
      const v = st.keychain.get(`${args[2]}/${args[4]}`);
      if (!v) throw new Error("not found");
      return `${v}\n`;
    }
    if (args[0] === "delete-generic-password") st.keychain.delete(`${args[2]}/${args[4]}`);
    return "";
  };
  const linkOptions = {
    baseDir, hostname: "Test-Mac", fetchImpl, runCommand, platform,
    log: (m) => st.logs.push(m),
    openBrowser: async (url) => { st.opened.push(url); },
    sleep: async () => {},
    now: () => 1_000_000,
  };
  return { st, baseDir, linkOptions };
}

test("link mode is the default for --channel without SALT_API_KEY, or with --link; the env path is untouched", () => {
  assert.equal(isChannelLinkMode(["--channel"], {}), true);
  assert.equal(isChannelLinkMode(["--channel"], { SALT_API_KEY: "  " }), true);
  assert.equal(isChannelLinkMode(["--channel"], { SALT_API_KEY: "k" }), false);
  assert.equal(isChannelLinkMode(["--channel", "--link"], { SALT_API_KEY: "k" }), true);
  assert.equal(isChannelLinkMode([], {}), false);
});

test("a scan makes the agent: kind agent request, QR page opened, polled, secrets in the Keychain via stdin, rest in a 0600 file", async () => {
  const { st, baseDir, linkOptions } = setup();
  const client = createChannelLink({ host: HOST, ...linkOptions });
  assert.equal(await client.load(), null);
  const linked = await client.link();

  assert.equal(st.created.kind, "agent");
  assert.equal(st.created.name, "Claude Code on Test-Mac");
  assert.equal(st.created.agent_name, "Claude Code");
  assert.match(st.created.public_key, /BEGIN PGP PUBLIC KEY BLOCK/);
  assert.equal(st.polls, 3);
  assert.equal(st.opened.length, 1);
  const openpgp = await loadOpenpgp();
  const fp = (await openpgp.readKey({ armoredKey: st.created.public_key })).getFingerprint();
  assert.equal(st.opened[0], `${HOST}/link/show#id=link-1&fp=${fp}&name=${encodeURIComponent("Claude Code on Test-Mac")}`);
  assert.equal(linked.agent.id, AGENT.id);

  // The private key belongs to the public key sent, and opens with the SDK passphrase.
  const key = await openpgp.decryptKey({ privateKey: await openpgp.readPrivateKey({ armoredKey: linked.private_key }), passphrase: KEY_PASSPHRASE });
  assert.equal(key.getFingerprint(), fp);

  const file = join(baseDir, `channel-link-${hostSlug(HOST)}.json`);
  assert.equal(client.path, file);
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.equal(statSync(baseDir).mode & 0o777, 0o700);
  const onDisk = readFileSync(file, "utf8");
  assert.ok(!onDisk.includes(API_KEY) && !onDisk.includes("PRIVATE KEY"), "no secret in the file");
  assert.equal(JSON.parse(onDisk).owner.id, OWNER.id);
  assert.ok([...st.keychain.keys()][0].startsWith("salt-mcp-channel/"));
  for (const c of st.commands) {
    assert.ok(!c.args.join(" ").includes(API_KEY), "no secret on a command line");
    assert.ok(!c.args.join(" ").includes("PGP"), "no key on a command line");
  }
  assert.ok(!st.logs.join("\n").includes(API_KEY) && !st.logs.join("\n").includes("PRIVATE KEY"), "nothing secret logged");

  const again = await createChannelLink({ host: HOST, ...linkOptions }).load();
  assert.equal(again.api_key, API_KEY);
  assert.equal(again.private_key, linked.private_key);
  assert.equal(again.agent.handle, AGENT.handle);
});

test("channelLinkEnv layers the agent identity over a copy of the env and defaults the allow-list to the owner id", async () => {
  const { st, linkOptions } = setup({ pendingPolls: 0 });
  const base = { HOST, PATH: "/bin" };
  const env = await channelLinkEnv({ env: base, linkOptions });
  assert.equal(env.SALT_API_KEY, API_KEY);
  assert.equal(env.SALT_APP_ID, AGENT.id);
  assert.equal(env.SALT_CHANNEL_ALLOW, OWNER.id);
  assert.equal(base.SALT_API_KEY, undefined, "the original env is not touched");
  const cfg = loadChannelConfig(env, ["--channel"]);
  assert.deepEqual([...cfg.allow.ids], [OWNER.id]);

  // A second start reuses the stored link: no new request, no browser.
  st.created = null;
  st.opened.length = 0;
  const env2 = await channelLinkEnv({ env: { HOST }, linkOptions });
  assert.equal(env2.SALT_API_KEY, API_KEY);
  assert.equal(st.created, null);
  assert.equal(st.opened.length, 0);
});

test("an explicit SALT_CHANNEL_ALLOW wins over the owner default", async () => {
  const { linkOptions } = setup({ pendingPolls: 0 });
  const env = await channelLinkEnv({ env: { HOST, SALT_CHANNEL_ALLOW: "@ada" }, linkOptions });
  assert.equal(env.SALT_CHANNEL_ALLOW, "@ada");
});

test("denied, expired or used ends the wait with a message and stores nothing", async () => {
  for (const status of [410, 404]) {
    const { st, baseDir, linkOptions } = setup({ pendingPolls: 1, finalStatus: status });
    const client = createChannelLink({ host: HOST, ...linkOptions });
    await assert.rejects(client.link(), /denied, expired or already used/);
    assert.equal(existsSync(join(baseDir, `channel-link-${hostSlug(HOST)}.json`)), false);
    assert.equal(st.keychain.size, 0);
  }
});

test("an incomplete claim is refused and nothing is stored", async () => {
  const { st, baseDir, linkOptions } = setup({ pendingPolls: 0, claimBody: { status: "approved", agent: AGENT, owner: OWNER } });
  await assert.rejects(createChannelLink({ host: HOST, ...linkOptions }).link(), /incomplete/);
  assert.equal(existsSync(join(baseDir, `channel-link-${hostSlug(HOST)}.json`)), false);
  assert.equal(st.keychain.size, 0);
});

test("off macOS the secrets fall back into the 0600 file, with a line saying so", async () => {
  const { st, baseDir, linkOptions } = setup({ pendingPolls: 0, platform: "linux" });
  const client = createChannelLink({ host: HOST, ...linkOptions });
  await client.link();
  const file = join(baseDir, `channel-link-${hostSlug(HOST)}.json`);
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.ok(st.logs.some((l) => /no macOS Keychain/.test(l)));
  assert.equal(st.commands.length, 0);
  assert.equal((await client.load()).api_key, API_KEY);
});

test("--channel --unlink removes the file and the Keychain item and says to delete the agent in Salt", async () => {
  const { st, baseDir, linkOptions } = setup({ pendingPolls: 0 });
  await createChannelLink({ host: HOST, ...linkOptions }).link();
  assert.equal(st.keychain.size, 1);
  await runChannelUnlink({ env: { HOST }, linkOptions });
  assert.equal(existsSync(join(baseDir, `channel-link-${hostSlug(HOST)}.json`)), false);
  assert.equal(st.keychain.size, 0);
  assert.ok(st.logs.at(-1).includes("Developers"));
  assert.ok(!st.calls.some((c) => c.method === "DELETE"), "there is no self-delete call for an agent");
  await runChannelUnlink({ env: { HOST }, linkOptions });
  assert.match(st.logs.at(-1), /nothing to unlink/);
});

test("an unsafe HOST is refused before anything is requested", async () => {
  const { st, linkOptions } = setup();
  await assert.rejects(channelLinkEnv({ env: { HOST: "http://example.com" }, linkOptions }), /https/);
  assert.equal(st.calls.length, 0);
});
