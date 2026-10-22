// The entry point of --as-me: the platform and host checks, and a real stdio process speaking MCP against a local
// stand-in for Salt -- including the sign-out when the client goes away.

import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { checkPlatform, assertSafeHost, AsMeStartError } from "../src/me-cli.mjs";
import { DEFAULT_HOST } from "../src/me-session.mjs";
import { makeWorld, EMAIL, PASSWORD, CHAT_ADA } from "./me-fixtures.mjs";

test("--as-me refuses to start off macOS unless SALT_ME_PASSWORD_CMD is set", () => {
  assert.throws(() => checkPlatform({ platform: "linux", env: {} }), (err) => err instanceof AsMeStartError && /SALT_ME_PASSWORD_CMD/.test(err.message));
  assert.throws(() => checkPlatform({ platform: "win32", env: {} }), AsMeStartError);
  assert.doesNotThrow(() => checkPlatform({ platform: "linux", env: { SALT_ME_PASSWORD_CMD: "secret-tool lookup salt pw" } }));
  assert.doesNotThrow(() => checkPlatform({ platform: "darwin", env: {} }));
});

test("the default host is the origin the Salt website uses", () => {
  assert.equal(DEFAULT_HOST, "https://saltapp.ai");
});

test("the sign-in only goes to an https host, or one on this computer", () => {
  assert.doesNotThrow(() => assertSafeHost("https://saltapp.ai", {}));
  assert.doesNotThrow(() => assertSafeHost("http://localhost:3000", {}));
  assert.doesNotThrow(() => assertSafeHost("http://127.0.0.1:9", {}));
  assert.throws(() => assertSafeHost("http://salt.example", {}), /https/);
  assert.throws(() => assertSafeHost("not a url", {}), /web address/);
});

test("it refuses to start with certificate checking weakened, unless the host is on this computer", () => {
  assert.throws(() => assertSafeHost("https://saltapp.ai", { NODE_TLS_REJECT_UNAUTHORIZED: "0" }), (err) => err instanceof AsMeStartError && /NODE_TLS_REJECT_UNAUTHORIZED/.test(err.message));
  assert.throws(() => assertSafeHost("https://saltapp.ai", { NODE_EXTRA_CA_CERTS: "/tmp/mitm.pem" }), AsMeStartError);
  assert.doesNotThrow(() => assertSafeHost("https://saltapp.ai", { NODE_TLS_REJECT_UNAUTHORIZED: "1" }));
  assert.doesNotThrow(() => assertSafeHost("http://localhost:3000", { NODE_TLS_REJECT_UNAUTHORIZED: "0", NODE_EXTRA_CA_CERTS: "/x" }));
});

/** A real HTTP server in front of the fake Salt, so a spawned salt-mcp can talk to it. */
async function serveWorld(world) {
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = chunks.length ? Buffer.concat(chunks).toString() : undefined;
    const r = await world.fetchImpl(`http://127.0.0.1${req.url}`, { method: req.method, headers: { Authorization: req.headers.authorization }, body });
    res.writeHead(r.status, Object.fromEntries(r.headers));
    res.end(Buffer.from(await r.arrayBuffer()));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { server, host: `http://127.0.0.1:${server.address().port}` };
}

const spawnClient = (args, env) =>
  new StdioClientTransport({ command: process.execPath, args: ["src/index.mjs", ...args], env: { PATH: process.env.PATH, ...env }, stderr: "pipe" });

test("a real `salt-mcp --as-me --read-only` process: nine read tools, nothing asked until used, a clean sign-out when the client leaves", async () => {
  const world = await makeWorld({ authIterations: 600000 });
  const { server, host } = await serveWorld(world);
  const transport = spawnClient(["--as-me", "--read-only"], { SALT_ME_EMAIL: EMAIL, SALT_ME_PASSWORD_CMD: `printf %s '${PASSWORD}'`, HOST: host });
  const client = new Client({ name: "test", version: "0" }, { capabilities: {} });
  const stderr = [];
  await client.connect(transport);
  transport.stderr?.on("data", (d) => stderr.push(String(d)));
  try {
    const tools = (await client.listTools()).tools.map((t) => t.name).sort();
    assert.deepEqual(tools, ["salt_me_find_chat", "salt_me_list_chats", "salt_me_live_status", "salt_me_read_attachment", "salt_me_read_chat", "salt_me_wait", "salt_me_watch", "salt_me_whoami", "salt_me_work"]);
    assert.equal(world.requests.length, 0, "listing tools touches no network");
    const who = JSON.parse((await client.callTool({ name: "salt_me_whoami", arguments: {} })).content[0].text);
    assert.equal(who.unlocked, false);
    assert.equal(world.requests.length, 0);

    const chat = await client.callTool({ name: "salt_me_read_chat", arguments: { chat_id: CHAT_ADA, limit: 3 } });
    assert.match(chat.content[0].text, /message number 25/);
    assert.equal(world.state.signIns, 1);
    assert.equal(world.state.signOuts, 0);
  } finally {
    await client.close();
  }
  for (let i = 0; i < 100 && world.state.signOuts === 0; i++) await new Promise((r) => setTimeout(r, 50));
  assert.equal(world.state.signOuts, 1, "the session was revoked on exit");
  assert.ok(!stderr.join("").includes(PASSWORD));
  server.close();
});

test("a real process with nothing signed in leaves without calling sign-out", async () => {
  const world = await makeWorld();
  const { server, host } = await serveWorld(world);
  const client = new Client({ name: "test", version: "0" }, { capabilities: {} });
  await client.connect(spawnClient(["--as-me"], { SALT_ME_EMAIL: EMAIL, SALT_ME_PASSWORD_CMD: "echo x", HOST: host }));
  await client.listTools();
  await client.close();
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(world.state.signOuts, 0);
  assert.equal(world.requests.length, 0);
  server.close();
});

test("`--as-me` has the send tool by default in a real process, `--read-only` removes it, `--allow-send` is a harmless no-op", async () => {
  const names = async (args) => {
    const client = new Client({ name: "test", version: "0" }, { capabilities: {} });
    await client.connect(spawnClient(args, { SALT_ME_EMAIL: EMAIL, SALT_ME_PASSWORD_CMD: "echo x", HOST: "http://127.0.0.1:9" }));
    try {
      return (await client.listTools()).tools.map((t) => t.name);
    } finally {
      await client.close();
    }
  };
  assert.ok((await names(["--as-me"])).includes("salt_me_send"));
  assert.ok((await names(["--as-me", "--allow-send"])).includes("salt_me_send"));
  assert.ok(!(await names(["--as-me", "--read-only"])).includes("salt_me_send"));
});

test("a real process refuses to start with the certificate check off", async () => {
  const client = new Client({ name: "test", version: "0" }, { capabilities: {} });
  await assert.rejects(client.connect(spawnClient(["--as-me"], { SALT_ME_EMAIL: EMAIL, SALT_ME_PASSWORD_CMD: "echo x", NODE_TLS_REJECT_UNAUTHORIZED: "0" })));
});

test("--as-me-setup is gone: it says so and saves nothing", async () => {
  const { spawnSync } = await import("node:child_process");
  const r = spawnSync(process.execPath, ["src/index.mjs", "--as-me-setup", EMAIL], { encoding: "utf8", env: { PATH: process.env.PATH } });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /no setup step any more/);
});
