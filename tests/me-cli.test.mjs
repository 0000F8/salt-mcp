// The two entry points of --as-me: the platform check, the setup command (hidden dialog, verify by signing in and
// unlocking once, only then save to the Keychain), and a real stdio process speaking MCP.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { checkPlatform, runAsMeSetup, AsMeStartError } from "../src/me-cli.mjs";
import { makeWorld, EMAIL, PASSWORD, VAULT_PASSWORD, TEST_ITERATIONS } from "./me-fixtures.mjs";

const SAVED = "Saved. Salt MCP can read your chats on this Mac.";

function fakeSecrets() {
  const stored = [];
  return { stored, storePassword: async (service, email, password) => stored.push({ service, email, password }) };
}

const asker = (answers) => {
  const prompts = [];
  const ask = async (prompt) => {
    prompts.push(prompt);
    if (!answers.length) throw new Error("cancelled");
    return answers.shift();
  };
  return { ask, prompts };
};

test("--as-me refuses to start off macOS unless SALT_ME_PASSWORD_CMD is set", () => {
  assert.throws(() => checkPlatform({ platform: "linux", env: {} }), (err) => err instanceof AsMeStartError && /SALT_ME_PASSWORD_CMD/.test(err.message));
  assert.throws(() => checkPlatform({ platform: "win32", env: {} }), AsMeStartError);
  assert.doesNotThrow(() => checkPlatform({ platform: "linux", env: { SALT_ME_PASSWORD_CMD: "secret-tool lookup salt pw" } }));
  assert.doesNotThrow(() => checkPlatform({ platform: "darwin", env: {} }));
});

test("setup verifies the password by signing in and unlocking, then saves it and prints only the one sentence", async () => {
  const world = await makeWorld();
  const secrets = fakeSecrets();
  const { ask, prompts } = asker([PASSWORD]);
  const line = await runAsMeSetup(EMAIL, { platform: "darwin", env: {}, secrets, ask, fetchImpl: world.fetchImpl, signInIterations: TEST_ITERATIONS });
  assert.equal(line, SAVED);
  assert.deepEqual(secrets.stored, [{ service: "salt-mcp-me", email: EMAIL, password: PASSWORD }]);
  assert.equal(world.state.signIns, 1, "signed in exactly once");
  assert.ok(world.requests.some((r) => r.path === "/api/v1/userkeys") && world.requests.some((r) => r.path === "/api/v1/vault"), "and unlocked");
  assert.equal(prompts.length, 1);
  assert.ok(!line.includes(PASSWORD));
});

test("setup with a separate lock password asks for it too and saves it in its own item", async () => {
  const world = await makeWorld({ lockMode: "separate" });
  const secrets = fakeSecrets();
  const { ask, prompts } = asker([PASSWORD, VAULT_PASSWORD]);
  assert.equal(await runAsMeSetup(EMAIL, { platform: "darwin", env: {}, secrets, ask, fetchImpl: world.fetchImpl, signInIterations: TEST_ITERATIONS }), SAVED);
  assert.deepEqual(secrets.stored.map((s) => [s.service, s.password]), [["salt-mcp-me", PASSWORD], ["salt-mcp-me-vault", VAULT_PASSWORD]]);
  assert.equal(prompts.length, 2);
});

test("setup saves nothing when the password does not sign in", async () => {
  const world = await makeWorld();
  const secrets = fakeSecrets();
  await assert.rejects(
    runAsMeSetup(EMAIL, { platform: "darwin", env: {}, secrets, ask: asker(["wrong"]).ask, fetchImpl: world.fetchImpl, signInIterations: TEST_ITERATIONS }),
    (err) => /Couldn't sign in/.test(err.message) && !err.message.includes("wrong")
  );
  assert.deepEqual(secrets.stored, []);
});

test("setup saves nothing when the lock password is wrong, and nothing when the dialog is cancelled", async () => {
  const world = await makeWorld({ lockMode: "separate" });
  const secrets = fakeSecrets();
  await assert.rejects(
    runAsMeSetup(EMAIL, { platform: "darwin", env: {}, secrets, ask: asker([PASSWORD, "nope"]).ask, fetchImpl: world.fetchImpl, signInIterations: TEST_ITERATIONS }),
    /Couldn't unlock/
  );
  await assert.rejects(runAsMeSetup(EMAIL, { platform: "darwin", env: {}, secrets, ask: asker([]).ask, fetchImpl: world.fetchImpl, signInIterations: TEST_ITERATIONS }));
  assert.deepEqual(secrets.stored, []);
});

test("setup needs a Mac and a real email", async () => {
  await assert.rejects(runAsMeSetup(EMAIL, { platform: "linux", env: {} }), /runs on a Mac/);
  await assert.rejects(runAsMeSetup(undefined, { platform: "darwin", env: {} }), /Usage: salt-mcp --as-me-setup/);
  await assert.rejects(runAsMeSetup("not an email", { platform: "darwin", env: {} }), /Usage/);
});

test("a real `salt-mcp --as-me` process speaks MCP over stdio, offers five read tools, and touches no network until used", async () => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["src/index.mjs", "--as-me"],
    env: { PATH: process.env.PATH, SALT_ME_EMAIL: EMAIL, SALT_ME_PASSWORD_CMD: "echo never-used", HOST: "http://127.0.0.1:9" },
    stderr: "pipe",
  });
  const stderr = [];
  const client = new Client({ name: "test", version: "0" }, { capabilities: {} });
  await client.connect(transport);
  transport.stderr?.on("data", (d) => stderr.push(String(d)));
  try {
    const tools = (await client.listTools()).tools.map((t) => t.name).sort();
    assert.deepEqual(tools, ["salt_me_find_chat", "salt_me_list_chats", "salt_me_read_attachment", "salt_me_read_chat", "salt_me_whoami"]);
    const who = JSON.parse((await client.callTool({ name: "salt_me_whoami", arguments: {} })).content[0].text);
    assert.equal(who.unlocked, false);
    assert.equal(who.account.email, EMAIL);
    assert.equal(who.send_enabled, false);
    const failed = await client.callTool({ name: "salt_me_list_chats", arguments: {} });
    assert.equal(failed.isError, true);
    assert.match(failed.content[0].text, /Couldn't reach Salt/);
  } finally {
    await client.close();
  }
  assert.ok(!stderr.join("").includes("never-used"));
});

test("`--as-me --allow-send` adds the send tool in a real process", async () => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["src/index.mjs", "--as-me", "--allow-send"],
    env: { PATH: process.env.PATH, SALT_ME_EMAIL: EMAIL, SALT_ME_PASSWORD_CMD: "echo x", HOST: "http://127.0.0.1:9" },
  });
  const client = new Client({ name: "test", version: "0" }, { capabilities: {} });
  await client.connect(transport);
  try {
    assert.ok((await client.listTools()).tools.some((t) => t.name === "salt_me_send"));
  } finally {
    await client.close();
  }
});

test("the sign-in only goes to an https host, or one on this computer", async () => {
  const secrets = fakeSecrets();
  const never = async () => { throw new Error("must not ask"); };
  await assert.rejects(runAsMeSetup(EMAIL, { platform: "darwin", env: { HOST: "http://salt.example" }, secrets, ask: never }), /https/);
  await assert.rejects(runAsMeSetup(EMAIL, { platform: "darwin", env: { HOST: "not a url" }, secrets, ask: never }), /web address/);
  await assert.rejects(runAsMeSetup(EMAIL, { platform: "darwin", env: { HOST: "http://localhost:3000" }, secrets, ask: never }), /must not ask/, "localhost passes the check");
});
