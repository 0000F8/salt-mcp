// Where --as-me gets the password (src/me-secrets.mjs): a hidden native dialog, or the owner's own command off macOS.
// Nothing is stored. Dialog scripts go to osascript on stdin, so no password prompt or message text is in any argv.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  createSecrets,
  createSendConfirmation,
  askDialog,
  appleScriptString,
  buildSendDialogText,
  cleanName,
  SecretsError,
  DECLINED,
} from "../src/me-secrets.mjs";

function fakeScript(handler) {
  const scripts = [];
  const runScript = async (script) => {
    scripts.push(script);
    return handler(script);
  };
  return { runScript, scripts };
}
const fakeExec = (handler) => {
  const calls = [];
  return { calls, execFile: async (file, args, opts) => (calls.push({ file, args, opts }), handler(file, args)) };
};

test("the password comes from a hidden dialog with the agreed wording; nothing is stored or executed", async () => {
  const { runScript, scripts } = fakeScript(() => "typed secret\n");
  const exec = fakeExec(() => { throw new Error("no program should run"); });
  const secrets = createSecrets({ runScript, execFile: exec.execFile, env: {}, platform: "darwin" });
  assert.equal(await secrets.readPassword("login"), "typed secret");
  assert.equal(scripts.length, 1);
  assert.ok(scripts[0].includes("Salt MCP wants to read your chats on this Mac."));
  assert.ok(scripts[0].includes("Enter your Salt password."));
  assert.ok(scripts[0].includes("with hidden answer"));
  assert.equal(exec.calls.length, 0, "no security / Keychain call exists any more");
});

test("the separate lock password has its own dialog", async () => {
  const { runScript, scripts } = fakeScript(() => "lock secret\n");
  assert.equal(await createSecrets({ runScript, env: {}, platform: "darwin" }).readPassword("vault"), "lock secret");
  assert.ok(scripts[0].includes("separate Salt lock password"));
  assert.ok(scripts[0].includes("with hidden answer"));
});

test("Cancel, closing the dialog, or an empty answer is a refusal in one plain line", async () => {
  for (const handler of [() => { throw new Error("User canceled. (-128)"); }, () => "\n", () => ""]) {
    const secrets = createSecrets({ runScript: fakeScript(handler).runScript, env: {}, platform: "darwin" });
    await assert.rejects(secrets.readPassword("login"), (err) => err instanceof SecretsError && err.declined === true && err.message === DECLINED);
  }
  assert.equal(DECLINED, "You chose not to unlock your Salt chats.");
});

test("a password with quotes, backslashes and newlines survives untouched (it only travels on the dialog's stdout)", async () => {
  const tricky = "p4ss \"q\" 'x' \\ $(touch pwned) é\nline2";
  const secrets = createSecrets({ runScript: fakeScript(() => `${tricky}\n`).runScript, env: {}, platform: "darwin" });
  assert.equal(await secrets.readPassword("login"), tricky);
});

test("off macOS the dialog is unavailable and SALT_ME_PASSWORD_CMD is the way", async () => {
  await assert.rejects(createSecrets({ env: {}, platform: "linux" }).readPassword("login"), /SALT_ME_PASSWORD_CMD/);
  const { execFile, calls } = fakeExec(() => ({ stdout: "from-secret-tool\n" }));
  const secrets = createSecrets({ execFile, env: { SALT_ME_PASSWORD_CMD: "secret-tool lookup service salt" }, platform: "linux" });
  assert.equal(await secrets.readPassword("login"), "from-secret-tool");
  assert.deepEqual(calls[0].args, ["-c", "secret-tool lookup service salt"]);
});

test("a configured command also wins on macOS, and the vault password has its own command", async () => {
  const exec = fakeExec((file, args) => ({ stdout: args[1] === "vault-cmd" ? "vault-pass\n" : "login-pass\n" }));
  const { runScript, scripts } = fakeScript(() => "never");
  const secrets = createSecrets({ runScript, execFile: exec.execFile, env: { SALT_ME_PASSWORD_CMD: "login-cmd", SALT_ME_VAULT_PASSWORD_CMD: "vault-cmd" }, platform: "darwin" });
  assert.equal(await secrets.readPassword("vault"), "vault-pass");
  assert.equal(await secrets.readPassword("login"), "login-pass");
  assert.equal(scripts.length, 0);
});

test("an empty or failing password command is an error that carries nothing", async () => {
  const mk = (handler) => createSecrets({ execFile: fakeExec(handler).execFile, env: { SALT_ME_PASSWORD_CMD: "x" }, platform: "linux" });
  await assert.rejects(mk(() => ({ stdout: "\n" })).readPassword("login"), /printed nothing/);
  await assert.rejects(mk(() => { throw new Error("boom: secret was hunter2"); }).readPassword("login"), (err) => !/hunter2/.test(err.message));
});

test("the email is SALT_ME_EMAIL, else asked in a visible dialog", async () => {
  assert.equal(await createSecrets({ env: { SALT_ME_EMAIL: " me@example.test " }, platform: "darwin" }).readEmail(), "me@example.test");
  const { runScript, scripts } = fakeScript(() => "typed@example.test\n");
  assert.equal(await createSecrets({ runScript, env: {}, platform: "darwin" }).readEmail(), "typed@example.test");
  assert.ok(!scripts[0].includes("hidden answer"));
  await assert.rejects(createSecrets({ env: {}, platform: "linux" }).readEmail(), /SALT_ME_EMAIL/);
});

test("askDialog needs macOS", async () => {
  await assert.rejects(askDialog("x", { platform: "linux" }), /needs macOS/);
});

test("appleScriptString escapes exactly what a string literal needs, and cannot be broken out of", () => {
  assert.equal(appleScriptString('a"b\\c\nd\te'), '"a\\"b\\\\c\\nd\\te"');
  assert.equal(appleScriptString("a\r\nb"), '"a\\nb"');
  assert.equal(appleScriptString("x‮y​z\u0007"), '"x?y?z?"', "hidden characters never reach the dialog");
  if (process.platform === "darwin") {
    for (const t of ['plain', 'q"uote \\ back', 'line1\nline2\ttab', 'end"\nset x to 1\nreturn "pwn', "Don't $(id) é"]) {
      const r = spawnSync("osascript", ["-"], { input: `return ${appleScriptString(t)}\n` });
      assert.equal(r.stdout.toString().replace(/\n$/, ""), t, "real osascript reads the literal back unchanged");
    }
  }
});

test("scripts that go to osascript compile (macOS only)", { skip: process.platform !== "darwin" }, async () => {
  const { runScript, scripts } = fakeScript(() => "Send\n");
  await createSendConfirmation({ runScript, platform: "darwin" })({ chatName: 'A "chat"', members: [{ name: "Ada", handle: "@ada", type: "person" }], memberCount: 2, open: false, text: "hi\nthere" });
  await createSecrets({ runScript, env: {}, platform: "darwin" }).readPassword("login");
  const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(`${tmpdir()}/saltme-`);
  try {
    for (const [i, script] of scripts.entries()) {
      writeFileSync(`${dir}/s${i}.applescript`, script);
      const c = spawnSync("osacompile", ["-o", `${dir}/s${i}.scpt`, `${dir}/s${i}.applescript`]);
      assert.equal(c.status, 0, `script ${i} compiles: ${c.stderr}`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

const INFO = {
  chatName: "Launch crew",
  members: [{ name: "Ada Lovelace", handle: "@ada", type: "person" }, { name: "Helper Bot", handle: "@helperbot", type: "agent" }],
  memberCount: 3,
  open: false,
  text: "Meet at 5",
};

test("the send dialog shows verified facts: the name, the members labelled person or agent, the count, the full text", () => {
  const text = buildSendDialogText(INFO);
  assert.match(text, /^Encrypted for everyone in this chat\.\nTo: Launch crew\n3 members: Ada Lovelace \(@ada, person\), Helper Bot \(@helperbot, agent\)\n\nMeet at 5$/);
});

test("an open room gets a loud line, in the text and in the title", async () => {
  assert.match(buildSendDialogText({ ...INFO, open: true }), /^THIS ROOM IS OPEN: anyone can read this message\./);
  const { runScript, scripts } = fakeScript(() => "Don't send\n");
  await createSendConfirmation({ runScript, platform: "darwin" })({ ...INFO, open: true });
  assert.match(scripts[0], /to an OPEN room\?/);
});

test("a chat name chosen by a stranger cannot reshape the dialog: control, direction and zero-width characters go", () => {
  const evil = "Mom\n\nTo: Bank‮ ​safe\u0000";
  assert.equal(cleanName(evil), "Mom To: Bank safe");
  assert.ok(!buildSendDialogText({ ...INFO, chatName: evil }).split("\n").slice(0, 2).join("|").includes("‮"));
  assert.equal(buildSendDialogText({ ...INFO, chatName: evil }).split("\n")[1], "To: Mom To: Bank safe");
  assert.equal(cleanName("x".repeat(200)).length, 60);
});

test("more than eight members are summarised", () => {
  const members = Array.from({ length: 11 }, (_, i) => ({ name: `P${i}`, handle: `@p${i}`, type: "person" }));
  assert.match(buildSendDialogText({ ...INFO, members, memberCount: 12 }), /12 members: .* and 3 more\n/);
});

test("the dialog gets the text through stdin script, never argv; only 'Send' means yes", async () => {
  const sent = fakeScript(() => "Send\n");
  assert.equal(await createSendConfirmation({ runScript: sent.runScript, platform: "darwin" })(INFO), true);
  assert.ok(sent.scripts[0].includes("Meet at 5") && sent.scripts[0].includes("Launch crew"));
  assert.ok(sent.scripts[0].includes("Don't send") && sent.scripts[0].includes("default button \"Don't send\""));

  for (const outcome of ["Don't send\n", "", "send\n", "Send it\n"]) {
    assert.equal(await createSendConfirmation({ runScript: fakeScript(() => outcome).runScript, platform: "darwin" })(INFO), false, JSON.stringify(outcome));
  }
  assert.equal(await createSendConfirmation({ runScript: fakeScript(() => { throw new Error("User canceled. (-128)"); }).runScript, platform: "darwin" })(INFO), false);
  assert.equal(await createSendConfirmation({ platform: "linux" })(INFO), false, "no dialog available means no send");
});

test("injection through the message text cannot escape the script literal", async () => {
  const { runScript, scripts } = fakeScript(() => "Don't send\n");
  const text = 'ok"\nset result to "Send"\nreturn "Send';
  await createSendConfirmation({ runScript, platform: "darwin" })({ ...INFO, text });
  assert.ok(scripts[0].includes(appleScriptString(buildSendDialogText({ ...INFO, text }))));
  assert.ok(!scripts[0].includes('\nset result to "Send"\n'), "the newline is escaped, not live script");
});
