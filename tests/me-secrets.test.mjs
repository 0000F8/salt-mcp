// Where --as-me finds the password (src/me-secrets.mjs): the macOS Keychain through `security`, started with an
// argument array and never a shell string; a configured command for non-Macs; hex-encoded stdin for saving; and the
// two native dialogs. execFile is a fake, so nothing touches the real Keychain or screen.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  createSecrets,
  createSendConfirmation,
  askHiddenPassword,
  SecretsError,
  KEYCHAIN_SERVICE,
  KEYCHAIN_VAULT_SERVICE,
} from "../src/me-secrets.mjs";

const SECRET = "p4ss \"quoted\" 'x' \\ $(touch pwned) é\n second line";

function fakeExec(handler) {
  const calls = [];
  const execFile = async (file, args, opts) => {
    calls.push({ file, args, opts });
    return handler(file, args, opts);
  };
  return { execFile, calls };
}

test("readPassword asks the Keychain with an argument array", async () => {
  const { execFile, calls } = fakeExec(() => ({ stdout: "hunter2\n", stderr: "" }));
  const secrets = createSecrets({ execFile, env: {}, platform: "darwin" });
  assert.equal(await secrets.readPassword("me@example.test"), "hunter2");
  assert.deepEqual(calls[0], { file: "security", args: ["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", "me@example.test", "-w"], opts: calls[0].opts });
  await secrets.readPassword("me@example.test", KEYCHAIN_VAULT_SERVICE);
  assert.deepEqual(calls[1].args, ["find-generic-password", "-s", "salt-mcp-me-vault", "-a", "me@example.test", "-w"]);
});

test("a password with quotes, a newline and shell syntax round-trips through the b64 form", async () => {
  const stored = `salt-mcp-b64:${Buffer.from(SECRET, "utf8").toString("base64")}`;
  const { execFile } = fakeExec(() => ({ stdout: `${stored}\n` }));
  const secrets = createSecrets({ execFile, env: {}, platform: "darwin" });
  assert.equal(await secrets.readPassword("me@example.test"), SECRET);
});

test("a hand-added Keychain item without the prefix is used as typed", async () => {
  const { execFile } = fakeExec(() => ({ stdout: "plain pass\n" }));
  assert.equal(await createSecrets({ execFile, env: {}, platform: "darwin" }).readPassword("e@x.test"), "plain pass");
});

test("a missing Keychain item is one plain sentence with no program output in it", async () => {
  const { execFile } = fakeExec(() => {
    throw new Error("security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.");
  });
  await assert.rejects(createSecrets({ execFile, env: {}, platform: "darwin" }).readPassword("e@x.test"), (err) => {
    assert.ok(err instanceof SecretsError);
    assert.match(err.message, /No password is saved in the Keychain for salt-mcp-me\./);
    assert.ok(!/SecKeychain/.test(err.message));
    return true;
  });
});

test("SALT_ME_PASSWORD_CMD wins over the Keychain and works off macOS", async () => {
  const { execFile, calls } = fakeExec(() => ({ stdout: "from-linux-secret-tool\n" }));
  const secrets = createSecrets({ execFile, env: { SALT_ME_PASSWORD_CMD: "secret-tool lookup service salt" }, platform: "linux" });
  assert.equal(await secrets.readPassword("e@x.test"), "from-linux-secret-tool");
  assert.deepEqual(calls[0].args, ["-c", "secret-tool lookup service salt"]);
  assert.equal(calls.length, 1);
});

test("an empty or failing password command is an error that carries nothing", async () => {
  const empty = createSecrets({ execFile: fakeExec(() => ({ stdout: "\n" })).execFile, env: { SALT_ME_PASSWORD_CMD: "x" }, platform: "linux" });
  await assert.rejects(empty.readPassword("e@x.test"), /printed nothing/);
  const failing = createSecrets({ execFile: fakeExec(() => { throw new Error("boom: secret was hunter2"); }).execFile, env: { SALT_ME_PASSWORD_CMD: "x" }, platform: "linux" });
  await assert.rejects(failing.readPassword("e@x.test"), (err) => !/hunter2/.test(err.message));
});

test("the vault password has its own command", async () => {
  const { execFile, calls } = fakeExec((file, args) => ({ stdout: args[1] === "vault-cmd" ? "vault-pass\n" : "login-pass\n" }));
  const secrets = createSecrets({ execFile, env: { SALT_ME_PASSWORD_CMD: "login-cmd", SALT_ME_VAULT_PASSWORD_CMD: "vault-cmd" }, platform: "linux" });
  assert.equal(await secrets.readPassword("e@x.test", KEYCHAIN_VAULT_SERVICE), "vault-pass");
  assert.equal(await secrets.readPassword("e@x.test"), "login-pass");
  assert.equal(calls.length, 2);
});

test("findEmail: SALT_ME_EMAIL first, else the account of the saved item", async () => {
  assert.equal(await createSecrets({ env: { SALT_ME_EMAIL: " me@example.test " }, platform: "darwin" }).findEmail(), "me@example.test");
  const { execFile, calls } = fakeExec(() => ({ stdout: 'attributes:\n    "acct"<blob>="saved@example.test"\n    "svce"<blob>="salt-mcp-me"\n' }));
  assert.equal(await createSecrets({ execFile, env: {}, platform: "darwin" }).findEmail(), "saved@example.test");
  assert.deepEqual(calls[0].args, ["find-generic-password", "-s", "salt-mcp-me"]);
  const none = createSecrets({ execFile: fakeExec(() => { throw new Error("nope"); }).execFile, env: {}, platform: "darwin" });
  await assert.rejects(none.findEmail(), /--as-me-setup/);
});

test("storePassword feeds `security -i` on stdin, hex-encoded: the password is in no argument and no readable text", async () => {
  const runs = [];
  const secrets = createSecrets({ env: {}, platform: "darwin", runWithInput: async (file, args, input) => runs.push({ file, args, input }) });
  await secrets.storePassword(KEYCHAIN_SERVICE, "me@example.test", SECRET);
  assert.equal(runs.length, 1);
  assert.equal(runs[0].file, "security");
  assert.deepEqual(runs[0].args, ["-i"]);
  const line = runs[0].input;
  assert.match(line, /^add-generic-password -U -s salt-mcp-me -a me@example\.test -X [0-9a-f]+\n$/);
  assert.ok(!line.includes("p4ss"), "no readable password in the command");
  const hex = /-X ([0-9a-f]+)/.exec(line)[1];
  const decoded = Buffer.from(hex, "hex").toString("utf8");
  assert.ok(decoded.startsWith("salt-mcp-b64:"));
  assert.equal(Buffer.from(decoded.slice("salt-mcp-b64:".length), "base64").toString("utf8"), SECRET);
});

test("storePassword refuses an email it could not quote safely, and reports a refused save plainly", async () => {
  const secrets = createSecrets({ env: {}, platform: "darwin", runWithInput: async () => { throw new Error("exit 2"); } });
  await assert.rejects(secrets.storePassword(KEYCHAIN_SERVICE, 'a b"c@x.test', "x"), /characters the setup cannot save/);
  await assert.rejects(secrets.storePassword(KEYCHAIN_SERVICE, "me@example.test", "x"), /Keychain refused/);
  await assert.rejects(createSecrets({ env: {}, platform: "linux" }).storePassword(KEYCHAIN_SERVICE, "me@example.test", "x"), /needs macOS/);
});

test("askHiddenPassword uses a hidden-answer dialog and passes the prompt as an argument", async () => {
  const { execFile, calls } = fakeExec(() => ({ stdout: "typed secret\n" }));
  assert.equal(await askHiddenPassword("Salt password for me@example.test", { execFile, platform: "darwin" }), "typed secret");
  const { args } = calls[0];
  assert.equal(args.at(-1), "Salt password for me@example.test");
  assert.ok(args.join(" ").includes("with hidden answer"));
  assert.ok(!args.slice(0, -1).some((a) => a.includes("me@example.test")), "the prompt is an argument, not spliced into the script");
});

test("askHiddenPassword: cancel and empty answers are errors", async () => {
  await assert.rejects(askHiddenPassword("x", { execFile: fakeExec(() => { throw new Error("User canceled. (-128)"); }).execFile, platform: "darwin" }), /cancelled/);
  await assert.rejects(askHiddenPassword("x", { execFile: fakeExec(() => ({ stdout: "\n" })).execFile, platform: "darwin" }), /No password/);
  await assert.rejects(askHiddenPassword("x", { platform: "linux" }), /needs macOS/);
});

test("the send dialog shows the chat and the full text as arguments; only 'Send' means yes", async () => {
  const text = 'Meet at 5"; do shell script "rm -rf ~"';
  const sent = fakeExec(() => ({ stdout: "Send\n" }));
  assert.equal(await createSendConfirmation({ execFile: sent.execFile, platform: "darwin" })({ chatName: "Launch crew", text }), true);
  const { args } = sent.calls[0];
  assert.equal(sent.calls[0].file, "osascript");
  assert.ok(args.at(-1).includes("Launch crew") && args.at(-1).includes(text), "chat name and full text reach the dialog");
  assert.ok(!args.slice(0, -2).some((a) => a.includes("rm -rf")), "text is never part of the script");
  assert.ok(args.join(" ").includes("Don't send") && args.join(" ").includes('"Send"'));

  for (const outcome of [{ stdout: "Don't send\n" }, { stdout: "" }, { stdout: "send\n" }]) {
    assert.equal(await createSendConfirmation({ execFile: fakeExec(() => outcome).execFile, platform: "darwin" })({ chatName: "c", text: "t" }), false);
  }
  assert.equal(await createSendConfirmation({ execFile: fakeExec(() => { throw new Error("User canceled. (-128)"); }).execFile, platform: "darwin" })({ chatName: "c", text: "t" }), false);
  assert.equal(await createSendConfirmation({ platform: "linux" })({ chatName: "c", text: "t" }), false, "no dialog available means no send");
});
