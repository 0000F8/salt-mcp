// Where `salt-mcp --as-me` gets the owner's password, and the two native macOS
// dialogs it uses: a hidden password prompt for setup, and the Send / Don't
// send confirmation in front of every outgoing message.
//
// The password lives in the macOS Keychain (service "salt-mcp-me", account =
// the owner's email; a separate vault password in "salt-mcp-me-vault"), and
// is read with `security find-generic-password -w`. The owner's AI never
// handles it: it is not an environment variable, not a tool argument, not
// anything the model can read. Every external program is started with
// execFile and an argument array, never through a shell string; the one
// exception is SALT_ME_PASSWORD_CMD, a command line the owner writes
// themselves for Linux secret tools.
//
// Nothing here logs or returns a secret except as the value the caller asked
// for, and no error message carries one.

import { execFile as nodeExecFile, spawn } from "node:child_process";
import { promisify } from "node:util";

export const KEYCHAIN_SERVICE = "salt-mcp-me";
export const KEYCHAIN_VAULT_SERVICE = "salt-mcp-me-vault";

// Setup stores the password base64-encoded behind this prefix: `security -w`
// prints a value that is not plain printable text as hex, which would
// silently corrupt a password with an accent or a newline in it. A value
// without the prefix (an item the owner added by hand) is used as typed.
const B64_PREFIX = "salt-mcp-b64:";

export class SecretsError extends Error {
  constructor(message) {
    super(message);
    this.name = "SecretsError";
  }
}

const defaultExecFile = promisify(nodeExecFile);

// Runs a program with `input` on its stdin (no shell). Rejects on a non-zero exit.
const defaultRunWithInput = (file, args, input) =>
  new Promise((resolve, reject) => {
    const child = spawn(file, args, { stdio: ["pipe", "ignore", "ignore"] });
    child.on("error", reject);
    child.on("close", (code) => (code === 0 ? resolve() : reject(new Error(`exit ${code}`))));
    child.stdin.on("error", () => {});
    child.stdin.end(input);
  });

const stripOneNewline = (s) => String(s).replace(/\r?\n$/, "");

/**
 * @param {{execFile?: Function, runWithInput?: Function, env?: Record<string,string|undefined>, platform?: string}} options
 * `execFile` is `(file, args, opts?) => Promise<{stdout, stderr}>` and `runWithInput` is `(file, args, stdinText) => Promise<void>`;
 * tests inject fakes for both.
 */
export function createSecrets({ execFile = defaultExecFile, runWithInput = defaultRunWithInput, env = process.env, platform = process.platform } = {}) {
  const commandFor = (service) => (service === KEYCHAIN_VAULT_SERVICE ? env.SALT_ME_VAULT_PASSWORD_CMD : env.SALT_ME_PASSWORD_CMD);

  async function fromCommand(command) {
    try {
      const { stdout } = await execFile("/bin/sh", ["-c", command], { maxBuffer: 1024 * 1024 });
      const value = stripOneNewline(stdout);
      if (!value) throw new SecretsError("The password command printed nothing.");
      return value;
    } catch (err) {
      if (err instanceof SecretsError) throw err;
      throw new SecretsError("The password command failed.");
    }
  }

  async function fromKeychain(service, email) {
    if (platform !== "darwin") throw new SecretsError("The macOS Keychain is not available here. Set SALT_ME_PASSWORD_CMD.");
    try {
      const { stdout } = await execFile("security", ["find-generic-password", "-s", service, "-a", email, "-w"], { maxBuffer: 1024 * 1024 });
      const raw = stripOneNewline(stdout);
      if (!raw) throw new SecretsError("The saved password is empty.");
      return raw.startsWith(B64_PREFIX) ? Buffer.from(raw.slice(B64_PREFIX.length), "base64").toString("utf8") : raw;
    } catch (err) {
      if (err instanceof SecretsError) throw err;
      throw new SecretsError(`No password is saved in the Keychain for ${service}.`);
    }
  }

  return {
    /** The password for `service` (login by default). A configured command wins over the Keychain. */
    async readPassword(email, service = KEYCHAIN_SERVICE) {
      const command = commandFor(service);
      return command ? fromCommand(command) : fromKeychain(service, email);
    },

    /** The account email: SALT_ME_EMAIL, else the account of the Keychain item saved by setup. */
    async findEmail() {
      if (env.SALT_ME_EMAIL) return env.SALT_ME_EMAIL.trim();
      if (platform !== "darwin") throw new SecretsError("Set SALT_ME_EMAIL to your Salt email.");
      try {
        const { stdout } = await execFile("security", ["find-generic-password", "-s", KEYCHAIN_SERVICE], { maxBuffer: 1024 * 1024 });
        const match = /"acct"<blob>="([^"]+)"/.exec(String(stdout));
        if (match) return match[1];
      } catch {
        // fall through to the one plain sentence below
      }
      throw new SecretsError("No Salt account is saved yet. Run: salt-mcp --as-me-setup <your email>");
    },

    /**
     * Saves a password as a generic Keychain item. The command goes to `security -i` on stdin, so the password is never
     * in any process's argument list; it travels hex-encoded (-X) so no quoting can mangle it.
     */
    async storePassword(service, email, password) {
      if (platform !== "darwin") throw new SecretsError("Saving to the Keychain needs macOS.");
      if (!/^[^\s"'\\]+$/.test(email)) throw new SecretsError("That email address has characters the setup cannot save.");
      const hex = Buffer.from(B64_PREFIX + Buffer.from(password, "utf8").toString("base64"), "utf8").toString("hex");
      const line = `add-generic-password -U -s ${service} -a ${email} -X ${hex}\n`;
      try {
        await runWithInput("security", ["-i"], line);
      } catch {
        throw new SecretsError("The Keychain refused to save the password.");
      }
    },
  };
}

// ---------- macOS dialogs (osascript) ----------
//
// Every value reaches AppleScript as an argument to `on run argv`, never
// spliced into the script text, so a chat name or message cannot inject code.

const run = (script, args, execFile) =>
  execFile("osascript", [...script.flatMap((line) => ["-e", line]), ...args], { maxBuffer: 4 * 1024 * 1024 });

const PASSWORD_SCRIPT = [
  "on run argv",
  'text returned of (display dialog (item 1 of argv) with title "Salt MCP" default answer "" with hidden answer buttons {"Cancel", "Save"} default button "Save" cancel button "Cancel")',
  "end run",
];

/** Asks for a secret in a native dialog with hidden typing. Resolves the text, or rejects if cancelled. */
export async function askHiddenPassword(prompt, { execFile = defaultExecFile, platform = process.platform } = {}) {
  if (platform !== "darwin") throw new SecretsError("The password prompt needs macOS.");
  try {
    const { stdout } = await run(PASSWORD_SCRIPT, [prompt], execFile);
    const value = stripOneNewline(stdout);
    if (!value) throw new SecretsError("No password was entered.");
    return value;
  } catch (err) {
    if (err instanceof SecretsError) throw err;
    throw new SecretsError("The password prompt was cancelled.");
  }
}

const CONFIRM_SCRIPT = [
  "on run argv",
  'set answer to button returned of (display dialog (item 2 of argv) with title (item 1 of argv) buttons {"Don\'t send", "Send"} default button "Don\'t send" cancel button "Don\'t send" with icon note)',
  "return answer",
  "end run",
];

/**
 * The native confirmation in front of every send: the chat's name and the full text, "Send" or "Don't send".
 * Anything but an explicit "Send" (the other button, closing it, an error, no dialog available) is a no.
 * @returns {(args: {chatName: string, text: string}) => Promise<boolean>}
 */
export function createSendConfirmation({ execFile = defaultExecFile, platform = process.platform } = {}) {
  return async function confirmSend({ chatName, text }) {
    if (platform !== "darwin") return false;
    try {
      const { stdout } = await run(CONFIRM_SCRIPT, ["Salt MCP: send this message?", `To: ${chatName}\n\n${text}`], execFile);
      return stripOneNewline(stdout) === "Send";
    } catch {
      return false;
    }
  };
}
