// (Password path only: --password, or SALT_ME_PASSWORD_CMD. The default sign-in is the phone link, me-link.mjs,
// which stores a link file instead -- see below for why this path stores nothing.)
//
// Where `salt-mcp --as-me --password` gets the owner's password, and the native macOS
// dialog it uses: a hidden password prompt the first time a tool needs to
// unlock.
//
// NOTHING IS STORED. A Keychain item made by /usr/bin/security is readable,
// without a prompt, by any process of the same user -- including an AI client
// with a shell that an injected chat message has steered -- and the login
// password also opens the wallets. So the password is asked for in a hidden
// dialog when the server first needs it, held in memory for the one unlock
// (me-session.mjs drops it straight after), and never written anywhere.
// SALT_ME_PASSWORD_CMD is for systems without the dialog: the owner's own
// secret tool, whose own protections apply.
//
// The owner's AI never sees the password: it is not an argument, an
// environment variable or tool output. Programs are started with execFile and
// an argument array. Dialog text (which includes text an AI wrote) goes to
// osascript on STDIN, never as an argument, so `ps` shows nothing of it.
//
// No secret is logged or put in an error message.

import { execFile as nodeExecFile, spawn } from "node:child_process";
import { promisify } from "node:util";

export class SecretsError extends Error {
  constructor(message, { declined = false } = {}) {
    super(message);
    this.name = "SecretsError";
    this.declined = declined;
  }
}

export const DECLINED = "You chose not to unlock your Salt chats.";

const defaultExecFile = promisify(nodeExecFile);

// Runs an AppleScript given on stdin (`osascript -`) and resolves its stdout.
const defaultRunScript = (script) =>
  new Promise((resolve, reject) => {
    const child = spawn("osascript", ["-"], { stdio: ["pipe", "pipe", "ignore"] });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.on("error", reject);
    child.on("close", (code) => (code === 0 ? resolve(out) : reject(new Error(`osascript exit ${code}`))));
    child.stdin.on("error", () => {});
    child.stdin.end(script);
  });

const stripOneNewline = (s) => String(s).replace(/\r?\n$/, "");

// Anything the dialogs show that is not plain text is neutralised here as a last line of defence; callers (the send
// tool) refuse such text long before it gets this far, so what is shown is what is sent.
const UNSHOWABLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;

/** An AppleScript string literal for `text`. Only `\`, `"`, newline and tab need escaping inside one. */
export function appleScriptString(text) {
  const safe = String(text)
    .replace(/\r\n?/g, "\n")
    .replace(UNSHOWABLE, (c) => (c === "\n" || c === "\t" ? c : "?"));
  return `"${safe.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\t/g, "\\t")}"`;
}

/** Asks in a native dialog. `hidden` hides the typing. Resolves the text; rejects (declined) if cancelled or empty. */
export async function askDialog(prompt, { hidden = false, runScript = defaultRunScript, platform = process.platform } = {}) {
  if (platform !== "darwin") throw new SecretsError("The password prompt needs macOS. Set SALT_ME_PASSWORD_CMD.");
  const script =
    `text returned of (display dialog ${appleScriptString(prompt)} with title "Salt MCP" default answer ""` +
    `${hidden ? " with hidden answer" : ""} buttons {"Cancel", "Unlock"} default button "Unlock" cancel button "Cancel")\n`;
  let out;
  try {
    out = await runScript(script);
  } catch {
    throw new SecretsError(DECLINED, { declined: true });
  }
  const value = stripOneNewline(out);
  if (!value) throw new SecretsError(DECLINED, { declined: true });
  return value;
}

/**
 * @param {{execFile?: Function, runScript?: Function, env?: Record<string,string|undefined>, platform?: string}} options
 * `execFile` is `(file, args, opts?) => Promise<{stdout}>`, `runScript` is `(appleScript) => Promise<stdout>`; tests inject fakes.
 */
export function createSecrets({ execFile = defaultExecFile, runScript = defaultRunScript, env = process.env, platform = process.platform } = {}) {
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

  return {
    /** The password: "login" is the Salt password, "vault" the separate lock password. A configured command wins over the dialog. */
    async readPassword(kind = "login") {
      const command = kind === "vault" ? env.SALT_ME_VAULT_PASSWORD_CMD : env.SALT_ME_PASSWORD_CMD;
      if (command) return fromCommand(command);
      const prompt =
        kind === "vault"
          ? "Salt MCP needs your separate Salt lock password to open your messages key on this Mac."
          : "Salt MCP wants to read your chats on this Mac.\nEnter your Salt password.";
      return askDialog(prompt, { hidden: true, runScript, platform });
    },

    /** The account email: SALT_ME_EMAIL, else asked once in a dialog. */
    async readEmail() {
      if (env.SALT_ME_EMAIL) return env.SALT_ME_EMAIL.trim();
      if (platform !== "darwin") throw new SecretsError("Set SALT_ME_EMAIL to your Salt email.");
      return (await askDialog("Salt MCP wants to read your chats on this Mac.\nEnter your Salt email.", { hidden: false, runScript, platform })).trim();
    },
  };
}
