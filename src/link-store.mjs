// Pieces shared by the two phone links (me-link.mjs for --as-me, channel-link.mjs for --channel): the default
// browser opener, a stdin-fed command runner, a fake-able timer, the state directory, the host slug, a macOS
// Keychain item written through `security -i` on STDIN (never on a command line), and a 0600 file writer.

import { execFile as nodeExecFile, spawn } from "node:child_process";
import { chmodSync, mkdirSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const defaultExecFile = promisify(nodeExecFile);
export const defaultOpen = (url) => defaultExecFile("/usr/bin/open", [url]);

// Runs a program with an argument array (never a shell); `input` goes to its stdin. Resolves stdout.
export const defaultRunCommand = (file, args, { input } = {}) =>
  new Promise((resolve, reject) => {
    const child = spawn(file, args, { stdio: ["pipe", "pipe", "ignore"] });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.on("error", reject);
    child.on("close", (code) => (code === 0 ? resolve(out) : reject(new Error(`${file} exit ${code}`))));
    child.stdin.on("error", () => {});
    child.stdin.end(input ?? "");
  });

export const defaultSetTimer = (fn, ms) => {
  const handle = setTimeout(fn, ms);
  handle.unref?.();
  return handle;
};

export const defaultBaseDir = () => join(homedir(), "Library", "Application Support", "salt-mcp");
/** `https://saltapp.ai` -> `saltapp-ai`; the port stays, so a local server has its own link. */
export const hostSlug = (host) => new URL(host).host.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");

/** A generic-password Keychain item holding one secret string (base64 on the wire, so it is one token). */
export function createKeychain({ runCommand, service, account }) {
  return {
    set: (secret) => runCommand("/usr/bin/security", ["-i"], { input: `add-generic-password -U -s ${service} -a ${account} -w ${Buffer.from(secret, "utf8").toString("base64")}\n` }),
    async get() {
      try {
        const out = String(await runCommand("/usr/bin/security", ["find-generic-password", "-s", service, "-a", account, "-w"])).trim();
        return out ? Buffer.from(out, "base64").toString("utf8") : null;
      } catch {
        return null;
      }
    },
    remove: () => runCommand("/usr/bin/security", ["delete-generic-password", "-s", service, "-a", account]).catch(() => {}),
  };
}

/** Writes `data` as JSON to `file`: directory 0700, file 0600, via a temp file and a rename. */
export function writePrivateJson(baseDir, file, data) {
  mkdirSync(baseDir, { recursive: true, mode: 0o700 });
  chmodSync(baseDir, 0o700);
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(data), { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, file);
}
