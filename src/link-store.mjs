// Pieces shared by the two phone links (me-link.mjs for --as-me, channel-link.mjs for --channel): the default
// browser opener, a stdin-fed command runner, a fake-able timer, the state directory, the host slug, a macOS
// Keychain item written through `security -i` on STDIN (never on a command line), a 0600 file writer, and the local
// QR page (the code is drawn here, never by a web page of Salt's).

import { execFile as nodeExecFile, spawn } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import qrcodeGenerator from "qrcode-generator";

const qrcode = qrcodeGenerator;

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

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

/** The page that shows the code: an inline SVG drawn here, so no web page of Salt's draws it. Holds the link value (id and fingerprint) and the computer's name only. */
export function renderLinkPage({ value, name }) {
  const qr = qrcode(0, "M");
  qr.addData(value);
  qr.make();
  const svg = qr.createSvgTag({ cellSize: 8, margin: 4, scalable: true });
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Link this computer</title>
<style>
:root{color-scheme:dark}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f1115;color:#f2f4f8;font:19px/1.6 system-ui,sans-serif;text-align:center}
main{max-width:30rem;padding:1.5rem}
h1{font-size:1.6rem;margin:0 0 .25rem}
.qr{width:min(80vw,22rem);margin:1.25rem auto;padding:.75rem;background:#fff;border-radius:.75rem}
.qr svg{display:block;width:100%;height:auto}
</style></head>
<body><main>
<h1>Link this computer</h1>
<p>${escapeHtml(name)}</p>
<div class="qr">${svg}</div>
<p>On your phone, open Salt's menu, tap Devices, then Link a computer, and scan this.</p>
</main></body></html>
`;
}

/**
 * Draws the code locally for `{host}/link/<id>/<fp>`, writes it to a fresh 0700 temp dir as a 0600 file and opens it
 * (openBrowser gets the file:// URL). Resolves `{ file, url, opened, cleanup }`; cleanup deletes the dir (idempotent) and
 * is also run when the process exits. If opening fails the path goes to `log`.
 */
export async function showLinkPage({ host, id, fp, name, openBrowser = defaultOpen, log = (m) => console.error("[salt-mcp]", m) }) {
  const dir = mkdtempSync(join(tmpdir(), "salt-link-"));
  chmodSync(dir, 0o700);
  const file = join(dir, "link.html");
  writeFileSync(file, renderLinkPage({ value: `${host.replace(/\/$/, "")}/link/${encodeURIComponent(id)}/${encodeURIComponent(fp)}`, name }), { mode: 0o600 });
  chmodSync(file, 0o600);
  const url = pathToFileURL(file).href;
  const cleanup = () => {
    process.removeListener("exit", cleanup);
    rmSync(dir, { recursive: true, force: true });
  };
  process.once("exit", cleanup);
  let opened = true;
  try {
    await openBrowser(url);
  } catch {
    opened = false;
    log(`Couldn't open a browser. Open this file to see the code: ${file}`);
  }
  return { file, url, opened, cleanup };
}
