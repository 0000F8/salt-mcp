// The "link this computer" sign-in of `salt-mcp --as-me`: the computer shows a QR code, the owner's phone scans
// and approves it, and the computer gets a linked-device token plus the owner's messages key, sealed to a key
// this computer made. The server only ever sees ciphertext. Contract: worktrees/DEVICE_LINK_CONTRACT.md.
//
//   begin     make an openpgp curve25519 keypair, POST /api/v1/device_links {public_key,name}, open
//             {host}/link/show#id=&fp=&name= in the browser (/usr/bin/open, args array), then poll
//             POST /device_links/:id/claim every 3 s in the background until approved, denied, expired or claimed.
//   claim     200 {token:"sld_...", sealed_key, user, linked_device} arrives once. Before anything is stored the
//             sealed key is opened and checked (see open): a key that is not signed by the owner's key, or whose
//             fingerprint is not the owner's, is refused and nothing is written.
//   the file  ~/Library/Application Support/salt-mcp/link-<host-slug>.json, directory 0700, file 0600, written to
//             a temp file and renamed. It holds the token and the device private key: a program running as you
//             can read it. The token reaches chat endpoints only (never wallets, money, settings, keys or the
//             vault) and is cancelled from the phone (Connections) or with `--unlink`.
//
// No token, key or sealed key is logged or put in an error message.

import { execFile as nodeExecFile } from "node:child_process";
import { chmodSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir, hostname as osHostname } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { loadOpenpgp } from "./local-decrypt.mjs";

export const LINK_FIRST = "Link this computer first: a page with a code opened in your browser. Scan it with your phone, then try again.";
export const POLL_MS = 3000;
const REQUEST_TIMEOUT_MS = 30000;
const NAME_MAX = 60;

export class LinkError extends Error {
  constructor(message, { status, kind } = {}) {
    super(message);
    this.name = "LinkError";
    this.status = status;
    this.kind = kind;
  }
}

const defaultExecFile = promisify(nodeExecFile);
const defaultOpen = (url) => defaultExecFile("/usr/bin/open", [url]);
const defaultSetTimer = (fn, ms) => {
  const handle = setTimeout(fn, ms);
  handle.unref?.();
  return handle;
};

export const defaultBaseDir = () => join(homedir(), "Library", "Application Support", "salt-mcp");
/** `https://saltapp.ai` -> `saltapp-ai`; the port stays, so a local server has its own link. */
export const hostSlug = (host) => new URL(host).host.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");

/**
 * Opens the sealed key. The sealed key must be encrypted to this computer's key AND signed by the owner's key
 * (the public key is fetched with the linked token), and the fingerprint inside must be the owner's. Returns the
 * armored owner private key; throws LinkError kind "unlinked" on a 401 device_unlinked.
 */
export async function openSealedKey({ host, fetchImpl = fetch, token, sealed_key, device_private_key }) {
  let res;
  try {
    res = await fetchImpl(`${host.replace(/\/$/, "")}/api/v1/userkeys`, {
      headers: { Accept: "application/json", Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch {
    throw new LinkError("Couldn't reach Salt. Check the connection and try again.", { kind: "network" });
  }
  if (res.status === 401) {
    const body = await res.json().catch(() => null);
    if (body?.code === "device_unlinked") throw new LinkError("This computer was unlinked.", { status: 401, kind: "unlinked" });
    throw new LinkError("Salt refused the link (401).", { status: 401, kind: "link" });
  }
  if (!res.ok) throw new LinkError(`Salt answered the key lookup with ${res.status}.`, { status: res.status, kind: "link" });
  const keys = await res.json();
  const ownerArmored = (Array.isArray(keys) ? keys[0] : keys)?.public_key;
  if (typeof ownerArmored !== "string") throw new LinkError("Couldn't check the link: Salt sent no public key for you.", { kind: "verify" });
  try {
    const openpgp = await loadOpenpgp();
    const ownerKey = await openpgp.readKey({ armoredKey: ownerArmored });
    const { data, signatures } = await openpgp.decrypt({
      message: await openpgp.readMessage({ armoredMessage: sealed_key }),
      decryptionKeys: await openpgp.readPrivateKey({ armoredKey: device_private_key }),
      verificationKeys: ownerKey,
    });
    if (!signatures.length) throw new Error("unsigned");
    await signatures[0].verified; // rejects on a bad signature
    const payload = JSON.parse(String(data));
    if (payload?.v !== 1 || typeof payload.private_key !== "string") throw new Error("shape");
    if (String(payload.fingerprint).toLowerCase() !== ownerKey.getFingerprint().toLowerCase()) throw new Error("fingerprint");
    return payload.private_key;
  } catch {
    throw new LinkError("Couldn't trust the link: the key sent to this computer was not signed by your Salt key. Nothing was saved.", { kind: "verify" });
  }
}

/**
 * @param {{
 *   host: string, fetchImpl?: typeof fetch, baseDir?: string, hostname?: string,
 *   openBrowser?: (url: string) => Promise<unknown>, setTimer?: (fn: Function, ms: number) => unknown,
 *   clearTimer?: (handle: unknown) => void, now?: () => number,
 * }} options
 * Everything but `host` exists for tests (a fake clock, timer, browser and directory).
 */
export function createLinkClient({ host, fetchImpl, baseDir = defaultBaseDir(), hostname = osHostname(), openBrowser = defaultOpen, setTimer = defaultSetTimer, clearTimer = clearTimeout, now = () => Date.now() }) {
  const base = host.replace(/\/$/, "");
  const doFetch = fetchImpl ?? fetch;
  const file = join(baseDir, `link-${hostSlug(base)}.json`);
  let pending = null; // { id, pollSecret, expiresAt, url, opened, timer, privateKey, name }

  /** The stored link, or null when there is none (or it is not one of ours). */
  function read() {
    try {
      const link = JSON.parse(readFileSync(file, "utf8"));
      return link?.v === 1 && typeof link.token === "string" && link.token.startsWith("sld_") && typeof link.sealed_key === "string" && typeof link.device_private_key === "string" ? link : null;
    } catch {
      return null;
    }
  }

  function write(link) {
    mkdirSync(baseDir, { recursive: true, mode: 0o700 });
    chmodSync(baseDir, 0o700);
    const tmp = `${file}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(link), { mode: 0o600 });
    chmodSync(tmp, 0o600);
    renameSync(tmp, file);
  }

  const remove = () => rmSync(file, { force: true });

  async function claim(p) {
    try {
      return await doFetch(`${base}/api/v1/device_links/${encodeURIComponent(p.id)}/claim`, {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({ poll_secret: p.pollSecret }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch {
      return null;
    }
  }

  // One poll. Pending (202), a network blip or a server hiccup try again in 3 s until the link's own expiry; any
  // other answer (410 denied/expired/claimed, 404) ends it, and the next tool call starts a fresh link.
  async function poll(p) {
    if (pending !== p) return;
    const res = await claim(p);
    if (pending !== p) return;
    if (res?.status === 200) {
      try {
        const body = await res.json();
        const link = { v: 1, host: base, token: body.token, device_private_key: p.privateKey, sealed_key: body.sealed_key, user: body.user, linked_device: body.linked_device ?? { id: null, name: p.name }, linked_at: new Date(now()).toISOString() };
        await openSealedKey({ host: base, fetchImpl: doFetch, token: link.token, sealed_key: link.sealed_key, device_private_key: link.device_private_key });
        write(link);
      } catch {
        // Not stored: the next tool call links again.
      }
      pending = null;
      return;
    }
    if (res && (res.status === 410 || res.status === 404)) {
      pending = null;
      return;
    }
    if (now() >= p.expiresAt) {
      pending = null;
      return;
    }
    p.timer = setTimer(() => poll(p), POLL_MS);
  }

  /** Starts a link (or reuses the one in progress). Resolves `{ url, opened }`; `opened` is false if the browser would not open. */
  async function begin() {
    if (pending) return { url: pending.url, opened: pending.opened };
    const openpgp = await loadOpenpgp();
    const name = `Claude on ${hostname}`.slice(0, NAME_MAX);
    const { privateKey, publicKey } = await openpgp.generateKey({ type: "ecc", curve: "curve25519", userIDs: [{ name }], format: "armored" });
    const fingerprint = (await openpgp.readKey({ armoredKey: publicKey })).getFingerprint();
    let res;
    try {
      res = await doFetch(`${base}/api/v1/device_links`, {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({ public_key: publicKey, name }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch {
      throw new LinkError("Couldn't reach Salt. Check the connection and try again.", { kind: "network" });
    }
    if (res.status === 429) throw new LinkError("Salt is rate limiting new links. Wait a while and try again.", { status: 429, kind: "rate_limit" });
    if (res.status !== 201) throw new LinkError(`Salt answered the link request with ${res.status}.`, { status: res.status, kind: "link" });
    const made = await res.json();
    const url = `${base}/link/show#id=${encodeURIComponent(made.id)}&fp=${encodeURIComponent(fingerprint)}&name=${encodeURIComponent(name)}`;
    const p = { id: made.id, pollSecret: made.poll_secret, expiresAt: Date.parse(made.expires_at) || now() + 15 * 60000, url, opened: true, timer: null, privateKey, name };
    try {
      await openBrowser(url);
    } catch {
      p.opened = false;
    }
    pending = p;
    p.timer = setTimer(() => poll(p), POLL_MS);
    return { url, opened: p.opened };
  }

  /** Cancels the link in progress, if any. */
  function cancel() {
    if (pending?.timer) clearTimer(pending.timer);
    pending = null;
  }

  /** DELETE the linked device with its own token (self-unlink). Best effort; the local file is the caller's to remove. */
  async function unlinkRemote(link) {
    const id = link?.linked_device?.id;
    if (!id) return false;
    try {
      const res = await doFetch(`${base}/api/v1/linked_devices/${encodeURIComponent(id)}`, {
        method: "DELETE",
        headers: { Accept: "application/json", Authorization: `Bearer ${link.token}` },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      return res.status === 204 || res.status === 401;
    } catch {
      return false;
    }
  }

  return {
    path: file,
    read,
    remove,
    begin,
    cancel,
    unlinkRemote,
    get linking() {
      return pending !== null;
    },
    open: (link) => openSealedKey({ host: base, fetchImpl: doFetch, token: link.token, sealed_key: link.sealed_key, device_private_key: link.device_private_key }),
  };
}
