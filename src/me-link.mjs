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
//   a refusal  if anything after a successful claim fails (bad signature, wrong fingerprint, the sealed key's
//             user_id is not the claim's user, an account other than the pinned SALT_ME_HANDLE, a store error),
//             nothing is stored and the just-issued token is cancelled at once (DELETE /linked_devices/<id>).
//   the file  ~/Library/Application Support/salt-mcp/link-<host-slug>.json, directory 0700, file 0600, written to
//             a temp file and renamed, and excluded from Time Machine (best effort). It holds the token, the sealed
//             key, the user and the linked device. A program running as you can read it, and with the token it can
//             read your chats and send as you (to people and to your agents), but never reach wallets, money,
//             settings, keys or the vault. Cancel it from the phone (Connections) or with `--unlink`.
//   the key   the device PRIVATE key is not in that file: on macOS it is in the login Keychain (generic password,
//             service "salt-mcp-link", account <host-slug>), written through `security -i` with the command on
//             STDIN and read back with `security find-generic-password -w`, so it is never on a command line.
//             Elsewhere it falls back to the file, and a line on stderr says so.
//
// No token, key or sealed key is logged or put in an error message.

import { execFile as nodeExecFile, spawn } from "node:child_process";
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
// Runs a program with an argument array (never a shell); `input` goes to its stdin. Resolves stdout.
const defaultRunCommand = (file, args, { input } = {}) =>
  new Promise((resolve, reject) => {
    const child = spawn(file, args, { stdio: ["pipe", "pipe", "ignore"] });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.on("error", reject);
    child.on("close", (code) => (code === 0 ? resolve(out) : reject(new Error(`${file} exit ${code}`))));
    child.stdin.on("error", () => {});
    child.stdin.end(input ?? "");
  });
const KEYCHAIN_SERVICE = "salt-mcp-link";
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
 * (the public key is fetched with the linked token), the fingerprint inside must be the owner's, and when
 * `expectUserId` is given the user_id inside must be it. Returns `{ privateKey, userId }` (the armored owner
 * private key); throws LinkError kind "unlinked" on a 401 device_unlinked.
 */
export async function openSealedKey({ host, fetchImpl = fetch, token, sealed_key, device_private_key, expectUserId }) {
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
    if (expectUserId !== undefined && expectUserId !== null && String(payload.user_id) !== String(expectUserId)) throw new Error("user");
    return { privateKey: payload.private_key, userId: payload.user_id };
  } catch {
    throw new LinkError("Couldn't trust the link: the key sent to this computer was not signed by your Salt key. Nothing was saved.", { kind: "verify" });
  }
}

/**
 * @param {{
 *   host: string, fetchImpl?: typeof fetch, baseDir?: string, hostname?: string,
 *   openBrowser?: (url: string) => Promise<unknown>, setTimer?: (fn: Function, ms: number) => unknown,
 *   clearTimer?: (handle: unknown) => void, now?: () => number, pinHandle?: string|null,
 *   runCommand?: (file: string, args: string[], opts?: {input?: string}) => Promise<string>, platform?: string, log?: (msg: string) => void,
 * }} options
 * Everything but `host` and `pinHandle` exists for tests (a fake clock, timer, browser, directory, keychain runner).
 * `pinHandle` (SALT_ME_HANDLE) refuses a link approved by any other account.
 */
export function createLinkClient({ host, fetchImpl, baseDir = defaultBaseDir(), hostname = osHostname(), openBrowser = defaultOpen, setTimer = defaultSetTimer, clearTimer = clearTimeout, now = () => Date.now(), pinHandle = null, runCommand = defaultRunCommand, platform = process.platform, log = (m) => console.error("[salt-mcp]", m) }) {
  const base = host.replace(/\/$/, "");
  const doFetch = fetchImpl ?? fetch;
  const file = join(baseDir, `link-${hostSlug(base)}.json`);
  const slug = hostSlug(base);
  const onMac = platform === "darwin";
  const pin = pinHandle ? String(pinHandle).trim().replace(/^@/, "").toLowerCase() : null;
  let pending = null; // { id, pollSecret, expiresAt, url, opened, timer, privateKey, name }

  /** The stored link, or null when there is none (or it is not one of ours). */
  function read() {
    try {
      const link = JSON.parse(readFileSync(file, "utf8"));
      return link?.v === 1 && typeof link.token === "string" && link.token.startsWith("sld_") && typeof link.sealed_key === "string" && (typeof link.device_private_key === "string" || link.key_store === "keychain") ? link : null;
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

  // The device private key, base64 so it is one token. Written through `security -i` on stdin; read from stdout.
  const keychainSet = (armored) => runCommand("/usr/bin/security", ["-i"], { input: `add-generic-password -U -s ${KEYCHAIN_SERVICE} -a ${slug} -w ${Buffer.from(armored, "utf8").toString("base64")}\n` });
  const keychainGet = async () => {
    try {
      const out = String(await runCommand("/usr/bin/security", ["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", slug, "-w"])).trim();
      return out ? Buffer.from(out, "base64").toString("utf8") : null;
    } catch {
      return null;
    }
  };

  /** The stored link with its device private key (from the Keychain when it lives there), or null if either is gone. */
  async function load() {
    const link = read();
    if (!link || link.device_private_key) return link;
    const key = await keychainGet();
    return key ? { ...link, device_private_key: key } : null;
  }

  /** Writes the link: key to the Keychain on macOS (a failure there refuses the link), else into the file with a stderr note. */
  async function store(link) {
    const { device_private_key: key, ...rest } = link;
    if (onMac) {
      await keychainSet(key);
      write({ ...rest, key_store: "keychain" });
      await runCommand("/usr/bin/tmutil", ["addexclusion", file]).catch(() => {});
    } else {
      log("no macOS Keychain here: the device key is kept in the link file (readable by programs running as you)");
      write({ ...rest, device_private_key: key, key_store: "file" });
    }
  }

  /** Removes the file and the Keychain item (best effort for the item). */
  async function remove() {
    rmSync(file, { force: true });
    if (onMac) await runCommand("/usr/bin/security", ["delete-generic-password", "-s", KEYCHAIN_SERVICE, "-a", slug]).catch(() => {});
  }

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
      pending = null;
      let link = null;
      try {
        const body = await res.json();
        link = { v: 1, host: base, token: body.token, device_private_key: p.privateKey, sealed_key: body.sealed_key, user: body.user, linked_device: body.linked_device ?? { id: null, name: p.name }, linked_at: new Date(now()).toISOString() };
        await openSealedKey({ host: base, fetchImpl: doFetch, token: link.token, sealed_key: link.sealed_key, device_private_key: link.device_private_key, expectUserId: link.user?.id ?? "" });
        if (pin && String(link.user?.handle ?? "").toLowerCase() !== pin) throw new Error("pin");
        await store(link);
      } catch {
        // Refused: nothing is stored, and the token just issued is cancelled so it cannot be used by anyone.
        if (link?.token) await unlinkRemote(link);
      }
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
    load,
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
