// The "link this computer" sign-in of `salt-mcp --as-me`: the computer shows a QR code, the owner's phone scans
// and approves it, and the computer gets a linked-device token plus the owner's messages key, sealed to a key
// this computer made. The server only ever sees ciphertext. Contract: worktrees/DEVICE_LINK_CONTRACT.md.
//
//   begin     make an openpgp curve25519 keypair, POST /api/v1/device_links {public_key,name}, open
//             a local page (src/link-store.mjs showLinkPage: an inline-SVG QR of {host}/link/<id>/<fp>, in a 0700 temp dir,
//             deleted when the link ends or the process exits) in the browser (/usr/bin/open, args array), then poll
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
//   who       after a link, stderr says "Linked as @handle (name)" and the first tool result starts with
//             "Linked to Salt as @handle." so the person sees which account it joined. The first reopen of a link
//             with no SALT_ME_HANDLE writes the linked handle into the file as the pin, and a reopened file whose
//             user is not the pin is refused.
//   the key   the device PRIVATE key is not in that file: on macOS it is in the login Keychain (generic password,
//             service "salt-mcp-link", account <host-slug>), written through `security -i` with the command on
//             STDIN and read back with `security find-generic-password -w`, so it is never on a command line.
//             Elsewhere it falls back to the file, and a line on stderr says so. The Keychain keeps the key out of
//             backups and out of plain files, but any program running as you can still read it, and the token in
//             the file can send as you. Unlinking from your phone cuts this computer off from Salt; if you think
//             it was misused, unlink it and change your password.
//
// No token, key or sealed key is logged or put in an error message.

import { readFileSync, rmSync } from "node:fs";
import { hostname as osHostname } from "node:os";
import { join } from "node:path";
import { loadOpenpgp } from "./local-decrypt.mjs";
import { createKeychain, defaultBaseDir, defaultOpen, defaultRunCommand, defaultSetTimer, hostSlug, showLinkPage, writePrivateJson } from "./link-store.mjs";

export { defaultBaseDir, hostSlug };

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

const KEYCHAIN_SERVICE = "salt-mcp-link";

const NOT_TRUSTED = "Couldn't trust the link: the key sent to this computer was not signed by your Salt key. Nothing was saved.";

/** Reads a sealed payload: v1 `{private_key, fingerprint}` or v2 `{keys:[{private_key, fingerprint, generation, active}]}`. Throws on any other shape. */
function parsePayload(payload) {
  if (payload?.v === 1 && typeof payload.private_key === "string") {
    return { userId: payload.user_id, keys: [{ private_key: payload.private_key, fingerprint: String(payload.fingerprint), generation: 1, active: true }] };
  }
  if (payload?.v === 2 && Array.isArray(payload.keys) && payload.keys.length) {
    const keys = payload.keys.map((k) => ({ private_key: k?.private_key, fingerprint: String(k?.fingerprint), generation: Number(k?.generation), active: k?.active === true }));
    if (keys.some((k) => typeof k.private_key !== "string" || !Number.isFinite(k.generation))) throw new Error("shape");
    if (keys.filter((k) => k.active).length !== 1) throw new Error("shape");
    return { userId: payload.user_id, keys };
  }
  throw new Error("shape");
}

/** True when some signature in `signatures` verifies and was made by `key` (any of its key ids). */
async function signedBy(signatures, key) {
  const ids = key.getKeyIDs();
  for (const sig of signatures) {
    if (!ids.some((id) => id.equals(sig.keyID))) continue;
    try {
      if (await sig.verified) return true;
    } catch {
      // a bad signature does not count
    }
  }
  return false;
}

/** Decrypts `sealed` with the device key and checks it was signed by EVERY key in `verificationKeys`. Returns the parsed payload. */
async function openSigned({ sealed, devicePrivateKey, verificationKeys }) {
  const openpgp = await loadOpenpgp();
  const { data, signatures } = await openpgp.decrypt({
    message: await openpgp.readMessage({ armoredMessage: sealed }),
    decryptionKeys: await openpgp.readPrivateKey({ armoredKey: devicePrivateKey }),
    verificationKeys,
  });
  for (const key of verificationKeys) if (!(await signedBy(signatures, key))) throw new Error("unsigned");
  const parsed = parsePayload(JSON.parse(String(data)));
  // Every key must really be the one its fingerprint claims.
  for (const k of parsed.keys) {
    const fp = (await openpgp.readPrivateKey({ armoredKey: k.private_key })).getFingerprint();
    if (fp.toLowerCase() !== k.fingerprint.toLowerCase()) throw new Error("fingerprint");
  }
  return parsed;
}

const toResult = (parsed) => {
  const active = parsed.keys.find((k) => k.active);
  return {
    privateKey: active.private_key,
    retiredPrivateKeys: [...parsed.keys].filter((k) => !k.active).sort((a, b) => b.generation - a.generation).map((k) => k.private_key),
    userId: parsed.userId,
    generation: active.generation,
    fingerprint: active.fingerprint,
  };
};

/**
 * Opens the sealed key. The sealed key must be encrypted to this computer's key AND signed by the owner's key
 * (the public key is fetched with the linked token), the fingerprint inside must be the owner's, and when
 * `expectUserId` is given the user_id inside must be it. Returns `{ privateKey, retiredPrivateKeys, userId, generation }`
 * (the armored active owner private key and the older generations of a v2 payload); throws LinkError kind "unlinked"
 * on a 401 device_unlinked.
 *
 * `heldFingerprint` (the active key this computer verified when it stored the payload) lets a stored payload still open
 * after the owner reset their key and before this computer picked the new one up: it is accepted when it is signed by
 * that very key. A link file made before key resets recorded no such fingerprint: for a `storedLink` the payload's own
 * active key stands in for it (it was verified when the link was made; the file is private to the user).
 */
export async function openSealedKey({ host, fetchImpl = fetch, token, sealed_key, device_private_key, expectUserId, heldFingerprint, storedLink = false }) {
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
    let parsed;
    try {
      parsed = await openSigned({ sealed: sealed_key, devicePrivateKey: device_private_key, verificationKeys: [ownerKey] });
      if (String(parsed.keys.find((k) => k.active).fingerprint).toLowerCase() !== ownerKey.getFingerprint().toLowerCase()) throw new Error("fingerprint");
    } catch (err) {
      // The owner reset their key and this computer has not picked it up yet: the stored payload is signed by the key
      // it was stored under, not the server's new one.
      if (!heldFingerprint && !storedLink) throw err;
      const held = await openSigned({ sealed: sealed_key, devicePrivateKey: device_private_key, verificationKeys: [] });
      const active = held.keys.find((k) => k.active);
      if (heldFingerprint && active.fingerprint.toLowerCase() !== String(heldFingerprint).toLowerCase()) throw new Error("held");
      const heldPublic = (await openpgp.readPrivateKey({ armoredKey: active.private_key })).toPublic();
      parsed = await openSigned({ sealed: sealed_key, devicePrivateKey: device_private_key, verificationKeys: [heldPublic] });
    }
    if (expectUserId !== undefined && expectUserId !== null && String(parsed.userId) !== String(expectUserId)) throw new Error("user");
    return toResult(parsed);
  } catch {
    throw new LinkError(NOT_TRUSTED, { kind: "verify" });
  }
}

/**
 * A v2 re-seal picked up after the owner reset their chat key. It must be encrypted to this computer's key, carry the
 * signature of the generation this computer already holds (`held`, the armored held active private key) AND the
 * signature of the new active key, name the same user, hold a newer active generation and still include the held key.
 * A payload signed only by the new key is refused: Salt cannot plant a key of its own. Returns the same shape as
 * openSealedKey; throws (generic) on any refusal.
 */
export async function openReseal({ sealed_key, device_private_key, heldPrivateKey, heldFingerprint, heldGeneration, expectUserId }) {
  const openpgp = await loadOpenpgp();
  const heldPublic = (await openpgp.readPrivateKey({ armoredKey: heldPrivateKey })).toPublic();
  // First read without a signature requirement to learn the new key, then require both.
  const peek = await openSigned({ sealed: sealed_key, devicePrivateKey: device_private_key, verificationKeys: [] });
  const next = peek.keys.find((k) => k.active);
  const newPublic = (await openpgp.readPrivateKey({ armoredKey: next.private_key })).toPublic();
  const parsed = await openSigned({ sealed: sealed_key, devicePrivateKey: device_private_key, verificationKeys: [heldPublic, newPublic] });
  if (String(parsed.userId) !== String(expectUserId)) throw new Error("user");
  if (!parsed.keys.some((k) => k.fingerprint.toLowerCase() === String(heldFingerprint).toLowerCase())) throw new Error("held key missing");
  if (!(next.generation > heldGeneration)) throw new Error("not newer");
  return toResult(parsed);
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
  let pending = null;
  let justLinked = null; // { handle, name } until the first tool result has said so // { id, pollSecret, expiresAt, url, opened, timer, privateKey, name }

  /** Ends the link in progress for good: forgets it and deletes its code page. */
  function finish(p) {
    p?.page?.cleanup();
    if (pending === p) pending = null;
  }

  /** The stored link, or null when there is none (or it is not one of ours). */
  function read() {
    try {
      const link = JSON.parse(readFileSync(file, "utf8"));
      return link?.v === 1 && typeof link.token === "string" && link.token.startsWith("sld_") && typeof link.sealed_key === "string" && (typeof link.device_private_key === "string" || link.key_store === "keychain") ? link : null;
    } catch {
      return null;
    }
  }

  const write = (link) => writePrivateJson(baseDir, file, link);

  // The device private key, base64 so it is one token. Written through `security -i` on stdin; read from stdout.
  const keychain = createKeychain({ runCommand, service: KEYCHAIN_SERVICE, account: slug });
  const keychainSet = keychain.set;
  const keychainGet = keychain.get;

  /** The stored link with its device private key (from the Keychain when it lives there), or null if either is gone. */
  async function load() {
    const link = read();
    if (!link) return null;
    // Self-pin: the pinned handle (SALT_ME_HANDLE, else the one written on the first reopen) must be the link's user.
    const handle = String(link.user?.handle ?? "").toLowerCase();
    const wanted = pin ?? link.pin_handle ?? null;
    if (wanted && handle !== wanted) throw new LinkError("This link belongs to a different account than the one this computer is pinned to. Run --unlink, then link again.", { kind: "pin" });
    if (!wanted && handle) write({ ...link, pin_handle: handle });
    if (link.device_private_key) return link;
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
    if (onMac) await keychain.remove();
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
      finish(p);
      let link = null;
      try {
        const body = await res.json();
        link = { v: 1, host: base, token: body.token, device_private_key: p.privateKey, sealed_key: body.sealed_key, user: body.user, linked_device: body.linked_device ?? { id: null, name: p.name }, linked_at: new Date(now()).toISOString() };
        const opened = await openSealedKey({ host: base, fetchImpl: doFetch, token: link.token, sealed_key: link.sealed_key, device_private_key: link.device_private_key, expectUserId: link.user?.id ?? "" });
        link.sealed_key_generation = opened.generation;
        link.held_fingerprint = opened.fingerprint;
        if (pin && String(link.user?.handle ?? "").toLowerCase() !== pin) throw new Error("pin");
        await store(link);
        const shown = (v) => String(v ?? "").replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, "").slice(0, 80);
        justLinked = { handle: shown(link.user?.handle) };
        log(`Linked as @${justLinked.handle} (${shown(link.user?.name)})`);
      } catch {
        // Refused: nothing is stored, and the token just issued is cancelled so it cannot be used by anyone.
        if (link?.token) await unlinkRemote(link);
      }
      return;
    }
    if (res && (res.status === 410 || res.status === 404)) {
      finish(p);
      return;
    }
    if (now() >= p.expiresAt) {
      finish(p);
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
    const page = await showLinkPage({ host: base, id: made.id, fp: fingerprint, name, openBrowser, log });
    const p = { id: made.id, pollSecret: made.poll_secret, expiresAt: Date.parse(made.expires_at) || now() + 15 * 60000, url: page.file, opened: page.opened, page, timer: null, privateKey, name };
    pending = p;
    p.timer = setTimer(() => poll(p), POLL_MS);
    return { url: page.file, opened: page.opened };
  }

  /** Cancels the link in progress, if any. */
  function cancel() {
    if (pending?.timer) clearTimer(pending.timer);
    finish(pending);
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

  const sealedPath = `${base}/api/v1/linked_devices/self/sealed_key`;
  const authed = (link, init = {}) => ({ ...init, headers: { Accept: "application/json", Authorization: `Bearer ${link.token}`, ...init.headers }, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });

  /** Tells Salt this computer holds the new generation (POST .../ack; DELETE on the sealed_key itself where that is the route). Best effort. */
  async function ackPickup(link, generation) {
    try {
      let res = await doFetch(`${sealedPath}/ack`, authed(link, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ generation }) }));
      if (res.status === 404 || res.status === 405) res = await doFetch(sealedPath, authed(link, { method: "DELETE" }));
      return res.ok;
    } catch {
      return false;
    }
  }

  /**
   * Picks up a v2 re-seal after the owner reset their chat key. Resolves
   *   { status: "none" }                      nothing waiting (or this computer already holds it: acked again)
   *   { status: "picked_up", generation }     verified, stored (the link file's sealed key is replaced), acked
   *   { status: "refused" }                   verification failed: nothing stored, nothing acked, the old key still reads
   * and throws LinkError kind "unlinked" on 401 device_unlinked, kind "network" when Salt cannot be reached.
   */
  async function pickup(link) {
    let res;
    try {
      res = await doFetch(sealedPath, authed(link));
    } catch {
      throw new LinkError("Couldn't reach Salt. Check the connection and try again.", { kind: "network" });
    }
    if (res.status === 401) {
      const body = await res.json().catch(() => null);
      if (body?.code === "device_unlinked") throw new LinkError("This computer was unlinked.", { status: 401, kind: "unlinked" });
      throw new LinkError("Salt refused the link (401).", { status: 401, kind: "link" });
    }
    if (res.status === 204 || res.status === 404) return { status: "none" };
    if (!res.ok) throw new LinkError(`Salt answered the key pickup with ${res.status}.`, { status: res.status, kind: "link" });
    const body = await res.json().catch(() => null);
    const sealed = body?.sealed_key;
    if (typeof sealed !== "string" || !sealed) return { status: "none" };
    const generation = Number(body.generation);
    const held = Number(link.sealed_key_generation ?? 1);
    if (Number.isFinite(generation) && generation <= held) {
      await ackPickup(link, generation); // already held (an ack that did not land last time)
      return { status: "none" };
    }
    try {
      const current = await openSealedKey({ host: base, fetchImpl: doFetch, token: link.token, sealed_key: link.sealed_key, device_private_key: link.device_private_key, heldFingerprint: link.held_fingerprint, storedLink: true });
      const next = await openReseal({
        sealed_key: sealed,
        device_private_key: link.device_private_key,
        heldPrivateKey: current.privateKey,
        heldFingerprint: current.fingerprint,
        heldGeneration: held,
        expectUserId: link.user?.id ?? "",
      });
      if (Number.isFinite(generation) && next.generation !== generation) throw new Error("generation");
      const { device_private_key: key, ...rest } = link;
      write({ ...rest, ...(link.key_store === "file" ? { device_private_key: key } : {}), sealed_key: sealed, sealed_key_generation: next.generation, held_fingerprint: next.fingerprint });
      await ackPickup(link, next.generation);
      return { status: "picked_up", generation: next.generation };
    } catch (err) {
      if (err instanceof LinkError && err.kind !== "verify") throw err;
      return { status: "refused" };
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
    /** The account just linked, once; null after that. */
    takeLinked() {
      const j = justLinked;
      justLinked = null;
      return j;
    },
    get linking() {
      return pending !== null;
    },
    open: (link) => openSealedKey({ host: base, fetchImpl: doFetch, token: link.token, sealed_key: link.sealed_key, device_private_key: link.device_private_key, heldFingerprint: link.held_fingerprint, storedLink: true }),
    pickup,
  };
}
