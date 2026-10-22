// The owner's signed-in Salt session for `salt-mcp --as-me`: sign in once,
// unlock the messages key locally, and make authenticated requests as the
// owner -- exactly what the Salt website does in a browser.
//
//   sign in   POST {host}/auth/sign_in {user:{email,password:authString}}; the JWT comes back in the
//             `Authorization` RESPONSE header and is sent back verbatim. 30 days, no refresh, a 401 means sign in
//             again. Rack::Attack allows 5 sign-ins per email per 20 s, so this signs in once per process and
//             remembers a failure for a while instead of retrying on every tool call.
//   unlock    GET /api/v1/userkeys, and (for a vault key) GET /api/v1/vault; see me-crypto.mjs.
//
// LINK MODE (the default of --as-me, me-link.mjs): there is no sign-in. The stored `sld_` linked-device token is
// the `Authorization: Bearer` of every call, the key is the one the phone sealed to this computer, and a 401 with
// code device_unlinked deletes the link file and starts a new link. /auth/sign_in, /auth/sign_out and
// /api/v1/vault are never called. The password path below is --password.
//
// Everything is lazy: nothing happens until the first tool call, which asks
// the owner for the password (me-secrets.mjs). The raw password, the vault wrap
// and the DEK exist only inside unlock(); the password reference is dropped when
// it returns and what stays in memory is the signed-in token and the opened PGP
// key. On exit signOut() revokes the token. In password mode nothing in this file writes to disk (the link file is me-link.mjs's),
// and no request, header or body is ever logged.

import {
  authString,
  unwrapMessagesDek,
  readArmoredPrivateKey,
  openPrivateKey,
  openRetiredPrivateKeys,
  createMessageDecryptor,
  MAX_ATTACHMENT_BYTES,
} from "./me-crypto.mjs";
import { LINK_FIRST, LinkError } from "./me-link.mjs";

export const DEFAULT_HOST = "https://saltapp.ai";

export class MeError extends Error {
  constructor(message, { status, kind } = {}) {
    super(message);
    this.name = "MeError";
    this.status = status;
    this.kind = kind;
  }
}

export const UNLOCK_FAILED = "Couldn't unlock: the Salt password didn't open your messages key. Try again.";
export const SIGN_IN_FAILED =
  "Couldn't sign in: check the Salt password. If this account is older, sign in on saltapp.ai once, then try again.";

const REQUEST_TIMEOUT_MS = 30000;
// A failed (or declined) unlock is remembered this long, so a wrong password costs one sign-in and a cancelled dialog
// does not come straight back, instead of once per tool call.
const FAILURE_MEMORY_MS = 30000;

/**
 * @param {{
 *   host?: string, email?: string, readEmail?: () => Promise<string>,
 *   readPassword: (kind: "login"|"vault") => Promise<string>,
 *   fetchImpl?: typeof fetch, now?: () => number, signInIterations?: number, linkClient?: ReturnType<typeof import('./me-link.mjs').createLinkClient>,
 * }} options
 * `signInIterations` exists for tests; production never passes it. With a `linkClient` the session runs in LINK mode
 * (the default sign-in of --as-me): the stored `sld_` token replaces the JWT for every call, nothing is signed in
 * or out, and the key comes from the phone-sealed key; without one it is the password path (--password).
 */
export function createMeSession({ host = DEFAULT_HOST, email = null, readEmail, readPassword, fetchImpl, now = () => Date.now(), signInIterations, linkClient = null }) {
  const base = host.replace(/\/$/, "");
  const doFetch = fetchImpl ?? fetch;

  let token = null; // "Bearer <jwt>", verbatim
  let signedInAt = 0;
  let user = null; // { id, username, display_name }
  let lockMode = null;
  let privateKey = null;
  let decryptText = null;
  let unlocking = null;
  let failure = null; // { error, at }
  let signInFlight = null;
  const linkMode = Boolean(linkClient);

  const linkPending = (started) => new MeError(started.opened ? LINK_FIRST : `${LINK_FIRST} If no page opened, open this address: ${started.url}`, { kind: "link_pending" });
  const asMeError = (err) => (err instanceof LinkError ? new MeError(err.message, { status: err.status, kind: err.kind }) : err);

  /** The link is gone (unlinked from the phone, or never made): forget it and start linking. Always throws. */
  async function relink() {
    await linkClient.remove();
    token = null;
    privateKey = null;
    decryptText = null;
    try {
      throw linkPending(await linkClient.begin());
    } catch (err) {
      throw asMeError(err);
    }
  }

  async function send(method, path, { body, headers = {}, authed = true, as = "json" } = {}) {
    const init = {
      method,
      headers: { Accept: as === "json" ? "application/json" : "*/*", ...headers },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    };
    if (authed && token) init.headers.Authorization = token;
    if (body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    let res;
    try {
      res = await doFetch(`${base}${path}`, init);
    } catch {
      throw new MeError("Couldn't reach Salt. Check the connection and try again.", { kind: "network" });
    }
    return res;
  }

  async function signIn() {
    email ??= await readEmail();
    const password = await readPassword("login");
    const secret = await authString(password, signInIterations);
    const res = await send("POST", "/auth/sign_in", { body: { user: { email, password: secret } }, authed: false });
    if (res.status === 401 || res.status === 403) throw new MeError(SIGN_IN_FAILED, { status: res.status, kind: "sign_in" });
    if (res.status === 429) throw new MeError("Salt is rate limiting sign-ins. Wait a minute and try again.", { status: 429, kind: "rate_limit" });
    if (!res.ok) throw new MeError(`Salt answered the sign-in with ${res.status}.`, { status: res.status, kind: "sign_in" });
    const header = res.headers.get("authorization");
    if (!header) throw new MeError("Salt signed in but sent no session. Try again.", { kind: "sign_in" });
    let body = null;
    try {
      body = await res.json();
    } catch {
      body = null;
    }
    const account = body?.user ?? body;
    token = header;
    signedInAt = now();
    user = { id: account?.id ?? null, username: account?.username ?? null, display_name: account?.display_name ?? null };
    return { password };
  }

  /** One request as the owner. A 401 means the 30-day session ended: sign in again once and retry. */
  async function request(method, path, opts = {}) {
    if (linkMode) {
      const res = await send(method, path, opts);
      if (res.status === 401 && (await res.clone().json().catch(() => null))?.code === "device_unlinked") await relink();
      return res;
    }
    if (!token) await ensureSignedIn();
    let res = await send(method, path, opts);
    if (res.status === 401 && !opts.retried) {
      token = null;
      await ensureSignedIn();
      res = await send(method, path, { ...opts, retried: true });
    }
    return res;
  }

  async function ensureSignedIn() {
    signInFlight ??= signIn().then(() => undefined).finally(() => {
      signInFlight = null;
    });
    return signInFlight;
  }

  const failFor = (res, path) => {
    const hint = res.status === 404 ? "not found" : res.status === 403 ? "not allowed" : String(res.status);
    return new MeError(`Salt answered ${path.split("?")[0]} with ${hint}.`, { status: res.status });
  };

  async function getJson(path) {
    const res = await request("GET", path);
    if (!res.ok) throw failFor(res, path);
    return res.json();
  }

  // A 409 pickup_required: the owner reset their chat key and this computer has not picked the new one up. Pick it up
  // and send again, once.
  async function pickupThenRetry(res) {
    if (!linkMode || res.status !== 409 || (await res.clone().json().catch(() => null))?.code !== "pickup_required") return null;
    const link = await loadLinked();
    const status = await pickUpLinked(link);
    if (status === "needs_relink") await relink();
    if (status !== "picked_up") return null;
    await openLinked((await linkClient.load()) ?? link);
    return true;
  }

  async function postJson(path, body, headers) {
    let res = await request("POST", path, { body, headers });
    if (await pickupThenRetry(res)) res = await request("POST", path, { body, headers });
    if (!res.ok) {
      let detail = "";
      let refusal;
      try {
        const j = await res.json();
        if (typeof j?.error === "string") detail = `: ${j.error}`;
        refusal = j;
      } catch {
        // no body worth showing
      }
      const err = new MeError(`Salt refused the message (${res.status})${detail}`, { status: res.status });
      // The refusal's machine code and (for stale_recipient_keys) the current members, so a sender can re-encrypt once.
      if (refusal && typeof refusal === "object") err.body = { code: refusal.code, members: refusal.members };
      throw err;
    }
    return res.json();
  }

  async function getBytes(path, maxBytes = MAX_ATTACHMENT_BYTES + 16) {
    const res = await request("GET", path, { as: "bytes" });
    if (!res.ok) throw failFor(res, path);
    const declared = Number(res.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > maxBytes) throw new MeError("That file is larger than 15 MB; not downloading it.", { kind: "too_large" });
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > maxBytes) throw new MeError("That file is larger than 15 MB; not downloading it.", { kind: "too_large" });
    return buf;
  }

  // Link mode: the stored link, or a new one started (which asks the owner to scan it, so this throws).
  // After the owner resets their chat key the phone re-seals the new keyring to this computer: it is picked up here
  // (checked, stored, acknowledged) before the key is opened. A pickup that fails or is refused is not fatal: the held
  // key still reads old history.
  async function loadLinked() {
    let link;
    try {
      link = await linkClient.load();
    } catch (err) {
      throw asMeError(err);
    }
    if (!link) await relink();
    token = `Bearer ${link.token}`;
    user = { id: link.user?.id ?? null, username: link.user?.handle ?? null, display_name: link.user?.name ?? null };
    return link;
  }

  async function openLinked(link) {
    let opened;
    try {
      opened = await linkClient.open(link);
    } catch (err) {
      if (err?.kind === "unlinked") await relink();
      throw asMeError(err);
    }
    lockMode = "link";
    privateKey = await openPrivateKey(opened.privateKey);
    const retired = [];
    for (const armored of opened.retiredPrivateKeys ?? []) retired.push(await openPrivateKey(armored).catch(() => null));
    const ring = retired.filter(Boolean);
    decryptText = createMessageDecryptor(ring.length ? [privateKey, ...ring] : privateKey);
  }

  async function pickUpLinked(link) {
    try {
      return (await linkClient.pickup(link)).status;
    } catch (err) {
      if (err?.kind === "unlinked") await relink();
      return "error";
    }
  }

  async function unlockLinked() {
    const link = await loadLinked();
    if ((await pickUpLinked(link)) === "needs_relink") await relink(); // the pending key expired: link again
    await openLinked((await linkClient.load()) ?? link);
  }

  async function unlock() {
    if (linkMode) return unlockLinked();
    const { password } = await signIn();
    const userKeys = await getJson("/api/v1/userkeys");
    const userKey = Array.isArray(userKeys) ? userKeys[0] : userKeys;
    let armored;
    let retiredKeys = [];
    if (userKey?.encrypted_private_key) {
      const vault = await getJson("/api/v1/vault");
      lockMode = vault?.lock_mode ?? null;
      let dek;
      try {
        dek = await unwrapMessagesDek({ vault, vaultPassword: password });
      } catch (err) {
        // A separate lock password: the login password is tried first because plenty of "separate" vaults were set
        // to the same words; only if it does not open the vault is the owner asked for the second one.
        if (lockMode === "login") throw err;
        dek = await unwrapMessagesDek({ vault, vaultPassword: await readPassword("vault") });
      }
      armored = await readArmoredPrivateKey({ userKey, dek });
      retiredKeys = await openRetiredPrivateKeys({ retired: userKey.retired, dek });
    } else {
      lockMode = "legacy";
      armored = await readArmoredPrivateKey({ userKey });
    }
    privateKey = await openPrivateKey(armored);
    // Active key first, then retired generations. Sending and encrypting still use the active key only.
    decryptText = createMessageDecryptor(retiredKeys.length ? [privateKey, ...retiredKeys] : privateKey);
  }

  /** Signs in and unlocks on first use. Resolves once; a failure is remembered for a minute. */
  async function ensureUnlocked() {
    if (decryptText) return;
    if (failure && now() - failure.at < FAILURE_MEMORY_MS) throw failure.error;
    unlocking ??= unlock()
      .then(() => {
        failure = null;
      })
      .catch((err) => {
        token = null;
        privateKey = null;
        decryptText = null;
        const error = err instanceof MeError ? err : err?.declined ? new MeError(err.message, { kind: "declined" }) : new MeError(UNLOCK_FAILED, { kind: "unlock" });
        // "Scan the code first" is not a failure to remember: the next call should look again at once.
        if (error.kind !== "link_pending") failure = { error, at: now() };
        throw error;
      })
      .finally(() => {
        unlocking = null;
      });
    return unlocking;
  }

  /** Revokes this process's session and lets go of the key. Best effort, once; safe to call at any time. */
  async function signOut() {
    const had = token;
    token = null;
    privateKey = null;
    decryptText = null;
    if (!had || linkMode) return; // a link has no session to revoke: it is cancelled from the phone or with --unlink
    try {
      await doFetch(`${base}/auth/sign_out`, { method: "DELETE", headers: { Accept: "application/json", Authorization: had }, signal: AbortSignal.timeout(3000) });
    } catch {
      // The session simply runs out in 30 days; nothing else to do on the way out.
    }
  }

  return {
    get email() {
      return email;
    },
    signOut,
    ensureUnlocked,
    /** In link mode: `Linked to Salt as @handle.` once, for the first tool result after a link; else null. */
    takeLinkedNote: () => {
      const j = linkMode ? linkClient.takeLinked() : null;
      return j ? `Linked to Salt as @${j.handle}.` : null;
    },
    /** Reads and writes sign in and unlock first, so a tool never reaches Salt without the key being ready. */
    get: async (path) => (await ensureUnlocked(), getJson(path)),
    getBytes: async (path, maxBytes) => (await ensureUnlocked(), getBytes(path, maxBytes)),
    post: async (path, body, headers) => (await ensureUnlocked(), postJson(path, body, headers)),
    decrypt: async (body) => {
      await ensureUnlocked();
      return decryptText(body);
    },
    get me() {
      return user;
    },
    get host() {
      return base;
    },
    /** What the live socket needs: the websocket address and the raw token (no "Bearer "), after sign-in/unlock. */
    liveAuth: async () => {
      await ensureUnlocked();
      const raw = String(token || "").replace(/^Bearer\s+/i, "");
      if (!raw) throw new MeError("Not signed in.", { kind: "sign_in" });
      return { url: `${base.replace(/^http/, "ws")}/cable`, token: raw };
    },
    get status() {
      const link = linkMode ? linkClient.read() : null;
      return {
        ...(linkMode ? { linked: Boolean(link), device_name: link?.linked_device?.name ?? null, linked_at: link?.linked_at ?? null } : {}),
        unlocked: Boolean(decryptText),
        lock_mode: lockMode,
        signed_in_at: signedInAt ? new Date(signedInAt).toISOString() : null,
        token_age_days: signedInAt ? Math.floor((now() - signedInAt) / 86400000) : null,
      };
    },
  };
}
