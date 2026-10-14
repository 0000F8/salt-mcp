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
// Everything is lazy: nothing happens until the first tool call. The raw
// password, the vault wrap and the DEK exist only inside unlock(); what
// stays in memory is the signed-in token and the opened PGP key. Nothing in
// this file writes to disk, and no request, header or body is ever logged.

import { KEYCHAIN_SERVICE, KEYCHAIN_VAULT_SERVICE } from "./me-secrets.mjs";
import {
  authString,
  unwrapMessagesDek,
  readArmoredPrivateKey,
  openPrivateKey,
  createMessageDecryptor,
  MAX_ATTACHMENT_BYTES,
} from "./me-crypto.mjs";

export const DEFAULT_HOST = "https://saltapp.ai";

export class MeError extends Error {
  constructor(message, { status, kind } = {}) {
    super(message);
    this.name = "MeError";
    this.status = status;
    this.kind = kind;
  }
}

export const UNLOCK_FAILED = "Couldn't unlock: check the password saved for Salt MCP (run salt-mcp --as-me-setup)";
export const SIGN_IN_FAILED =
  "Couldn't sign in: check the password saved for Salt MCP (run salt-mcp --as-me-setup). If this account is older, sign in on saltapp.ai once, then try again.";

const REQUEST_TIMEOUT_MS = 30000;
// A failed unlock is remembered this long, so a wrong password costs one sign-in, not one per tool call.
const FAILURE_MEMORY_MS = 60000;

/**
 * @param {{
 *   host?: string, email: string,
 *   readPassword: (service: string) => Promise<string>,
 *   fetchImpl?: typeof fetch, now?: () => number, signInIterations?: number,
 * }} options
 * `signInIterations` exists for tests; production never passes it.
 */
export function createMeSession({ host = DEFAULT_HOST, email, readPassword, fetchImpl, now = () => Date.now(), signInIterations }) {
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
    const password = await readPassword(KEYCHAIN_SERVICE);
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
    signInFlight ??= signIn().finally(() => {
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

  async function postJson(path, body, headers) {
    const res = await request("POST", path, { body, headers });
    if (!res.ok) {
      let detail = "";
      try {
        const j = await res.json();
        if (typeof j?.error === "string") detail = `: ${j.error}`;
      } catch {
        // no body worth showing
      }
      throw new MeError(`Salt refused the message (${res.status})${detail}`, { status: res.status });
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

  async function unlock() {
    const { password } = await signIn();
    const userKeys = await getJson("/api/v1/userkeys");
    const userKey = Array.isArray(userKeys) ? userKeys[0] : userKeys;
    let armored;
    if (userKey?.encrypted_private_key) {
      const vault = await getJson("/api/v1/vault");
      lockMode = vault?.lock_mode ?? null;
      let vaultPassword = password;
      if (lockMode !== "login") {
        // A separate vault password lives in its own Keychain item. If none was saved, the login password is tried
        // once, because plenty of "separate" vaults were set to the same words.
        vaultPassword = await readPassword(KEYCHAIN_VAULT_SERVICE).catch(() => password);
      }
      const dek = await unwrapMessagesDek({ vault, vaultPassword });
      armored = await readArmoredPrivateKey({ userKey, dek });
    } else {
      lockMode = "legacy";
      armored = await readArmoredPrivateKey({ userKey });
    }
    privateKey = await openPrivateKey(armored);
    decryptText = createMessageDecryptor(privateKey);
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
        const error = err instanceof MeError ? err : new MeError(UNLOCK_FAILED, { kind: "unlock" });
        failure = { error, at: now() };
        throw error;
      })
      .finally(() => {
        unlocking = null;
      });
    return unlocking;
  }

  return {
    email,
    ensureUnlocked,
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
    get status() {
      return {
        unlocked: Boolean(decryptText),
        lock_mode: lockMode,
        signed_in_at: signedInAt ? new Date(signedInAt).toISOString() : null,
        token_age_days: signedInAt ? Math.floor((now() - signedInAt) / 86400000) : null,
      };
    },
  };
}
