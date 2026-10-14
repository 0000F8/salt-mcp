// A fake Salt for the --as-me tests: a mock HTTP layer (a fetch implementation, never the network) that serves what
// salt-api serves -- sign_in, vault, userkeys, chats, messages, attachments -- with REAL cryptography built the way the
// Salt website builds it, independently of src/me-crypto.mjs (so a round trip here is a real check, not a mirror):
// PBKDF2 -> AES-GCM wraps with the web's AAD strings, openpgp messages for the chat members' keys.

import { webcrypto, pbkdf2Sync, randomBytes, createCipheriv } from "node:crypto";
import { loadOpenpgp } from "../src/local-decrypt.mjs";
import { createMeSession } from "../src/me-session.mjs";

const subtle = webcrypto.subtle;
const te = new TextEncoder();

export const HOST = "https://salt.test";
export const PASSWORD = "Tr0ub4dor&3-correct-horse";
export const VAULT_PASSWORD = "a-separate-lock-password";
export const EMAIL = "SALT-owner@example.test";
export const TEST_ITERATIONS = 1000;

export const ME_ID = "aaaaaaaa-0000-4000-8000-000000000001";
export const ADA_ID = "aaaaaaaa-0000-4000-8000-000000000002";
export const BOT_ID = "aaaaaaaa-0000-4000-8000-000000000003";
export const CHAT_ADA = "c0000000-0000-4000-8000-000000000001";
export const CHAT_GROUP = "c0000000-0000-4000-8000-000000000002";
export const CHAT_OPEN = "c0000000-0000-4000-8000-000000000003";
export const CHAT_LEGACY = "c0000000-0000-4000-8000-000000000004";
export const CHAT_REQUEST = "c0000000-0000-4000-8000-000000000005";

const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const NFKC = (s) => s.normalize("NFKC");

/** The web's authString, computed independently with node:crypto's synchronous PBKDF2. */
export const expectedAuthString = (password, iterations = TEST_ITERATIONS) =>
  b64(pbkdf2Sync(Buffer.from(NFKC(password), "utf8"), Buffer.from("saltfor.com/auth/v1"), iterations, 32, "sha256"));

async function gcmWrap(keyBytes, plaintext, aad) {
  const key = await subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const iv = randomBytes(12);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv, additionalData: te.encode(aad), tagLength: 128 }, key, plaintext));
  return b64(Buffer.concat([iv, ct]));
}

/** The vault exactly as walletVault.js builds it: KEK from the password, the messages DEK wrapped under it. */
export async function buildVault({ vaultPassword, lockMode, dek, iterations = TEST_ITERATIONS }) {
  const salt = randomBytes(16);
  const kekBytes = pbkdf2Sync(Buffer.from(NFKC(vaultPassword), "utf8"), salt, iterations, 32, "sha256");
  return {
    salt_password: b64(salt),
    kdf_iterations: iterations,
    lock_mode: lockMode,
    wrapped_deks: {
      messages: { password: await gcmWrap(kekBytes, dek, "wrap:messages:password") },
      wallets: { password: await gcmWrap(kekBytes, randomBytes(32), "wrap:wallets:password") },
    },
  };
}

let keyCache;
async function pgpKeys() {
  if (keyCache) return keyCache;
  const openpgp = await loadOpenpgp();
  const make = async (name) => {
    const { privateKey, publicKey } = await openpgp.generateKey({ type: "ecc", curve: "curve25519", userIDs: [{ name }], format: "armored" });
    const fingerprint = (await openpgp.readKey({ armoredKey: publicKey })).getFingerprint();
    return { privateKey, publicKey, fingerprint };
  };
  keyCache = { me: await make("me"), ada: await make("ada"), bot: await make("bot"), stranger: await make("stranger") };
  return keyCache;
}

async function pgpEncrypt(text, publicKeys) {
  const openpgp = await loadOpenpgp();
  return openpgp.encrypt({
    message: await openpgp.createMessage({ text }),
    encryptionKeys: await Promise.all(publicKeys.map((armoredKey) => openpgp.readKey({ armoredKey }))),
  });
}

const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });

/**
 * @param {{
 *   lockMode?: "login"|"separate"|null, scheme?: "vault"|"legacy", wrapCase?: "upper"|"lower"|"mixed",
 *   password?: string, vaultPassword?: string, signInStatus?: number, messageCount?: number,
 * }} options
 */
export async function makeWorld({ lockMode = "login", scheme = "vault", wrapCase = "upper", password = PASSWORD, vaultPassword = VAULT_PASSWORD, signInStatus, messageCount = 25, authIterations = TEST_ITERATIONS } = {}) {
  const openpgp = await loadOpenpgp();
  const keys = await pgpKeys();
  const dek = randomBytes(32);
  const vaultSecret = lockMode === "login" ? password : vaultPassword;
  const vault = await buildVault({ vaultPassword: vaultSecret, lockMode, dek });
  const servedFingerprint = keys.me.fingerprint.toUpperCase();

  let userKey;
  if (scheme === "vault") {
    const aadFingerprint = wrapCase === "lower" ? keys.me.fingerprint.toLowerCase() : wrapCase === "mixed" ? `${servedFingerprint.slice(0, 8)}${servedFingerprint.slice(8).toLowerCase()}` : servedFingerprint;
    userKey = {
      public_fingerprint: servedFingerprint,
      encryption_scheme: "vault",
      encrypted_private_key: await gcmWrap(dek, te.encode(JSON.stringify({ private_key: keys.me.privateKey })), `userkey:${aadFingerprint}`),
    };
  } else {
    // A legacy key: armored under the passphrase "salt", served as-is.
    const locked = await openpgp.encryptKey({ privateKey: await openpgp.readPrivateKey({ armoredKey: keys.me.privateKey }), passphrase: "salt" });
    userKey = { public_fingerprint: servedFingerprint, encryption_scheme: "server", private_key: locked.armor() };
  }

  const person = (id, username, display_name, account_type, key) => ({ id, username, display_name, account_type, public_key: key.publicKey });
  const me = person(ME_ID, "owner", "Owner", "User", keys.me);
  const ada = person(ADA_ID, "ada", "Ada Lovelace", "User", keys.ada);
  const bot = person(BOT_ID, "helperbot", "Helper Bot", "Agent", keys.bot);

  const serverMessages = new Map(); // chat id -> ascending array
  const messageById = new Map();
  let nextId = 1000;
  let seq = 0;

  const forMe = [keys.me.publicKey, keys.ada.publicKey];
  async function add(chatId, { from, text, encryptFor = forMe, plain = false, extra = {}, minutesAgo = 0, senderCopyFor }) {
    const id = String(nextId++);
    const msg = {
      id,
      message_id: id,
      seq: ++seq,
      chat_id: chatId,
      created_by: from.id,
      created_at: new Date(Date.UTC(2026, 9, 14, 12, 0, 0) - minutesAgo * 60000).toISOString(),
      encrypted: !plain,
      event_type: null,
      reply_to_message_id: null,
      mentions: [],
      message: plain ? text : text === null ? null : await pgpEncrypt(text, encryptFor),
      sender_message: senderCopyFor ? await pgpEncrypt(text, senderCopyFor) : null,
      user: { id: from.id, username: from.username, display_name: from.display_name, account_type: from.account_type },
      ...extra,
    };
    if (!serverMessages.has(chatId)) serverMessages.set(chatId, []);
    serverMessages.get(chatId).push(msg);
    messageById.set(id, msg);
    return msg;
  }

  // 1:1 with Ada: one message from before the owner joined (encrypted for a stranger), then a conversation.
  await add(CHAT_ADA, { from: ada, text: "from before you joined", encryptFor: [keys.ada.publicKey, keys.stranger.publicKey], minutesAgo: 500 });
  for (let i = 1; i <= messageCount; i++) {
    await add(CHAT_ADA, { from: i % 2 ? ada : me, text: `message number ${i}`, minutesAgo: messageCount - i + 1 });
  }

  // The group: markers, a mention, a reply, an attachment, an event.
  const first = await add(CHAT_GROUP, { from: ada, text: "[[SALT-DELEGATION depth=1]]\nplease review the plan", minutesAgo: 30 });
  await add(CHAT_GROUP, { from: bot, text: "[[SALT-THINKING]]internal reasoning[[/SALT-THINKING]]\nreviewing now, @owner", encryptFor: [keys.me.publicKey, keys.ada.publicKey, keys.bot.publicKey], extra: { reply_to_message_id: first.id, mentions: [ME_ID] }, minutesAgo: 20 });
  const fileKey = randomBytes(32);
  const fileIv = randomBytes(12);
  const files = {
    note: { name: "notes.txt", type: "text/plain", bytes: Buffer.from("first line\nsecond line\n") },
    pic: { name: "dot.png", type: "image/png", bytes: Buffer.from("89504e470d0a1a0a", "hex") },
    blob: { name: "data.bin", type: "application/octet-stream", bytes: Buffer.from([0, 1, 2, 3, 0, 255]) },
    huge: { name: "big.zip", type: "application/zip", bytes: Buffer.alloc(8), declared: 16 * 1024 * 1024 },
  };
  const ciphertextOf = (bytes) => {
    const cipher = createCipheriv("aes-256-gcm", fileKey, fileIv, { authTagLength: 16 });
    return Buffer.concat([cipher.update(bytes), cipher.final(), cipher.getAuthTag()]);
  };
  const attachmentMessages = {};
  for (const [name, f] of Object.entries(files)) {
    const meta = JSON.stringify({ key: b64(fileKey), iv: b64(fileIv), filename: f.name, content_type: f.type, size: f.declared ?? f.bytes.length });
    attachmentMessages[name] = await add(CHAT_GROUP, {
      from: ada,
      text: null,
      extra: { resource_type: "Attachment", resource: { id: `att-${name}`, byte_size: f.declared ?? f.bytes.length + 16, encrypted_key: await pgpEncrypt(meta, forMe), encrypted_key_sender: null } },
      minutesAgo: 10,
    });
  }
  await add(CHAT_GROUP, { from: ada, text: "Ada called. No answer.", plain: true, extra: { event_type: "call_unanswered" }, minutesAgo: 5 });

  // The open room is plain text; the legacy chat has a two-copy message of the owner's own.
  await add(CHAT_OPEN, { from: ada, text: "hello open room", plain: true, minutesAgo: 3 });
  await add(CHAT_LEGACY, { from: me, text: "my own legacy message", encryptFor: [keys.ada.publicKey], senderCopyFor: [keys.me.publicKey], minutesAgo: 2 });

  const chats = {
    [CHAT_ADA]: { id: CHAT_ADA, name: "Unnamed Chat", group_chat: false, encrypted: true, users: [me, ada], unread_count: 2 },
    [CHAT_GROUP]: { id: CHAT_GROUP, name: "Launch crew", group_chat: true, encrypted: true, users: [me, ada, bot], unread_count: 0 },
    [CHAT_OPEN]: { id: CHAT_OPEN, name: "Open lounge", group_chat: true, public: true, encrypted: false, users: [me, ada], unread_count: 5 },
    [CHAT_LEGACY]: { id: CHAT_LEGACY, name: "Unnamed Chat", group_chat: false, encrypted: true, users: [me, ada], unread_count: 0 },
  };
  const requestChats = { [CHAT_REQUEST]: { id: CHAT_REQUEST, name: "Unnamed Chat", group_chat: false, encrypted: true, users: [me, bot], unread_count: 1, request_state: "pending" } };
  await add(CHAT_REQUEST, { from: bot, text: "hello, may I introduce myself?", encryptFor: [keys.me.publicKey, keys.bot.publicKey], minutesAgo: 1 });

  const requests = [];
  const posted = [];
  const state = { signIns: 0, signOuts: 0, expireNextRequest: false };

  const sessionFor = (chat) => ({ ...chat, joined_at: "2026-01-01T00:00:00Z", request_state: chat.request_state ?? null });
  const sorted = (chatId) => serverMessages.get(chatId) ?? [];

  async function fetchImpl(url, init = {}) {
    const method = init.method || "GET";
    const u = new URL(url);
    const path = u.pathname;
    requests.push({ method, path, search: u.search, headers: { ...(init.headers || {}) }, body: init.body });

    if (method === "POST" && path === "/auth/sign_in") {
      state.signIns++;
      const body = JSON.parse(init.body);
      if (signInStatus) return json({ status: signInStatus }, signInStatus);
      if (body.user.email !== EMAIL || body.user.password !== expectedAuthString(password, authIterations)) return json({ status: 401, message: "Credentials invalid" }, 401);
      return json({ id: ME_ID, username: "owner", display_name: "Owner", email: EMAIL }, 200, { Authorization: "Bearer test.jwt.token" });
    }

    if (method === "DELETE" && path === "/auth/sign_out") {
      if (init.headers?.Authorization !== "Bearer test.jwt.token") return json({ error: "unauthorized" }, 401);
      state.signOuts++;
      return new Response(null, { status: 204 });
    }

    if (init.headers?.Authorization !== "Bearer test.jwt.token" || state.expireNextRequest) {
      state.expireNextRequest = false;
      return json({ error: "unauthorized" }, 401);
    }

    if (method === "GET" && path === "/api/v1/vault") return json(vault);
    if (method === "GET" && path === "/api/v1/userkeys") return json(userKey);

    if (method === "GET" && path === "/api/v1/chats") {
      const pool = u.searchParams.get("requests") ? requestChats : chats;
      const rows = Object.values(pool).map((chat) => {
        const list = sorted(chat.id);
        const last = list[list.length - 1];
        return { session: sessionFor(chat), recent_message: last ? { message: last, user: last.user } : {} };
      });
      return json(rows);
    }

    let m = /^\/api\/v1\/chats\/([^/]+)(\/previous)?$/.exec(path);
    if (method === "GET" && m) {
      const chat = chats[m[1]] ?? requestChats[m[1]];
      if (!chat) return json({ error: "Not found." }, 404);
      const list = sorted(chat.id);
      let page;
      if (m[2]) {
        const idx = list.findIndex((x) => x.id === u.searchParams.get("last"));
        page = list.slice(Math.max(0, idx - 10), Math.max(0, idx));
      } else {
        page = list.slice(-10);
      }
      return json({ session: sessionFor(chat), messages: page });
    }

    m = /^\/api\/v1\/messages\/([^/]+)(\/attachment)?$/.exec(path);
    if (method === "GET" && m) {
      const msg = messageById.get(m[1]);
      if (!msg) return json({ error: "Not found" }, 404);
      if (m[2]) {
        const f = Object.values(attachmentMessages).findIndex((x) => x.id === msg.id);
        const file = Object.values(files)[f];
        return new Response(ciphertextOf(file.bytes), { status: 200, headers: { "Content-Type": "application/octet-stream" } });
      }
      return json(msg);
    }

    if (method === "POST" && path === "/api/v1/messages") {
      const body = JSON.parse(init.body);
      posted.push({ body, headers: init.headers });
      return json({ id: "9001", message_id: "9001", chat_id: body.chat_id });
    }

    return json({ error: `unrouted ${method} ${path}` }, 404);
  }

  const secretCalls = [];
  const session = createMeSession({
    host: HOST,
    email: EMAIL,
    fetchImpl,
    signInIterations: authIterations,
    readPassword: async (kind) => {
      secretCalls.push(kind);
      if (kind === "vault") {
        if (lockMode === "login") throw new Error("no second password");
        return vaultPassword;
      }
      return password;
    },
  });

  return { fetchImpl, requests, posted, state, session, keys, vault, userKey, dek, ids: { me, ada, bot }, files, attachmentMessages, secretCalls, serverMessages, password };
}

/** Everything the world would have to keep secret from a model: scanned for in tool output and logs. */
export const secretsOf = (world) => [world.password, VAULT_PASSWORD, world.dek.toString("base64"), expectedAuthString(world.password), "Bearer test.jwt.token", "test.jwt.token"];
