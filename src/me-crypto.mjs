// The crypto behind `salt-mcp --as-me`: the owner's password turned into the
// same keys the Salt website uses, on this computer only. Every function here
// is a Node port of a salt-fe module and says which:
//
//   authString          salt-fe src/utilities/passwordDerivation.js (AUTH_SALT, AUTH_ITERATIONS)
//   deriveKek/unwrap    salt-fe src/utilities/walletVault.js (deriveKek, gcmDecrypt, wrapAad)
//   unlockPrivateKey    salt-fe src/utilities/messageKey.js (aadCandidates, unlockMessageKey)
//   decrypt/encrypt     salt-fe src/utilities/encrypt.jsx
//   decryptAttachment   salt-fe src/utilities/attachments.js (decryptFileBytes)
//
// Nothing is logged, written to disk or returned beyond what a caller needs.
// The password, the wrapping key and the DEK live only in these function
// scopes; the DEK is imported non-extractable and its raw bytes are zeroed.
// The wallets DEK is never unwrapped: this module only knows "messages".

import { webcrypto } from "node:crypto";
import { loadOpenpgp } from "./local-decrypt.mjs";

const subtle = webcrypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder();

// A label, not a hostname: every account's login string was derived under it
// (salt-fe passwordDerivation.js), so it never changes.
export const AUTH_SALT = "saltfor.com/auth/v1";
export const AUTH_ITERATIONS = 600000;
const AUTH_KEY_BYTES = 32;
const GCM_TAG_LENGTH = 128;
const IV_BYTES = 12;

export const MAX_ATTACHMENT_BYTES = 15 * 1024 * 1024;

const normalize = (pw) => (pw || "").normalize("NFKC");
const fromBase64 = (b64) => new Uint8Array(Buffer.from(b64, "base64"));
const toBase64 = (bytes) => Buffer.from(bytes).toString("base64");

/**
 * What Devise receives as "the password": base64 of PBKDF2-HMAC-SHA256 over
 * the NFKC-normalised password, salt "saltfor.com/auth/v1", 600000 rounds,
 * 256 bits. `iterations` exists for tests only.
 */
export async function authString(password, iterations = AUTH_ITERATIONS) {
  const material = await subtle.importKey("raw", te.encode(normalize(password)), "PBKDF2", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: te.encode(AUTH_SALT), iterations },
    material,
    AUTH_KEY_BYTES * 8
  );
  return toBase64(new Uint8Array(bits));
}

/** The vault's password-wrapping key: PBKDF2-SHA256 over the NFKC password with the vault's own salt, as a non-extractable AES-GCM key. */
export async function deriveKek(vaultPassword, saltB64, iterations) {
  const material = await subtle.importKey("raw", te.encode(normalize(vaultPassword)), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: fromBase64(saltB64), iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

const gcmDecrypt = (key, b64, aad) => {
  const data = fromBase64(b64);
  return subtle.decrypt(
    { name: "AES-GCM", iv: data.slice(0, IV_BYTES), additionalData: te.encode(aad), tagLength: GCM_TAG_LENGTH },
    key,
    data.slice(IV_BYTES)
  );
};

/** The messages DEK, from the vault's password wrap. Returned as a non-extractable key; the raw bytes are zeroed before this returns. */
export async function unwrapMessagesDek({ vault, vaultPassword }) {
  const wrapped = vault?.wrapped_deks?.messages?.password;
  if (!wrapped) throw new Error("This account has no messages wrap in its vault.");
  const kek = await deriveKek(vaultPassword, vault.salt_password, vault.kdf_iterations);
  const raw = new Uint8Array(await gcmDecrypt(kek, wrapped, "wrap:messages:password"));
  try {
    return await subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  } finally {
    raw.fill(0);
  }
}

// GCM's AAD check is byte-exact and the fingerprint's case has varied between
// openpgp.js (lowercase) and the server (uppercase): as served first, then both.
const aadCandidates = (fingerprint) => {
  const fpr = fingerprint || "";
  return [...new Set([fpr, fpr.toLowerCase(), fpr.toUpperCase()])].map((f) => `userkey:${f}`);
};

/**
 * The armored private key. `scheme: "vault"` keys are AES-GCM under the messages DEK; legacy keys are armored under
 * the passphrase "salt" and arrive as `private_key`.
 */
export async function readArmoredPrivateKey({ userKey, dek }) {
  if (userKey?.encrypted_private_key) {
    if (!dek) throw new Error("Vault is locked");
    let lastError = null;
    for (const aad of aadCandidates(userKey.public_fingerprint)) {
      try {
        const plain = await gcmDecrypt(dek, userKey.encrypted_private_key, aad);
        return JSON.parse(td.decode(plain)).private_key;
      } catch (e) {
        lastError = e;
      }
    }
    throw lastError || new Error("Could not decrypt the message key");
  }
  if (userKey?.private_key) return userKey.private_key;
  throw new Error("This account has no message key");
}

/** openpgp key from an armored private key; a key that is still passphrase-protected is opened with the legacy "salt". */
export async function openPrivateKey(armoredKey) {
  const openpgp = await loadOpenpgp();
  const key = await openpgp.readPrivateKey({ armoredKey });
  return key.isDecrypted() ? key : openpgp.decryptKey({ privateKey: key, passphrase: "salt" });
}

/**
 * The retired generations of the owner's chat key (`retired` from GET /userkeys; absent means none), opened with the
 * same DEK. A row that cannot be opened (a DEK minted after "start fresh", a damaged row) is skipped: that history
 * simply stays "[Encrypted]". Never throws.
 */
export async function openRetiredPrivateKeys({ retired, dek }) {
  const keys = [];
  for (const row of Array.isArray(retired) ? retired : []) {
    try {
      keys.push(await openPrivateKey(await readArmoredPrivateKey({ userKey: row, dek })));
    } catch {
      // skipped on purpose
    }
  }
  return keys;
}

export const ENCRYPTED_PLACEHOLDER = "[Encrypted]";
const PGP_MESSAGE_RE = /^-----BEGIN PGP MESSAGE-----/;
export const isCiphertext = (text) => PGP_MESSAGE_RE.test(text || "");

/**
 * A decryptor over the unlocked key, or a keyring: `privateKey` is one openpgp key or an array (active first, then
 * retired). openpgp matches the message's recipient key ids itself. A body that is not PGP armor passes through untouched (an open room); a body
 * that cannot be opened is "[Encrypted]" -- normal for anything sent before the owner joined the chat.
 */
export function createMessageDecryptor(privateKey) {
  return async function decryptText(body) {
    if (!isCiphertext(body)) return body ?? "";
    try {
      const openpgp = await loadOpenpgp();
      const { data } = await openpgp.decrypt({
        message: await openpgp.readMessage({ armoredMessage: body }),
        decryptionKeys: privateKey, // one key or the whole keyring
      });
      return String(data);
    } catch {
      return ENCRYPTED_PLACEHOLDER;
    }
  };
}

/** Encrypts one plain message for every public key (the sender's own included). */
export async function encryptForKeys(text, armoredPublicKeys) {
  const openpgp = await loadOpenpgp();
  const encryptionKeys = await Promise.all(armoredPublicKeys.map((armoredKey) => openpgp.readKey({ armoredKey })));
  return openpgp.encrypt({ message: await openpgp.createMessage({ text }), encryptionKeys });
}

/** AES-256-GCM file bytes (the 16-byte tag is the last 16 bytes), no AAD -- the web's decryptFileBytes. */
export async function decryptAttachmentBytes(ciphertext, keyB64, ivB64) {
  const key = await subtle.importKey("raw", fromBase64(keyB64), { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const plain = await subtle.decrypt({ name: "AES-GCM", iv: fromBase64(ivB64) }, key, ciphertext);
  return Buffer.from(plain);
}
