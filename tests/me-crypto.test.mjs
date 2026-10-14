// The crypto of `salt-mcp --as-me` (src/me-crypto.mjs) against vectors from the website's own code and against a vault
// built with the same WebCrypto steps as salt-fe walletVault.js / messageKey.js (tests/me-fixtures.mjs builds it
// independently of the module under test).

import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto, randomBytes } from "node:crypto";
import {
  authString,
  AUTH_ITERATIONS,
  unwrapMessagesDek,
  readArmoredPrivateKey,
  openPrivateKey,
  createMessageDecryptor,
  decryptAttachmentBytes,
  encryptForKeys,
  ENCRYPTED_PLACEHOLDER,
} from "../src/me-crypto.mjs";
import { loadOpenpgp } from "../src/local-decrypt.mjs";
import { makeWorld, buildVault, expectedAuthString, PASSWORD, VAULT_PASSWORD, TEST_ITERATIONS } from "./me-fixtures.mjs";

// Computed by running salt-fe src/utilities/passwordDerivation.js's authString verbatim under Node's WebCrypto, and
// cross-checked with Python hashlib.pbkdf2_hmac -- both agreed on every value below.
const VECTORS = [
  ["correct horse battery staple", AUTH_ITERATIONS, "fkU/WuO/u9+7BIE9veYC6D+Du0xR8sB4mJkV/Qtz7kU="],
  // Full-width letters and digits: NFKC folds them to "password123" before hashing.
  ["ｐａｓｓｗｏｒｄ１２３", AUTH_ITERATIONS, "f2LWWTkExfp+BNH6Eb5ddg//LgDyVe7xrX+oLS/tn4s="],
  ["Zażółć gęślą jaźń ✓", AUTH_ITERATIONS, "TrsDDthEwkGqXPjBROlq2FoUuFazxDvw5o7Kvn2veXQ="],
  ["hunter2", 1000, "Szrqd4hOoNH3qeTLUakEDThmBeQk0b/0roeAr+EtOjc="],
];

test("authString matches the website's derivation (known vectors)", async () => {
  for (const [password, iterations, expected] of VECTORS) {
    assert.equal(await authString(password, iterations), expected, `vector for ${JSON.stringify(password)}`);
  }
});

test("authString normalises to NFKC and uses 600000 rounds by default", async () => {
  assert.equal(AUTH_ITERATIONS, 600000);
  assert.equal(await authString("ｐａｓｓｗｏｒｄ１２３", 1000), await authString("password123", 1000));
  // Composed and decomposed forms of the same letters give one string.
  assert.equal(await authString("café", 1000), await authString("café", 1000));
  assert.equal(await authString(PASSWORD, TEST_ITERATIONS), expectedAuthString(PASSWORD));
});

test("unwrapMessagesDek opens the messages wrap with the login password and returns a non-extractable key", async () => {
  const dekBytes = randomBytes(32);
  const vault = await buildVault({ vaultPassword: PASSWORD, lockMode: "login", dek: dekBytes });
  const dek = await unwrapMessagesDek({ vault, vaultPassword: PASSWORD });
  assert.equal(dek.extractable, false);
  assert.deepEqual(dek.usages, ["decrypt"]);
  // It is the very key that was wrapped: it decrypts something the raw DEK encrypted.
  const iv = randomBytes(12);
  const raw = await webcrypto.subtle.importKey("raw", dekBytes, "AES-GCM", false, ["encrypt"]);
  const ct = await webcrypto.subtle.encrypt({ name: "AES-GCM", iv }, raw, Buffer.from("proof"));
  assert.equal(Buffer.from(await webcrypto.subtle.decrypt({ name: "AES-GCM", iv }, dek, ct)).toString(), "proof");
});

test("unwrapMessagesDek rejects a wrong password, a missing wrap, and a wrap with the wrong purpose AAD", async () => {
  const vault = await buildVault({ vaultPassword: PASSWORD, lockMode: "login", dek: randomBytes(32) });
  await assert.rejects(unwrapMessagesDek({ vault, vaultPassword: "not the password" }));
  await assert.rejects(unwrapMessagesDek({ vault: { ...vault, wrapped_deks: {} }, vaultPassword: PASSWORD }), /no messages wrap/);
  // The wallets wrap is never read: swapping it into the messages slot fails the AAD check.
  const swapped = { ...vault, wrapped_deks: { messages: { password: vault.wrapped_deks.wallets.password } } };
  await assert.rejects(unwrapMessagesDek({ vault: swapped, vaultPassword: PASSWORD }));
});

test("a separate lock password unwraps; the login password does not", async () => {
  const vault = await buildVault({ vaultPassword: VAULT_PASSWORD, lockMode: "separate", dek: randomBytes(32) });
  await unwrapMessagesDek({ vault, vaultPassword: VAULT_PASSWORD });
  await assert.rejects(unwrapMessagesDek({ vault, vaultPassword: PASSWORD }));
});

test("the vault password is NFKC-normalised like the website's", async () => {
  const vault = await buildVault({ vaultPassword: "ｐａｓｓｗｏｒｄ１２３", lockMode: "login", dek: randomBytes(32) });
  await unwrapMessagesDek({ vault, vaultPassword: "password123" });
});

for (const [wrapCase, label] of [["upper", "as served (uppercase)"], ["lower", "lowercased"], ["mixed", "neither case"]]) {
  test(`private key AAD fallback: wrapped under the fingerprint ${label}`, async () => {
    const world = await makeWorld({ wrapCase });
    const dek = await unwrapMessagesDek({ vault: world.vault, vaultPassword: PASSWORD });
    if (wrapCase === "mixed") {
      await assert.rejects(readArmoredPrivateKey({ userKey: world.userKey, dek }));
      return;
    }
    const armored = await readArmoredPrivateKey({ userKey: world.userKey, dek });
    assert.equal(armored, world.keys.me.privateKey);
  });
}

test("a legacy key armored under the passphrase salt is opened without a vault", async () => {
  const world = await makeWorld({ scheme: "legacy" });
  const armored = await readArmoredPrivateKey({ userKey: world.userKey });
  const key = await openPrivateKey(armored);
  assert.equal(key.isDecrypted(), true);
  const decrypt = createMessageDecryptor(key);
  const openpgp = await loadOpenpgp();
  const body = await encryptForKeys("legacy hello", [world.keys.me.publicKey]);
  assert.equal(await decrypt(body), "legacy hello");
  assert.ok(openpgp);
});

test("an unprotected vault key is used as is", async () => {
  const world = await makeWorld();
  const key = await openPrivateKey(world.keys.me.privateKey);
  assert.equal(key.isDecrypted(), true);
});

test("decrypt: PGP bodies open, plain bodies pass through, unreadable ones are [Encrypted]", async () => {
  const world = await makeWorld();
  const decrypt = createMessageDecryptor(await openPrivateKey(world.keys.me.privateKey));
  assert.equal(await decrypt(await encryptForKeys("hello owner", [world.keys.me.publicKey, world.keys.ada.publicKey])), "hello owner");
  assert.equal(await decrypt("just an open room line"), "just an open room line");
  assert.equal(await decrypt(null), "");
  // Sent before the owner joined: encrypted for someone else.
  assert.equal(await decrypt(await encryptForKeys("not for you", [world.keys.stranger.publicKey])), ENCRYPTED_PLACEHOLDER);
  assert.equal(await decrypt("-----BEGIN PGP MESSAGE-----\n\ngarbage\n-----END PGP MESSAGE-----"), ENCRYPTED_PLACEHOLDER);
});

test("attachment bytes: AES-256-GCM with the tag in the last 16 bytes, no AAD", async () => {
  const { createCipheriv } = await import("node:crypto");
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
  const plain = Buffer.from("the file body");
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
  const out = await decryptAttachmentBytes(ciphertext, key.toString("base64"), iv.toString("base64"));
  assert.equal(out.toString(), "the file body");
  ciphertext[0] ^= 1;
  await assert.rejects(decryptAttachmentBytes(ciphertext, key.toString("base64"), iv.toString("base64")));
});
