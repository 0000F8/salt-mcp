// Key-reset phase 1: the as-me session and the local server hold a keyring (active + retired) and read history from
// every generation, skipping rows they cannot open.

import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto, randomBytes } from "node:crypto";
import { openPrivateKey, openRetiredPrivateKeys, createMessageDecryptor, encryptForKeys, ENCRYPTED_PLACEHOLDER } from "../src/me-crypto.mjs";
import { loadOpenpgp, createDecryptor } from "../src/local-decrypt.mjs";

const subtle = webcrypto.subtle;
const te = new TextEncoder();

async function genKey() {
  const openpgp = await loadOpenpgp();
  const { privateKey, publicKey } = await openpgp.generateKey({ type: "ecc", curve: "curve25519", userIDs: [{ name: "t" }], format: "armored" });
  const fingerprint = (await openpgp.readKey({ armoredKey: publicKey })).getFingerprint().toUpperCase();
  return { privateKey, publicKey, fingerprint };
}

async function dekPair() {
  const raw = randomBytes(32);
  return {
    raw,
    key: await subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]),
    wrapKey: await subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]),
  };
}

async function row(k, wrapKey, generation) {
  const iv = randomBytes(12);
  const ct = Buffer.from(await subtle.encrypt({ name: "AES-GCM", iv, additionalData: te.encode(`userkey:${k.fingerprint}`) }, wrapKey, te.encode(JSON.stringify({ private_key: k.privateKey }))));
  return { generation, public_fingerprint: k.fingerprint, encrypted_private_key: Buffer.concat([iv, ct]).toString("base64"), retired_at: "2026-10-01T00:00:00Z" };
}

test("as-me keyring: old, new and both keys open; a retired row under another DEK is skipped", async () => {
  const oldK = await genKey();
  const newK = await genKey();
  const lostK = await genKey();
  const dek = await dekPair();
  const other = await dekPair(); // the DEK minted by "start fresh": cannot open older wraps
  const retired = [await row(oldK, dek.wrapKey, 1), await row(lostK, other.wrapKey, 0), { generation: 9, public_fingerprint: "X", encrypted_private_key: "!!!" }];

  const ring = await openRetiredPrivateKeys({ retired, dek: dek.key });
  assert.equal(ring.length, 1);
  assert.deepEqual(await openRetiredPrivateKeys({ retired: undefined, dek: dek.key }), []); // missing = empty

  const active = await openPrivateKey(newK.privateKey);
  const toOld = await encryptForKeys("old text", [oldK.publicKey]);
  const toNew = await encryptForKeys("new text", [newK.publicKey]);
  const toLost = await encryptForKeys("lost text", [lostK.publicKey]);

  const single = createMessageDecryptor(active);
  assert.equal(await single(toNew), "new text");
  assert.equal(await single(toOld), ENCRYPTED_PLACEHOLDER); // old key alone cannot read old history

  const both = createMessageDecryptor([active, ...ring]);
  assert.equal(await both(toNew), "new text");
  assert.equal(await both(toOld), "old text");
  assert.equal(await both(toLost), ENCRYPTED_PLACEHOLDER); // unopenable generation: marked unreadable, no throw

  const oldOnly = createMessageDecryptor(ring);
  assert.equal(await oldOnly(toOld), "old text");
  assert.equal(await oldOnly(toNew), ENCRYPTED_PLACEHOLDER);
});

test("local decryptor: single key unchanged; keyring opens old and new; bad entries skipped", async () => {
  const oldK = await genKey();
  const newK = await genKey();
  const toOld = await encryptForKeys("old text", [oldK.publicKey]);
  const toNew = await encryptForKeys("new text", [newK.publicKey]);

  assert.equal(await createDecryptor({ privateKey: newK.privateKey })(toNew), "new text");
  await assert.rejects(createDecryptor({ privateKey: newK.privateKey })(toOld));

  const ring = createDecryptor({ privateKey: [newK.privateKey, "garbage", oldK.privateKey] });
  assert.equal(await ring(toNew), "new text");
  assert.equal(await ring(toOld), "old text");

  await assert.rejects(createDecryptor({ privateKey: ["garbage"] })(toNew));
});
