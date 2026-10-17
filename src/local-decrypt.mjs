// Decrypts a message with this agent's own PGP key, for the LOCAL server only
// (the hosted server never holds a key and never calls this). Handles both a
// passphrase-protected key and an unprotected one -- Salt-generated agent keys
// have no passphrase, which salt-agent-sdk's `decrypt` (it always calls
// decryptKey) rejects as "already decrypted", so this does its own two steps.
//
// openpgp is salt-agent-sdk's dependency, not ours: resolved from the SDK's
// own location so it is the very copy the SDK encrypts with, hoisted or not.

import { createRequire } from "node:module";

let openpgpPromise;
export function loadOpenpgp() {
  if (!openpgpPromise) {
    const sdkEntry = import.meta.resolve("salt-agent-sdk");
    openpgpPromise = Promise.resolve(createRequire(sdkEntry)("openpgp"));
  }
  return openpgpPromise;
}

/**
 * `privateKey` is one armored key or an array of them (active first, then retired generations). A key that cannot be
 * read or unlocked is skipped; with none usable the message throws like any unopenable message.
 * @returns {(armoredMessage: string) => Promise<string>} Throws per message if it can't be opened; keys are unlocked once and reused.
 */
export function createDecryptor({ privateKey, passphrase }) {
  let keysPromise;
  const unlockedKeys = async (openpgp) => {
    if (!keysPromise) {
      keysPromise = (async () => {
        const armoredKeys = Array.isArray(privateKey) ? privateKey : [privateKey];
        const settled = await Promise.allSettled(
          armoredKeys.map(async (armoredKey) => {
            const key = await openpgp.readPrivateKey({ armoredKey });
            return key.isDecrypted() ? key : openpgp.decryptKey({ privateKey: key, passphrase: passphrase ?? "" });
          })
        );
        const keys = settled.filter((r) => r.status === "fulfilled").map((r) => r.value);
        // Single-key behaviour kept: when nothing opens, surface the first error and retry next time.
        if (!keys.length) throw settled[0]?.reason ?? new Error("No usable decryption key");
        return keys;
      })();
      // A failed unlock must be retried, not cached forever.
      keysPromise.catch(() => { keysPromise = undefined; });
    }
    return keysPromise;
  };
  return async function decryptMessage(armoredMessage) {
    const openpgp = await loadOpenpgp();
    const keys = await unlockedKeys(openpgp);
    const { data } = await openpgp.decrypt({
      message: await openpgp.readMessage({ armoredMessage }),
      decryptionKeys: keys,
    });
    return String(data);
  };
}
