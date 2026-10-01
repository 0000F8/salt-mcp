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
function loadOpenpgp() {
  if (!openpgpPromise) {
    const sdkEntry = import.meta.resolve("salt-agent-sdk");
    openpgpPromise = Promise.resolve(createRequire(sdkEntry)("openpgp"));
  }
  return openpgpPromise;
}

/**
 * @returns {(armoredMessage: string) => Promise<string>} Throws per message if it can't be opened; the key is unlocked once and reused.
 */
export function createDecryptor({ privateKey, passphrase }) {
  let keyPromise;
  const unlockedKey = async (openpgp) => {
    if (!keyPromise) {
      keyPromise = (async () => {
        const key = await openpgp.readPrivateKey({ armoredKey: privateKey });
        return key.isDecrypted() ? key : openpgp.decryptKey({ privateKey: key, passphrase: passphrase ?? "" });
      })();
      // A failed unlock must be retried, not cached forever.
      keyPromise.catch(() => { keyPromise = undefined; });
    }
    return keyPromise;
  };
  return async function decryptMessage(armoredMessage) {
    const openpgp = await loadOpenpgp();
    const key = await unlockedKey(openpgp);
    const { data } = await openpgp.decrypt({
      message: await openpgp.readMessage({ armoredMessage }),
      decryptionKeys: [key],
    });
    return String(data);
  };
}
