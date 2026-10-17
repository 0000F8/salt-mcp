// The opt-in send guard (KEY_RESET_DESIGN.md 7). A message carries the public
// fingerprint of every key it was encrypted to; if any is out of date Salt
// answers 409 {code: "stale_recipient_keys", members: [...]} and the sender
// re-encrypts ONCE to the keys it sent back. Members are always read at send
// time by the caller; nothing here caches.

const same = (a, b) => String(a) === String(b);

/**
 * Guard fields for a member list, or {} when any keyed member has no fingerprint
 * (a missing fingerprint must never read as a stale one). With `selfId` the
 * sender's own row becomes `senderFingerprint` and is left out of the recipient
 * map; without it (the keyless server has no identity) every member is listed
 * and `senderFingerprint` is omitted: Salt ignores the sender's own entry.
 */
export function buildGuard(users, selfId) {
  const keyed = (users || []).filter((u) => u?.public_key);
  if (keyed.length === 0 || !keyed.every((u) => u.public_fingerprint)) return {};
  const guard = {
    recipientFingerprints: Object.fromEntries(keyed.filter((u) => selfId == null || !same(u.id, selfId)).map((u) => [String(u.id), u.public_fingerprint])),
  };
  const me = selfId == null ? null : keyed.find((u) => same(u.id, selfId));
  if (me) guard.senderFingerprint = me.public_fingerprint;
  return guard;
}

/** The request-body spelling of a guard. */
export function guardBody(guard) {
  const body = {};
  if (guard?.recipientFingerprints && Object.keys(guard.recipientFingerprints).length > 0) body.recipient_fingerprints = guard.recipientFingerprints;
  if (guard?.senderFingerprint) body.sender_fingerprint = guard.senderFingerprint;
  return body;
}

/** The current members out of a stale_recipient_keys refusal (any of this repo's error shapes), or null for any other error. */
export function staleMembers(err) {
  if (!err || err.status !== 409) return null;
  if ((err.body?.code ?? err.code) !== "stale_recipient_keys") return null;
  const members = err.body?.members ?? err.members;
  return Array.isArray(members) ? members : [];
}

/** `users` with the keys and fingerprints Salt just returned. */
export function applyFresh(users, members) {
  return users.map((u) => {
    const m = members.find((x) => same(x.id, u.id));
    return m ? { ...u, public_key: m.public_key ?? u.public_key, public_fingerprint: m.public_fingerprint ?? u.public_fingerprint } : u;
  });
}

/** attempt(users) encrypts and posts. On a stale refusal it runs once more with the fresh keys; a second refusal propagates. */
export async function sendWithFreshKeys(users, attempt) {
  try {
    return await attempt(users);
  } catch (err) {
    const members = staleMembers(err);
    if (!members) throw err;
    return attempt(applyFresh(users, members));
  }
}
