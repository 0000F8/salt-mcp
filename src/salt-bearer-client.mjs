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

/** Mirrors salt-agent-sdk's SaltApiError shape (status + body + one-sentence message). */
export class SaltBearerApiError extends Error {
  constructor(method, path, status, body) {
    const reason = body && typeof body === "object" && typeof body.error === "string" ? `: ${body.error}` : "";
    super(`Salt API ${method} ${path} -> ${status}${reason}`);
    this.name = "SaltBearerApiError";
    this.status = status;
    this.body = body;
  }
}

/**
 * @param {{host: string, fetchImpl?: typeof fetch}} options
 */
export function createSaltBearerClient({ host, fetchImpl }) {
  const base = host.replace(/\/$/, "");
  const doFetch = fetchImpl ?? fetch;

  async function request(method, path, bearerToken, body) {
    const url = `${base}${path}`;
    const headers = { Authorization: `Bearer ${bearerToken}` };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const res = await doFetch(url, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
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
    if (!res.ok) throw new SaltBearerApiError(method, path, res.status, parsed);
    return parsed;
  }

  return {
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
      return request("GET", `/api/v1/chats/${chatId}`, bearerToken);
    },

    /** Post a ciphertext message. No senderMessage -- a keyless agent has no private key to read one back with. */
    async postMessage(bearerToken, chatId, message) {
      return request("POST", "/api/v1/messages", bearerToken, { chat_id: chatId, message });
    },

    async postCard(bearerToken, chatId, blocks, text) {
      return request("POST", "/api/v1/cards", bearerToken, { chat_id: chatId, blocks, text });
    },

    async updateCard(bearerToken, cardId, blocks) {
      return request("PATCH", `/api/v1/cards/${cardId}`, bearerToken, { blocks });
    },

    /**
     * Short-poll the socket-mode outbox (K2 contract). `timeoutSeconds` is
     * clamped server-side to 0..2 regardless of what's asked here.
     */
    async agentUpdates(bearerToken, { after = 0, timeoutSeconds = 2, limit = 50 } = {}) {
      const qs = new URLSearchParams({ after: String(after), timeout: String(timeoutSeconds), limit: String(limit) });
      return request("GET", `/api/v1/agent/updates?${qs}`, bearerToken);
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

    async listWallets(bearerToken) {
      const wallets = await request("GET", "/api/v1/wallets", bearerToken);
      return Array.isArray(wallets) ? wallets : [];
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
