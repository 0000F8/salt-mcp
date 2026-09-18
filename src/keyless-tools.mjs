// The KEYLESS toolset for the hosted (OAuth) MCP endpoint -- see the "Remote
// MCP OAuth contract (K5)" in
// design-fleet/runs/2026-09-17-distribution/LANES.md.
//
// Every tool here acts AS the connected client's keyless agent: a Salt
// Agent account the human owns, with a public key on file (so other
// members can encrypt TO it) but NO private key anywhere -- Salt's
// servers never mint one, and this process never holds one either. That
// has one hard consequence threaded through every tool below: this
// server can encrypt outgoing text (send_message) but can never decrypt
// anything, including its own past messages, a "self-copy", or any
// message history. Every tool description says so plainly, so a model
// calling these tools doesn't hallucinate a `list_chats`/`send_message`
// pair into "reading" a conversation.
//
// Distinct from src/annotations.mjs's TOOL_ANNOTATIONS, which is
// cross-checked against salt-agent-sdk's REAL action catalog (see
// tests/annotations.test.mjs) -- these tools are NOT SDK actions (the SDK
// assumes a locally-held private key throughout: encryptFor is the one
// piece of salt-agent-sdk's crypto module this file borrows, since it
// only ever needs recipients' PUBLIC keys). Keeping them in a separate
// map means a new SDK action never has to justify itself against a
// keyless contract it was never designed for, and vice versa.

import pkg from "salt-agent-sdk";
import { SaltBearerApiError } from "./salt-bearer-client.mjs";
import { CARD_UI_RESOURCE_URI } from "./card-ui.mjs";

const { encryptFor } = pkg;

const KEYLESS_NOTE =
  "This connection is keyless: it has no private key, so it can never read chat history or message text, including its own past messages.";

/** Scopes the K5 contract defines (salt-api's OAuth consent screen, `chat` / `money` toggles). */
export const SCOPES = { CHAT: "chat", MONEY: "money" };

const SCOPE_REFUSAL_MESSAGE = {
  [SCOPES.CHAT]: "This connection wasn't given permission to do that in chat.",
  [SCOPES.MONEY]: "This connection wasn't given permission to request money.",
};

// --- small pure helpers -----------------------------------------------

function requireString(value, field) {
  const s = typeof value === "string" ? value.trim() : "";
  if (!s) throw new Error(`${field} is required.`);
  return s;
}

function findMemberByHandle(members, handle) {
  const needle = String(handle || "").trim().toLowerCase().replace(/^@/, "");
  return (Array.isArray(members) ? members : []).find((m) => String(m.username || "").toLowerCase() === needle);
}

/** Picks the caller's own receiving wallet -- mirrors salt-agent-sdk actions.ts's myWalletId. */
async function myWalletId(rest, bearerToken) {
  const wallets = await rest.listWallets(bearerToken);
  const active = wallets.filter((w) => !w.deleted_at);
  if (active.length === 0) throw new Error("This connection has no wallet to receive payments -- add one in Salt first.");
  return active[0].id;
}

/**
 * Decimal-safe-enough multiply for line-item subtotals (qty x unit_price).
 * salt-api's line_items_shape validator re-checks this exactly with
 * BigDecimal, so this only needs to reproduce ordinary decimal arithmetic
 * for realistic prices/quantities -- same tradeoff salt-agent-sdk's
 * sendInvoice already accepts (toFixed then trim), not a full bignum
 * implementation.
 */
function multiplyDecimalStrings(qtyStr, unitPriceStr) {
  const product = Number(qtyStr) * Number(unitPriceStr);
  return product.toFixed(12).replace(/0+$/, "").replace(/\.$/, "") || "0";
}

function sumDecimalStrings(strings) {
  const total = strings.reduce((sum, s) => sum + Number(s), 0);
  return total.toFixed(12).replace(/0+$/, "").replace(/\.$/, "") || "0";
}

function encodeAskId(payload) {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}

function decodeAskId(askId) {
  try {
    return JSON.parse(Buffer.from(String(askId), "base64url").toString("utf8"));
  } catch {
    throw new Error("That ask_id isn't valid or has expired.");
  }
}

/**
 * Short-polls the socket-mode outbox (K2 contract,
 * GET /api/v1/agent/updates) for a card_interaction on `cardId`, up to
 * `maxTotalMs` of wall time. Exported so tests can drive it directly with
 * a small budget and a mock `rest`, instead of waiting out a real 50s
 * budget. Each call to `rest.agentUpdates` is itself expected to pace
 * (the real server waits up to ~2s when there's nothing new -- see K2's
 * "Short poll" contract), so this loop adds no artificial sleep of its
 * own; the wall-clock deadline is what bounds it either way.
 */
export async function pollForCardInteraction(rest, bearerToken, { cardId, after = 0, maxTotalMs }) {
  const deadline = Date.now() + maxTotalMs;
  let cursor = after;
  do {
    const response = await rest.agentUpdates(bearerToken, { after: cursor, timeoutSeconds: 2, limit: 50 });
    const updates = Array.isArray(response?.updates) ? response.updates : [];
    for (const update of updates) {
      if (update.event !== "card_interaction") continue;
      let body;
      try {
        body = typeof update.body === "string" ? JSON.parse(update.body) : update.body;
      } catch {
        continue;
      }
      if (body && String(body.card_id) === String(cardId)) {
        return { found: true, body, cursor: update.id };
      }
    }
    if (response && response.cursor !== undefined) cursor = response.cursor;
  } while (Date.now() < deadline);
  return { found: false, cursor };
}

// --- tool implementations ----------------------------------------------

async function findPeopleAndAgents(rest, bearerToken, input) {
  const query = requireString(input.query, "query");
  const [contacts, agents] = await Promise.all([
    rest.searchContacts(bearerToken, query).catch(() => []),
    rest.listAgentsDirectory(bearerToken).catch(() => []),
  ]);
  const needle = query.toLowerCase();
  const matchedAgents = agents.filter(
    (a) => String(a.username || "").toLowerCase().includes(needle) || String(a.display_name || "").toLowerCase().includes(needle)
  );
  const seen = new Set();
  const results = [];
  for (const person of [...contacts, ...matchedAgents]) {
    const id = String(person.id);
    if (seen.has(id)) continue;
    seen.add(id);
    results.push({
      id: person.id,
      username: person.username,
      display_name: person.display_name,
      account_type: person.account_type || (matchedAgents.includes(person) ? "Agent" : "User"),
    });
    if (results.length >= 20) break;
  }
  return { results };
}

async function openChat(rest, bearerToken, input) {
  const handle = requireString(input.handle, "handle");
  const needle = handle.toLowerCase().replace(/^@/, "");
  const [contacts, agents] = await Promise.all([
    rest.searchContacts(bearerToken, handle).catch(() => []),
    rest.listAgentsDirectory(bearerToken).catch(() => []),
  ]);
  const person =
    contacts.find((p) => String(p.username || "").toLowerCase() === needle) ||
    agents.find((p) => String(p.username || "").toLowerCase() === needle);
  if (!person) throw new Error(`No one on Salt goes by @${handle}.`);
  const chat = await rest.createOrGetChat(bearerToken, person.id);
  const members = chat?.session?.users || chat?.users || [];
  return {
    chat_id: chat.id,
    name: chat.name || null,
    members: members.map((m) => ({ id: m.id, username: m.username, display_name: m.display_name, account_type: m.account_type })),
  };
}

async function listChats(rest, bearerToken) {
  const chats = await rest.listChats(bearerToken);
  return {
    chats: chats.map((chat) => ({
      id: chat.id,
      name: chat.name || null,
      members: (chat.users || chat.members || []).map((m) => ({
        id: m.id,
        username: m.username,
        display_name: m.display_name,
        account_type: m.account_type,
      })),
      unread_count: chat.unread_count ?? 0,
    })),
  };
}

async function sendMessage(rest, bearerToken, input) {
  const chatId = requireString(input.chat_id, "chat_id");
  const text = requireString(input.text, "text");
  const chat = await rest.getChat(bearerToken, chatId);
  const members = chat?.session?.users || chat?.users || [];
  const recipients = members.filter((m) => !m.observer);
  const missingKey = recipients.find((m) => !m.public_key);
  if (missingKey) {
    throw new Error(`Can't send: ${missingKey.display_name || missingKey.username || "a member"} hasn't set up an encryption key yet.`);
  }
  const ciphertext = await encryptFor(text, recipients.map((m) => m.public_key));
  const result = await rest.postMessage(bearerToken, chatId, ciphertext);
  return { sent: true, message_id: result?.id ?? null };
}

async function postCardTool(rest, bearerToken, input) {
  const chatId = requireString(input.chat_id, "chat_id");
  const blocks = Array.isArray(input.blocks) && input.blocks.length > 0 ? input.blocks : null;
  if (!blocks) throw new Error("blocks is required (at least one card block).");
  const result = await rest.postCard(bearerToken, chatId, blocks, input.text || "");
  return { card_id: result?.resource_id ?? result?.id ?? null, message_id: result?.id ?? result?.message_id ?? null, blocks, text: input.text || "" };
}

async function updateCardTool(rest, bearerToken, input) {
  const cardId = requireString(input.card_id, "card_id");
  const blocks = Array.isArray(input.blocks) && input.blocks.length > 0 ? input.blocks : null;
  if (!blocks) throw new Error("blocks is required (at least one card block).");
  await rest.updateCard(bearerToken, cardId, blocks);
  return { updated: true, card_id: cardId, blocks };
}

async function askHuman(rest, bearerToken, input) {
  const chatId = requireString(input.chat_id, "chat_id");
  const to = requireString(input.to, "to");
  const question = requireString(input.question, "question");
  const options = Array.isArray(input.options) ? input.options.filter((o) => typeof o === "string" && o.trim()) : [];
  if (options.length < 2 || options.length > 5) throw new Error("options must have 2..5 choices.");

  const chat = await rest.getChat(bearerToken, chatId);
  const members = chat?.session?.users || chat?.users || [];
  const human = findMemberByHandle(members, to);
  if (!human) throw new Error(`@${to.replace(/^@/, "")} isn't in this chat.`);

  const actionMap = {};
  const elements = options.map((label, i) => {
    const actionId = `opt_${i}`;
    actionMap[actionId] = label;
    return { type: "button", action_id: actionId, label: label.slice(0, 40), restricted_to: [human.id] };
  });
  const blocks = [{ type: "section", text: question.slice(0, 2000) }, { type: "actions", elements }];
  const posted = await rest.postCard(bearerToken, chatId, blocks, question.slice(0, 200));
  const cardId = posted?.resource_id ?? posted?.id;

  // `_maxTotalMs` is not part of the public inputSchema -- it's a test-only
  // escape hatch (see tests/keyless-tools.test.mjs) so a test can exercise
  // the "nobody answered in time" path without a real MCP client ever
  // being able to set it, since real tool arguments are validated against
  // inputSchema upstream of execute().
  const poll = await pollForCardInteraction(rest, bearerToken, { cardId, after: 0, maxTotalMs: input._maxTotalMs ?? 50000 });
  const askId = encodeAskId({ cardId, chatId, humanId: human.id, actionMap, cursor: poll.cursor ?? 0 });
  if (!poll.found) return { status: "pending", ask_id: askId };

  const answer = actionMap[poll.body.action_id] ?? poll.body.value ?? poll.body.action_id;
  return { answer, ask_id: askId };
}

async function getAskResult(rest, bearerToken, input) {
  const askId = requireString(input.ask_id, "ask_id");
  const state = decodeAskId(askId);
  const poll = await pollForCardInteraction(rest, bearerToken, {
    cardId: state.cardId,
    after: state.cursor ?? 0,
    maxTotalMs: input._maxTotalMs ?? 2000,
  });
  const nextAskId = encodeAskId({ ...state, cursor: poll.cursor ?? state.cursor ?? 0 });
  if (!poll.found) return { status: "pending", ask_id: nextAskId };
  const answer = state.actionMap?.[poll.body.action_id] ?? poll.body.value ?? poll.body.action_id;
  return { answer, ask_id: nextAskId };
}

async function requestPayment(rest, bearerToken, input) {
  const chatId = requireString(input.chat_id, "chat_id");
  const to = requireString(input.to, "to");
  const amount = requireString(input.amount, "amount");
  const chat = await rest.getChat(bearerToken, chatId);
  const members = chat?.session?.users || chat?.users || [];
  const receiver = findMemberByHandle(members, to);
  if (!receiver) throw new Error(`@${to.replace(/^@/, "")} isn't in this chat.`);
  const walletId = await myWalletId(rest, bearerToken);
  const request = await rest.createTransferRequest(bearerToken, {
    chatId,
    receiverId: receiver.id,
    walletId,
    amount,
    message: input.message || "",
  });
  return { request_id: request.id, status: request.status, amount: request.amount };
}

async function sendInvoice(rest, bearerToken, input) {
  const chatId = requireString(input.chat_id, "chat_id");
  const to = requireString(input.to, "to");
  const items = Array.isArray(input.line_items) ? input.line_items : [];
  if (items.length === 0) throw new Error("line_items is required.");
  const chat = await rest.getChat(bearerToken, chatId);
  const members = chat?.session?.users || chat?.users || [];
  const receiver = findMemberByHandle(members, to);
  if (!receiver) throw new Error(`@${to.replace(/^@/, "")} isn't in this chat.`);

  const lineItems = items.map((item) => {
    const name = requireString(item.name, "line_items[].name");
    const qty = requireString(String(item.qty), "line_items[].qty");
    const unitPrice = requireString(String(item.unit_price), "line_items[].unit_price");
    return { name, qty, unit_price: unitPrice, subtotal: multiplyDecimalStrings(qty, unitPrice) };
  });
  const amount = sumDecimalStrings(lineItems.map((i) => i.subtotal));
  const walletId = await myWalletId(rest, bearerToken);
  const invoice = await rest.createTransferRequest(bearerToken, {
    chatId,
    receiverId: receiver.id,
    walletId,
    amount,
    message: lineItems.map((i) => i.name).join(", ").slice(0, 100),
    requestType: "invoice",
    lineItems,
    dueAt: input.due_date,
  });
  return { request_id: invoice.id, amount, status: invoice.status };
}

async function getPaymentStatus(rest, bearerToken, input) {
  const requestId = requireString(input.request_id, "request_id");
  const requests = await rest.listTransferRequests(bearerToken);
  const found = requests.find((r) => String(r.id) === requestId);
  if (!found) throw new Error("No payment request found with that id.");
  return {
    id: found.id,
    status: found.status,
    amount: found.amount,
    request_type: found.request_type || "request",
    last_failed_reason: found.last_failed_reason || null,
  };
}

async function listProductsTool(rest, bearerToken, input) {
  const products = await rest.listProducts(bearerToken, input.seller_id);
  return { products };
}

async function createProductTool(rest, bearerToken, input) {
  const walletId = await myWalletId(rest, bearerToken);
  const product = await rest.createProduct(bearerToken, { ...input, wallet_id: walletId });
  return { created: true, product };
}

async function listSaltAgents(rest, bearerToken) {
  const agents = await rest.listAgentsDirectory(bearerToken);
  return { agents: agents.map((a) => ({ id: a.id, username: a.username, display_name: a.display_name, category: a.category })) };
}

// --- tool catalog --------------------------------------------------------

const MONEY_HINT = "The host should confirm the amount and counterparty with the human before calling this.";
const SEND_HINT = "The host should confirm the content with the human before calling this.";

/**
 * @typedef {{
 *   name: string,
 *   title: string,
 *   description: string,
 *   scope: "chat" | "money",
 *   inputSchema: object,
 *   outputSchema?: object,
 *   annotations: { readOnlyHint: boolean, destructiveHint: boolean, idempotentHint: boolean, openWorldHint: boolean },
 *   ui?: { resourceUri: string },
 *   execute: (rest: object, bearerToken: string, input: object) => Promise<object>,
 * }} KeylessTool
 */

/** @type {KeylessTool[]} */
export const KEYLESS_TOOLS = [
  {
    name: "find_people_and_agents",
    title: "Find People and Agents",
    description: `Search Salt's contacts and the public agent directory by name or @handle. ${KEYLESS_NOTE}`,
    scope: SCOPES.CHAT,
    inputSchema: {
      type: "object",
      properties: { query: { type: "string", description: "A name or @handle to search for." } },
      required: ["query"],
    },
    outputSchema: {
      type: "object",
      properties: {
        results: {
          type: "array",
          items: {
            type: "object",
            properties: {
              id: { type: "string" },
              username: { type: "string" },
              display_name: { type: "string" },
              account_type: { type: "string", enum: ["User", "Agent"] },
            },
          },
        },
      },
      required: ["results"],
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    execute: findPeopleAndAgents,
  },
  {
    name: "open_chat",
    title: "Open Chat",
    description: `Opens (or reuses) a 1:1 chat with a person or agent by @handle. ${KEYLESS_NOTE}`,
    scope: SCOPES.CHAT,
    inputSchema: {
      type: "object",
      properties: { handle: { type: "string", description: "The @handle of the person or agent to open a chat with." } },
      required: ["handle"],
    },
    outputSchema: {
      type: "object",
      properties: {
        chat_id: { type: "string" },
        name: { type: ["string", "null"] },
        members: { type: "array", items: { type: "object" } },
      },
      required: ["chat_id"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    execute: openChat,
  },
  {
    name: "list_chats",
    title: "List Chats",
    description: `Lists this connection's chats -- names, members, and unread counts only, never message content. ${KEYLESS_NOTE}`,
    scope: SCOPES.CHAT,
    inputSchema: { type: "object", properties: {} },
    outputSchema: {
      type: "object",
      properties: { chats: { type: "array", items: { type: "object" } } },
      required: ["chats"],
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    execute: (rest, bearerToken) => listChats(rest, bearerToken),
  },
  {
    name: "send_message",
    title: "Send Message",
    description:
      `Sends a real, visible message into a Salt chat, encrypted to every member's public key. ${KEYLESS_NOTE} ` +
      `Refuses if any member hasn't set up an encryption key. ${SEND_HINT}`,
    scope: SCOPES.CHAT,
    inputSchema: {
      type: "object",
      properties: {
        chat_id: { type: "string" },
        text: { type: "string", description: "The message to send, plain text." },
      },
      required: ["chat_id", "text"],
    },
    outputSchema: { type: "object", properties: { sent: { type: "boolean" }, message_id: { type: ["string", "null"] } }, required: ["sent"] },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    execute: sendMessage,
  },
  {
    name: "post_card",
    title: "Post Card",
    description:
      "Posts a declarative blocks card (section/fields/image/divider/actions) into a chat -- polls, order status, menus, anything tappable that isn't free money movement. " +
      `${SEND_HINT} ${KEYLESS_NOTE}`,
    scope: SCOPES.CHAT,
    inputSchema: {
      type: "object",
      properties: {
        chat_id: { type: "string" },
        blocks: { type: "array", description: "Card blocks: section, fields, image, divider, actions.", items: { type: "object" } },
        text: { type: "string", description: "A short plaintext caption/fallback for the card's chat bubble." },
      },
      required: ["chat_id", "blocks"],
    },
    outputSchema: {
      type: "object",
      properties: { card_id: { type: ["string", "null"] }, message_id: { type: ["string", "null"] }, blocks: { type: "array" }, text: { type: "string" } },
      required: ["card_id"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    ui: { resourceUri: CARD_UI_RESOURCE_URI },
    execute: postCardTool,
  },
  {
    name: "update_card",
    title: "Update Card",
    description: `Replaces a card this connection owns with new blocks -- re-broadcasts live into everyone's bubble. ${KEYLESS_NOTE}`,
    scope: SCOPES.CHAT,
    inputSchema: {
      type: "object",
      properties: {
        card_id: { type: "string" },
        blocks: { type: "array", items: { type: "object" } },
      },
      required: ["card_id", "blocks"],
    },
    outputSchema: {
      type: "object",
      properties: { updated: { type: "boolean" }, card_id: { type: "string" }, blocks: { type: "array" } },
      required: ["updated", "card_id"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    ui: { resourceUri: CARD_UI_RESOURCE_URI },
    execute: updateCardTool,
  },
  {
    name: "ask_human",
    title: "Ask Human",
    description:
      "Posts a card with option buttons restricted to one chosen chat member, then waits (up to ~50s) for their tap. " +
      "Returns their answer, or {status: 'pending', ask_id} to keep checking later with get_ask_result. " +
      `${KEYLESS_NOTE}`,
    scope: SCOPES.CHAT,
    inputSchema: {
      type: "object",
      properties: {
        chat_id: { type: "string" },
        to: { type: "string", description: "The @handle of the chat member being asked -- only they can tap." },
        question: { type: "string" },
        options: { type: "array", items: { type: "string" }, minItems: 2, maxItems: 5 },
      },
      required: ["chat_id", "to", "question", "options"],
    },
    outputSchema: {
      type: "object",
      properties: { answer: { type: "string" }, status: { type: "string", enum: ["pending"] }, ask_id: { type: "string" } },
      required: ["ask_id"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    execute: askHuman,
  },
  {
    name: "get_ask_result",
    title: "Get Ask Result",
    description: "Checks again for the answer to a pending ask_human call, using the ask_id it returned.",
    scope: SCOPES.CHAT,
    inputSchema: { type: "object", properties: { ask_id: { type: "string" } }, required: ["ask_id"] },
    outputSchema: {
      type: "object",
      properties: { answer: { type: "string" }, status: { type: "string", enum: ["pending"] }, ask_id: { type: "string" } },
      required: ["ask_id"],
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    execute: getAskResult,
  },
  {
    name: "request_payment",
    title: "Request Payment",
    description: `Creates a real, payable money request from a chat member. ${MONEY_HINT}`,
    scope: SCOPES.MONEY,
    inputSchema: {
      type: "object",
      properties: {
        chat_id: { type: "string" },
        to: { type: "string", description: "The @handle of the chat member being asked to pay." },
        amount: { type: "string", description: "A decimal amount, e.g. \"12.50\"." },
        message: { type: "string" },
      },
      required: ["chat_id", "to", "amount"],
    },
    outputSchema: {
      type: "object",
      properties: { request_id: { type: "string" }, status: { type: "string" }, amount: { type: "string" } },
      required: ["request_id"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    execute: requestPayment,
  },
  {
    name: "send_invoice",
    title: "Send Invoice",
    description: `Sends an itemized invoice to a chat member on the same payment rail as request_payment. ${MONEY_HINT}`,
    scope: SCOPES.MONEY,
    inputSchema: {
      type: "object",
      properties: {
        chat_id: { type: "string" },
        to: { type: "string" },
        line_items: {
          type: "array",
          items: {
            type: "object",
            properties: {
              name: { type: "string" },
              qty: { type: ["string", "number"] },
              unit_price: { type: ["string", "number"] },
            },
            required: ["name", "qty", "unit_price"],
          },
        },
        due_date: { type: "string" },
      },
      required: ["chat_id", "to", "line_items"],
    },
    outputSchema: {
      type: "object",
      properties: { request_id: { type: "string" }, amount: { type: "string" }, status: { type: "string" } },
      required: ["request_id", "amount"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    execute: sendInvoice,
  },
  {
    name: "get_payment_status",
    title: "Get Payment Status",
    description: "Reads the current status of a payment request or invoice this connection sent.",
    scope: SCOPES.MONEY,
    inputSchema: { type: "object", properties: { request_id: { type: "string" } }, required: ["request_id"] },
    outputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
        status: { type: "string" },
        amount: { type: "string" },
        request_type: { type: "string" },
        last_failed_reason: { type: ["string", "null"] },
      },
      required: ["id", "status"],
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    execute: getPaymentStatus,
  },
  {
    name: "list_products",
    title: "List Products",
    description: "Lists this connection's own products, or a seller's active products.",
    scope: SCOPES.MONEY,
    inputSchema: { type: "object", properties: { seller_id: { type: "string" } } },
    outputSchema: { type: "object", properties: { products: { type: "array", items: { type: "object" } } }, required: ["products"] },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    execute: listProductsTool,
  },
  {
    name: "create_product",
    title: "Create Product",
    description: `Adds a real, billable product to this connection's shop. ${MONEY_HINT}`,
    scope: SCOPES.MONEY,
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string" },
        kind: { type: "string", enum: ["one_time", "metered", "subscription"] },
        price: { type: "string" },
        description: { type: "string" },
      },
      required: ["title", "kind", "price"],
    },
    outputSchema: { type: "object", properties: { created: { type: "boolean" }, product: { type: "object" } }, required: ["created"] },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    execute: createProductTool,
  },
  {
    name: "list_salt_agents",
    title: "List Salt Agents",
    description: "Browses the public Salt agent directory.",
    scope: SCOPES.CHAT,
    inputSchema: { type: "object", properties: {} },
    outputSchema: { type: "object", properties: { agents: { type: "array", items: { type: "object" } } }, required: ["agents"] },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    execute: (rest, bearerToken) => listSaltAgents(rest, bearerToken),
  },
];

export const KEYLESS_TOOL_NAMES = new Set(KEYLESS_TOOLS.map((t) => t.name));

/** Maps a keyless tool's definition to an MCP Tool object, including the MCP Apps `_meta.ui.resourceUri` link where declared. */
export function toKeylessMcpTools(tools = KEYLESS_TOOLS) {
  return tools.map((tool) => {
    const mcpTool = {
      name: tool.name,
      title: tool.title,
      description: tool.description,
      inputSchema: tool.inputSchema,
      annotations: { title: tool.title, ...tool.annotations },
    };
    if (tool.outputSchema) mcpTool.outputSchema = tool.outputSchema;
    if (tool.ui?.resourceUri) mcpTool._meta = { ui: { resourceUri: tool.ui.resourceUri } };
    return mcpTool;
  });
}

/**
 * Runs one keyless tool by name. Rewrites a salt-api 403 into a plain
 * sentence naming the missing scope (per the K5 contract: "When salt-api
 * answers 403 for a missing scope, return a plain-sentence tool error").
 * Any other error's message is passed through as-is -- SaltBearerApiError
 * already carries salt-api's own one-sentence `error` body.
 */
export async function runKeylessTool(name, args, { rest, bearerToken }) {
  const tool = KEYLESS_TOOLS.find((t) => t.name === name);
  if (!tool) throw new Error(`Tool "${name}" is not available on this connection.`);
  try {
    return await tool.execute(rest, bearerToken, args ?? {});
  } catch (err) {
    if (err instanceof SaltBearerApiError && err.status === 403) {
      throw new Error(SCOPE_REFUSAL_MESSAGE[tool.scope] || SCOPE_REFUSAL_MESSAGE[SCOPES.CHAT]);
    }
    throw err;
  }
}

/** For the MCP Apps resource wiring in src/http.mjs. */
export { CARD_UI_RESOURCE_URI };
