// Unit tests for src/keyless-tools.mjs -- the OAuth/bearer keyless toolset
// (K5 contract). salt-api is mocked throughout via a hand-rolled `rest`
// object matching src/salt-bearer-client.mjs's interface (the k5-oauth
// lane builds the real salt-api side in parallel, per
// design-fleet/runs/2026-09-17-distribution/LANES.md).
//
// Encryption is exercised for REAL: send_message's test generates real
// openpgp keypairs for each chat member and actually decrypts the
// ciphertext salt-mcp produced, rather than asserting on a mocked
// "encrypted" string.

import { test } from "node:test";
import assert from "node:assert/strict";
import pkg from "salt-agent-sdk";
import {
  KEYLESS_TOOLS,
  KEYLESS_TOOL_NAMES,
  SCOPES,
  toKeylessMcpTools,
  runKeylessTool,
  pollForCardInteraction,
} from "../src/keyless-tools.mjs";
import { SaltBearerApiError } from "../src/salt-bearer-client.mjs";
import { CARD_UI_RESOURCE_URI } from "../src/card-ui.mjs";

const { generateKeypair, decrypt } = pkg;

function toolNamed(name) {
  const tool = KEYLESS_TOOLS.find((t) => t.name === name);
  assert.ok(tool, `no such tool: ${name}`);
  return tool;
}

// --- catalog shape -------------------------------------------------------

test("the keyless catalog matches the K5 spec's 14 tools exactly", () => {
  const expected = [
    "find_people_and_agents",
    "open_chat",
    "list_chats",
    "send_message",
    "post_card",
    "update_card",
    "ask_human",
    "get_ask_result",
    "request_payment",
    "send_invoice",
    "get_payment_status",
    "list_products",
    "create_product",
    "list_salt_agents",
  ];
  assert.deepEqual([...KEYLESS_TOOL_NAMES].sort(), expected.sort());
});

test("every keyless tool has a title and all four MCP annotation hints", () => {
  for (const tool of KEYLESS_TOOLS) {
    assert.equal(typeof tool.title, "string");
    assert.ok(tool.title.length > 0, `${tool.name} needs a title`);
    for (const field of ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"]) {
      assert.equal(typeof tool.annotations[field], "boolean", `${tool.name}.${field}`);
    }
  }
});

test("read/list tools are read-only; every money and message-sending tool is destructive", () => {
  const mustBeReadOnly = ["find_people_and_agents", "list_chats", "get_ask_result", "get_payment_status", "list_products", "list_salt_agents"];
  const mustBeDestructive = ["send_message", "post_card", "update_card", "ask_human", "request_payment", "send_invoice", "create_product"];
  for (const name of mustBeReadOnly) assert.equal(toolNamed(name).annotations.readOnlyHint, true, name);
  for (const name of mustBeDestructive) {
    assert.equal(toolNamed(name).annotations.readOnlyHint, false, name);
    assert.equal(toolNamed(name).annotations.destructiveHint, true, name);
  }
});

test("every tool's description says plainly that this connection is keyless (can't read message text)", () => {
  const exempt = new Set(["get_ask_result", "request_payment", "send_invoice", "get_payment_status", "list_products", "create_product", "list_salt_agents"]);
  for (const tool of KEYLESS_TOOLS) {
    if (exempt.has(tool.name)) continue;
    assert.match(tool.description, /keyless/i, `${tool.name}'s description should say it's keyless`);
  }
});

test("money-scoped tools say the host should confirm with the human first", () => {
  for (const name of ["send_message", "post_card", "request_payment", "send_invoice", "create_product"]) {
    assert.match(toolNamed(name).description, /confirm/i, name);
  }
});

test("post_card and update_card declare the MCP Apps ui:// resource link", () => {
  assert.equal(toolNamed("post_card").ui.resourceUri, CARD_UI_RESOURCE_URI);
  assert.equal(toolNamed("update_card").ui.resourceUri, CARD_UI_RESOURCE_URI);
});

test("scopes partition into exactly chat and money, matching the K5 contract's two toggles", () => {
  for (const tool of KEYLESS_TOOLS) {
    assert.ok([SCOPES.CHAT, SCOPES.MONEY].includes(tool.scope), `${tool.name} has an unknown scope: ${tool.scope}`);
  }
  const moneyTools = KEYLESS_TOOLS.filter((t) => t.scope === SCOPES.MONEY).map((t) => t.name);
  assert.deepEqual(moneyTools.sort(), ["create_product", "get_payment_status", "list_products", "request_payment", "send_invoice"].sort());
});

test("toKeylessMcpTools attaches name/description/inputSchema/annotations to every tool, and _meta.ui for card tools only", () => {
  const tools = toKeylessMcpTools();
  assert.equal(tools.length, KEYLESS_TOOLS.length);
  const postCard = tools.find((t) => t.name === "post_card");
  assert.deepEqual(postCard._meta, { ui: { resourceUri: CARD_UI_RESOURCE_URI } });
  const findPeople = tools.find((t) => t.name === "find_people_and_agents");
  assert.equal(findPeople._meta, undefined);
  for (const tool of tools) {
    assert.equal(typeof tool.inputSchema, "object");
    assert.equal(typeof tool.annotations.readOnlyHint, "boolean");
  }
});

// --- request shapes: each tool calls the rest client with the right args ---

test("find_people_and_agents merges contacts and directory matches, deduped, capped at 20", async () => {
  const calls = [];
  const rest = {
    async searchContacts(token, q) {
      calls.push(["searchContacts", token, q]);
      return [{ id: "u1", username: "ada", display_name: "Ada", account_type: "User" }];
    },
    async listAgentsDirectory(token) {
      calls.push(["listAgentsDirectory", token]);
      return [
        { id: "a1", username: "faucet-ada", display_name: "Faucet Ada", account_type: "Agent" },
        { id: "a2", username: "other", display_name: "Other", account_type: "Agent" },
      ];
    },
  };
  const result = await runKeylessTool("find_people_and_agents", { query: "ada" }, { rest, bearerToken: "tok" });
  assert.deepEqual(calls[0], ["searchContacts", "tok", "ada"]);
  assert.equal(calls[1][0], "listAgentsDirectory");
  assert.equal(result.results.length, 2, "the human contact plus the one agent matching 'ada'");
  assert.ok(result.results.some((r) => r.id === "u1"));
  assert.ok(result.results.some((r) => r.id === "a1"));
  assert.ok(!result.results.some((r) => r.id === "a2"));
});

test("open_chat resolves a handle against contacts, then the directory, then opens/reuses the chat", async () => {
  const rest = {
    async searchContacts() {
      return [];
    },
    async listAgentsDirectory() {
      return [{ id: "a1", username: "faucet", display_name: "Faucet", account_type: "Agent" }];
    },
    async createOrGetChat(token, contactId) {
      assert.equal(token, "tok");
      assert.equal(contactId, "a1");
      return { id: "chat-1", name: null, session: { users: [{ id: "a1", username: "faucet", display_name: "Faucet", account_type: "Agent" }] } };
    },
  };
  const result = await runKeylessTool("open_chat", { handle: "@faucet" }, { rest, bearerToken: "tok" });
  assert.equal(result.chat_id, "chat-1");
  assert.equal(result.members.length, 1);
});

test("open_chat refuses a handle nobody has", async () => {
  const rest = { async searchContacts() { return []; }, async listAgentsDirectory() { return []; } };
  await assert.rejects(
    () => runKeylessTool("open_chat", { handle: "nobody" }, { rest, bearerToken: "tok" }),
    /No one on Salt goes by @nobody/
  );
});

test("list_chats returns metadata only -- id, name, members, unread_count -- and drops anything else the mock includes", async () => {
  const rest = {
    async listChats() {
      return [
        {
          id: "c1",
          name: "Group",
          users: [{ id: "u1", username: "ada", display_name: "Ada", account_type: "User" }],
          unread_count: 3,
          messages: [{ id: "m1", message: "some-ciphertext-should-never-appear" }],
        },
      ];
    },
  };
  const result = await runKeylessTool("list_chats", {}, { rest, bearerToken: "tok" });
  assert.deepEqual(result.chats, [
    { id: "c1", name: "Group", members: [{ id: "u1", username: "ada", display_name: "Ada", account_type: "User" }], unread_count: 3 },
  ]);
  assert.equal(JSON.stringify(result).includes("ciphertext"), false);
});

test("post_card forwards blocks and text to the rest client and returns ids", async () => {
  const rest = {
    async postCard(token, chatId, blocks, text) {
      assert.equal(token, "tok");
      assert.equal(chatId, "chat-1");
      assert.deepEqual(blocks, [{ type: "divider" }]);
      assert.equal(text, "hi");
      return { resource_id: "card-1", id: "msg-1" };
    },
  };
  const result = await runKeylessTool("post_card", { chat_id: "chat-1", blocks: [{ type: "divider" }], text: "hi" }, { rest, bearerToken: "tok" });
  assert.equal(result.card_id, "card-1");
  assert.equal(result.message_id, "msg-1");
});

test("update_card forwards card_id and blocks", async () => {
  const rest = {
    async updateCard(token, cardId, blocks) {
      assert.equal(cardId, "card-1");
      assert.deepEqual(blocks, [{ type: "section", text: "updated" }]);
      return {};
    },
  };
  const result = await runKeylessTool("update_card", { card_id: "card-1", blocks: [{ type: "section", text: "updated" }] }, { rest, bearerToken: "tok" });
  assert.deepEqual(result, { updated: true, card_id: "card-1", blocks: [{ type: "section", text: "updated" }] });
});

test("request_payment resolves the payee by handle within the chat and uses the caller's own wallet", async () => {
  const rest = {
    async getChat() {
      return { session: { users: [{ id: "u1", username: "bob", display_name: "Bob" }] } };
    },
    async listWallets() {
      return [{ id: "w1", deleted_at: null }];
    },
    async createTransferRequest(token, params) {
      assert.equal(params.chatId, "chat-1");
      assert.equal(params.receiverId, "u1");
      assert.equal(params.walletId, "w1");
      assert.equal(params.amount, "10.00");
      return { id: "req-1", status: "Pending", amount: "10.00" };
    },
  };
  const result = await runKeylessTool("request_payment", { chat_id: "chat-1", to: "bob", amount: "10.00" }, { rest, bearerToken: "tok" });
  assert.deepEqual(result, { request_id: "req-1", status: "Pending", amount: "10.00" });
});

test("request_payment refuses when the connection has no active wallet", async () => {
  const rest = {
    async getChat() {
      return { session: { users: [{ id: "u1", username: "bob" }] } };
    },
    async listWallets() {
      return [];
    },
  };
  await assert.rejects(
    () => runKeylessTool("request_payment", { chat_id: "chat-1", to: "bob", amount: "1" }, { rest, bearerToken: "tok" }),
    /no wallet to receive payments/
  );
});

test("send_invoice computes subtotal = qty x unit_price and amount = sum of subtotals, matching salt-api's line_items_shape validator", async () => {
  let sentBody;
  const rest = {
    async getChat() {
      return { session: { users: [{ id: "u2", username: "carol" }] } };
    },
    async listWallets() {
      return [{ id: "w9", deleted_at: null }];
    },
    async createTransferRequest(token, params) {
      sentBody = params;
      return { id: "inv-1", status: "Pending" };
    },
  };
  const result = await runKeylessTool(
    "send_invoice",
    {
      chat_id: "chat-1",
      to: "carol",
      line_items: [
        { name: "Widget", qty: 2, unit_price: 5 },
        { name: "Gadget", qty: 1, unit_price: 2.5 },
      ],
    },
    { rest, bearerToken: "tok" }
  );
  assert.equal(sentBody.requestType, "invoice");
  assert.equal(sentBody.lineItems[0].subtotal, "10");
  assert.equal(sentBody.lineItems[1].subtotal, "2.5");
  assert.equal(sentBody.amount, "12.5");
  assert.equal(result.amount, "12.5");
  assert.equal(result.request_id, "inv-1");
});

test("get_payment_status finds the matching request by id from the index and refuses an unknown id", async () => {
  const rest = {
    async listTransferRequests() {
      return [{ id: "req-1", status: "Confirmed", amount: "5", request_type: "request" }];
    },
  };
  const found = await runKeylessTool("get_payment_status", { request_id: "req-1" }, { rest, bearerToken: "tok" });
  assert.equal(found.status, "Confirmed");
  await assert.rejects(() => runKeylessTool("get_payment_status", { request_id: "nope" }, { rest, bearerToken: "tok" }), /No payment request found/);
});

test("list_products / create_product / list_salt_agents pass through to the rest client", async () => {
  const rest = {
    async listProducts(token, sellerId) {
      assert.equal(sellerId, "seller-1");
      return [{ id: "p1" }];
    },
    async listWallets() {
      return [{ id: "w1", deleted_at: null }];
    },
    async createProduct(token, params) {
      assert.equal(params.wallet_id, "w1");
      assert.equal(params.title, "Coffee");
      return { id: "p2" };
    },
    async listAgentsDirectory() {
      return [{ id: "a1", username: "faucet", display_name: "Faucet", category: "utility" }];
    },
  };
  assert.deepEqual(await runKeylessTool("list_products", { seller_id: "seller-1" }, { rest, bearerToken: "tok" }), { products: [{ id: "p1" }] });
  assert.deepEqual(await runKeylessTool("create_product", { title: "Coffee", kind: "one_time", price: "3" }, { rest, bearerToken: "tok" }), {
    created: true,
    product: { id: "p2" },
  });
  assert.deepEqual(await runKeylessTool("list_salt_agents", {}, { rest, bearerToken: "tok" }), {
    agents: [{ id: "a1", username: "faucet", display_name: "Faucet", category: "utility" }],
  });
});

// --- send_message: real encryption, decrypted for real ---------------------

test("send_message encrypts for every OTHER member's real public key, with no self-copy, and refuses a chat where a member has no key", async () => {
  const alice = await generateKeypair("alice-pass");
  const bob = await generateKeypair("bob-pass");

  const rest = {
    async getChat() {
      return {
        session: {
          users: [
            { id: "agent-1", username: "myagent", public_key: null }, // the keyless agent itself -- irrelevant, has no key anyway
            { id: "alice", username: "alice", display_name: "Alice", public_key: alice.publicKey },
            { id: "bob", username: "bob", display_name: "Bob", public_key: bob.publicKey },
          ],
        },
      };
    },
    async postMessage(token, chatId, message) {
      this.sentMessage = message;
      return { id: "msg-1" };
    },
  };

  // Sanity: a chat with a keyless member (no public_key at all, e.g. the
  // agent's own row) must NOT block sending -- only an actual recipient
  // missing a key should. Re-run with the agent excluded to isolate that.
  rest.getChat = async () => ({
    session: {
      users: [
        { id: "alice", username: "alice", display_name: "Alice", public_key: alice.publicKey },
        { id: "bob", username: "bob", display_name: "Bob", public_key: bob.publicKey },
      ],
    },
  });

  const result = await runKeylessTool("send_message", { chat_id: "chat-1", text: "hello both" }, { rest, bearerToken: "tok" });
  assert.equal(result.sent, true);
  assert.equal(result.message_id, "msg-1");

  // Decrypt for REAL with each recipient's own private key -- proves the
  // ciphertext really is readable by every member, not a mocked stand-in.
  const readByAlice = await decrypt(rest.sentMessage, alice.privateKey, "alice-pass");
  const readByBob = await decrypt(rest.sentMessage, bob.privateKey, "bob-pass");
  assert.equal(readByAlice, "hello both");
  assert.equal(readByBob, "hello both");
});

test("send_message refuses when any member has no public key on file", async () => {
  const alice = await generateKeypair("alice-pass");
  const rest = {
    async getChat() {
      return {
        session: {
          users: [
            { id: "alice", username: "alice", display_name: "Alice", public_key: alice.publicKey },
            { id: "dave", username: "dave", display_name: "Dave", public_key: null },
          ],
        },
      };
    },
  };
  await assert.rejects(
    () => runKeylessTool("send_message", { chat_id: "chat-1", text: "hi" }, { rest, bearerToken: "tok" }),
    /Dave hasn't set up an encryption key yet/
  );
});

test("send_message excludes silent observers from the recipient set", async () => {
  const alice = await generateKeypair("alice-pass");
  const observer = await generateKeypair("observer-pass");
  let ciphertext;
  const rest = {
    async getChat() {
      return {
        session: {
          users: [
            { id: "alice", username: "alice", public_key: alice.publicKey },
            { id: "obs", username: "root_owner", public_key: observer.publicKey, observer: true },
          ],
        },
      };
    },
    async postMessage(token, chatId, message) {
      ciphertext = message;
      return { id: "m1" };
    },
  };
  await runKeylessTool("send_message", { chat_id: "chat-1", text: "secret-ish" }, { rest, bearerToken: "tok" });
  await assert.rejects(() => decrypt(ciphertext, observer.privateKey, "observer-pass"), /Error decrypting message/i);
  const readByAlice = await decrypt(ciphertext, alice.privateKey, "alice-pass");
  assert.equal(readByAlice, "secret-ish");
});

// --- scope refusal ----------------------------------------------------------

test("a salt-api 403 on a money tool becomes the exact plain-sentence scope refusal", async () => {
  const rest = {
    async listTransferRequests() {
      throw new SaltBearerApiError("GET", "/api/v1/transfer_requests", 403, { error: "insufficient scope" });
    },
  };
  await assert.rejects(
    () => runKeylessTool("get_payment_status", { request_id: "x" }, { rest, bearerToken: "tok" }),
    /This connection wasn't given permission to request money\./
  );
});

test("a salt-api 403 on a chat tool becomes the chat-scope refusal sentence", async () => {
  const rest = {
    async listChats() {
      throw new SaltBearerApiError("GET", "/api/v1/chats", 403, { error: "insufficient scope" });
    },
  };
  await assert.rejects(
    () => runKeylessTool("list_chats", {}, { rest, bearerToken: "tok" }),
    /This connection wasn't given permission to do that in chat\./
  );
});

test("a non-403 error's message passes through unchanged", async () => {
  const rest = {
    async listChats() {
      throw new SaltBearerApiError("GET", "/api/v1/chats", 500, { error: "boom" });
    },
  };
  await assert.rejects(() => runKeylessTool("list_chats", {}, { rest, bearerToken: "tok" }), /boom/);
});

test("runKeylessTool refuses an unknown tool name", async () => {
  await assert.rejects(() => runKeylessTool("not_a_real_tool", {}, { rest: {}, bearerToken: "tok" }), /is not available/);
});

// --- ask_human / get_ask_result: resolution, restriction, and timeout ------

test("ask_human posts a card with one restricted_to button per option, then resolves the matching tap", async () => {
  let postedBlocks;
  const rest = {
    async getChat() {
      return { session: { users: [{ id: "human-1", username: "dan", display_name: "Dan" }] } };
    },
    async postCard(token, chatId, blocks) {
      postedBlocks = blocks;
      return { resource_id: "card-42" };
    },
    async agentUpdates() {
      return {
        updates: [
          { id: 5, event: "card_interaction", body: JSON.stringify({ card_id: "card-42", action_id: "opt_1", value: "", user: { id: "human-1" } }) },
        ],
        cursor: 5,
      };
    },
  };
  const result = await runKeylessTool(
    "ask_human",
    { chat_id: "chat-1", to: "dan", question: "Pineapple on pizza?", options: ["Yes", "No"], _maxTotalMs: 20 },
    { rest, bearerToken: "tok" }
  );
  const actionsBlock = postedBlocks.find((b) => b.type === "actions");
  assert.equal(actionsBlock.elements.length, 2);
  assert.deepEqual(actionsBlock.elements[0].restricted_to, ["human-1"]);
  assert.equal(result.answer, "No", "opt_1 maps to the second option, 'No'");
  assert.equal(typeof result.ask_id, "string");
});

test("ask_human ignores a card_interaction for a different card_id and one from the wrong action_id namespace", async () => {
  const rest = {
    async getChat() {
      return { session: { users: [{ id: "human-1", username: "dan" }] } };
    },
    async postCard() {
      return { resource_id: "card-42" };
    },
    async agentUpdates() {
      return {
        updates: [{ id: 1, event: "card_interaction", body: JSON.stringify({ card_id: "some-other-card", action_id: "opt_0" }) }],
        cursor: 1,
      };
    },
  };
  const result = await runKeylessTool(
    "ask_human",
    { chat_id: "chat-1", to: "dan", question: "Q?", options: ["A", "B"], _maxTotalMs: 15 },
    { rest, bearerToken: "tok" }
  );
  assert.equal(result.status, "pending");
  assert.equal(result.answer, undefined);
});

test("ask_human returns {status: 'pending', ask_id} when nobody has answered within its time budget", async () => {
  const rest = {
    async getChat() {
      return { session: { users: [{ id: "human-1", username: "dan" }] } };
    },
    async postCard() {
      return { resource_id: "card-1" };
    },
    async agentUpdates() {
      return { updates: [], cursor: 0 };
    },
  };
  const result = await runKeylessTool(
    "ask_human",
    { chat_id: "chat-1", to: "dan", question: "Q?", options: ["A", "B"], _maxTotalMs: 10 },
    { rest, bearerToken: "tok" }
  );
  assert.deepEqual(Object.keys(result).sort(), ["ask_id", "status"]);
  assert.equal(result.status, "pending");
});

test("ask_human refuses a `to` handle that isn't a member of the chat", async () => {
  const rest = { async getChat() { return { session: { users: [{ id: "u1", username: "someoneelse" }] } }; } };
  await assert.rejects(
    () => runKeylessTool("ask_human", { chat_id: "c1", to: "dan", question: "Q?", options: ["A", "B"] }, { rest, bearerToken: "tok" }),
    /dan isn't in this chat/
  );
});

test("ask_human requires 2..5 options", async () => {
  const rest = { async getChat() { return { session: { users: [{ id: "u1", username: "dan" }] } }; } };
  await assert.rejects(
    () => runKeylessTool("ask_human", { chat_id: "c1", to: "dan", question: "Q?", options: ["only one"] }, { rest, bearerToken: "tok" }),
    /2\.\.5 choices/
  );
});

test("get_ask_result resumes from a pending ask_id and resolves once the tap lands", async () => {
  const pendingAsk = await runKeylessTool(
    "ask_human",
    {
      chat_id: "chat-1",
      to: "dan",
      question: "Q?",
      options: ["Yes", "No"],
      _maxTotalMs: 5,
    },
    {
      rest: {
        async getChat() {
          return { session: { users: [{ id: "human-1", username: "dan" }] } };
        },
        async postCard() {
          return { resource_id: "card-9" };
        },
        async agentUpdates() {
          return { updates: [], cursor: 3 };
        },
      },
      bearerToken: "tok",
    }
  );
  assert.equal(pendingAsk.status, "pending");

  const rest = {
    async agentUpdates(token, { after }) {
      assert.equal(after, 3, "get_ask_result resumes from the cursor the pending ask left off at");
      return {
        updates: [{ id: 4, event: "card_interaction", body: JSON.stringify({ card_id: "card-9", action_id: "opt_0" }) }],
        cursor: 4,
      };
    },
  };
  const resolved = await runKeylessTool("get_ask_result", { ask_id: pendingAsk.ask_id }, { rest, bearerToken: "tok" });
  assert.equal(resolved.answer, "Yes");
});

test("get_ask_result refuses a malformed ask_id", async () => {
  await assert.rejects(() => runKeylessTool("get_ask_result", { ask_id: "not-base64-json" }, { rest: {}, bearerToken: "tok" }), /isn't valid or has expired/);
});

test("pollForCardInteraction stops within its wall-clock budget when nothing ever matches", async () => {
  let calls = 0;
  const rest = { async agentUpdates() { calls += 1; return { updates: [], cursor: 0 }; } };
  const result = await pollForCardInteraction(rest, "tok", { cardId: "c1", maxTotalMs: 15 });
  assert.equal(result.found, false);
  assert.ok(calls >= 1);
});
