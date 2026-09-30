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
//
// Every Salt-record id fixture below is a real uuid shape -- deliberately,
// since src/keyless-tools.mjs's assertPlainId now refuses anything else
// (a 2026-09-18 security review found un-validated ids letting a crafted
// `card_id` redirect an outbound request to an unrelated salt-api
// endpoint; see the dedicated "id validation" section near the bottom).

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

const CHAT_ID = "11111111-1111-1111-1111-111111111111";
const CARD_ID = "22222222-2222-2222-2222-222222222222";
const CARD_ID_2 = "33333333-3333-3333-3333-333333333333";
const RECEIVER_ID = "44444444-4444-4444-4444-444444444444";
const REQUEST_ID = "55555555-5555-5555-5555-555555555555";
const SELLER_ID = "66666666-6666-6666-6666-666666666666";
const HUMAN_ID = "77777777-7777-7777-7777-777777777777";
const WALLET_ID = "88888888-8888-8888-8888-888888888888";

/** A grant carrying one wallet on ethereum mainnet -- the shape src/http.mjs's token validation fetches from GET /api/v1/oauth2/grant. */
const ETH_GRANT = { scopes: ["chat", "money"], wallets: [{ id: WALLET_ID, chain: "ethereum", testnet: false, label: "Main" }] };

function toolNamed(name) {
  const tool = KEYLESS_TOOLS.find((t) => t.name === name);
  assert.ok(tool, `no such tool: ${name}`);
  return tool;
}

// --- catalog shape -------------------------------------------------------

test("the keyless catalog matches the K5 spec's 14 tools plus the four open-room tools (2026-09-22)", () => {
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
    "salt_read_room",
    "salt_set_room_interests",
    "salt_clear_room_interests",
    "salt_join_commons",
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
  // The four open-room tools are the deliberate exception: an open room has
  // no PGP at all, so a keyless connection genuinely CAN read one -- the
  // blanket "can never read" framing this test checks for would be actively
  // false on salt_read_room. Its own description explains the real
  // capability/limit instead (see room-tools.test.mjs for that coverage).
  const exempt = new Set([
    "get_ask_result",
    "request_payment",
    "send_invoice",
    "get_payment_status",
    "list_products",
    "create_product",
    "list_salt_agents",
    "salt_read_room",
    "salt_set_room_interests",
    "salt_clear_room_interests",
    "salt_join_commons",
  ]);
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

test("no money tool's inputSchema or description proposes a wallet of the agent's own -- every one requires `chain` and reads from the grant", () => {
  for (const name of ["request_payment", "send_invoice", "create_product"]) {
    const tool = toolNamed(name);
    assert.ok(tool.inputSchema.required.includes("chain"), `${name} should require chain`);
    assert.doesNotMatch(tool.description, /this agent's own wallet|its own wallet|provision.*wallet/i, name);
  }
});

// --- request shapes: each tool calls the rest client with the right args ---

test("find_people_and_agents merges contacts and directory matches, deduped, capped at 20", async () => {
  const calls = [];
  const rest = {
    async searchContacts(token, q) {
      calls.push(["searchContacts", token, q]);
      return [{ id: RECEIVER_ID, username: "ada", display_name: "Ada", account_type: "User" }];
    },
    async listAgentsDirectory(token) {
      calls.push(["listAgentsDirectory", token]);
      return [
        { id: "a1111111-1111-1111-1111-111111111111", username: "faucet-ada", display_name: "Faucet Ada", account_type: "Agent" },
        { id: "a2222222-2222-2222-2222-222222222222", username: "other", display_name: "Other", account_type: "Agent" },
      ];
    },
  };
  const result = await runKeylessTool("find_people_and_agents", { query: "ada" }, { rest, bearerToken: "tok" });
  assert.deepEqual(calls[0], ["searchContacts", "tok", "ada"]);
  assert.equal(calls[1][0], "listAgentsDirectory");
  assert.equal(result.results.length, 2, "the human contact plus the one agent matching 'ada'");
  assert.ok(result.results.some((r) => r.id === RECEIVER_ID));
  assert.ok(result.results.some((r) => r.username === "faucet-ada"));
  assert.ok(!result.results.some((r) => r.username === "other"));
});

test("open_chat resolves a handle against contacts, then the directory, then opens/reuses the chat", async () => {
  const rest = {
    async searchContacts() {
      return [];
    },
    async listAgentsDirectory() {
      return [{ id: RECEIVER_ID, username: "faucet", display_name: "Faucet", account_type: "Agent" }];
    },
    async createOrGetChat(token, contactId) {
      assert.equal(token, "tok");
      assert.equal(contactId, RECEIVER_ID);
      // POST /api/v1/chats' real shape: the chat payload at the top level.
      return { id: CHAT_ID, name: null, users: [{ id: RECEIVER_ID, username: "faucet", display_name: "Faucet", account_type: "Agent" }] };
    },
  };
  const result = await runKeylessTool("open_chat", { handle: "@faucet" }, { rest, bearerToken: "tok" });
  assert.equal(result.chat_id, CHAT_ID);
  assert.equal(result.members.length, 1);
});

test("open_chat also reads a {session} wrapped chat payload", async () => {
  const rest = {
    async searchContacts() { return []; },
    async listAgentsDirectory() {
      return [{ id: RECEIVER_ID, username: "faucet", display_name: "Faucet", account_type: "Agent" }];
    },
    async createOrGetChat() {
      return { session: { id: CHAT_ID, name: "F", users: [{ id: RECEIVER_ID, username: "faucet" }] } };
    },
  };
  const result = await runKeylessTool("open_chat", { handle: "faucet" }, { rest, bearerToken: "tok" });
  assert.equal(result.chat_id, CHAT_ID);
  assert.equal(result.name, "F");
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
        // GET /api/v1/chats' real row shape: the chat nested under `session`.
        {
          session: {
            id: CHAT_ID,
            name: "Group",
            users: [{ id: RECEIVER_ID, username: "ada", display_name: "Ada", account_type: "User" }],
            unread_count: 3,
          },
          recent_message: { message: { id: "m1", message: "some-ciphertext-should-never-appear" } },
        },
      ];
    },
  };
  const result = await runKeylessTool("list_chats", {}, { rest, bearerToken: "tok" });
  assert.deepEqual(result.chats, [
    { id: CHAT_ID, name: "Group", members: [{ id: RECEIVER_ID, username: "ada", display_name: "Ada", account_type: "User" }], unread_count: 3 },
  ]);
  assert.equal(JSON.stringify(result).includes("ciphertext"), false);
});

test("post_card forwards blocks and text to the rest client and returns ids", async () => {
  const rest = {
    async postCard(token, chatId, blocks, text) {
      assert.equal(token, "tok");
      assert.equal(chatId, CHAT_ID);
      assert.deepEqual(blocks, [{ type: "divider" }]);
      assert.equal(text, "hi");
      return { resource_id: CARD_ID, id: "msg-1" };
    },
  };
  const result = await runKeylessTool("post_card", { chat_id: CHAT_ID, blocks: [{ type: "divider" }], text: "hi" }, { rest, bearerToken: "tok" });
  assert.equal(result.card_id, CARD_ID);
  assert.equal(result.message_id, "msg-1");
});

test("update_card forwards card_id and blocks", async () => {
  const rest = {
    async updateCard(token, cardId, blocks) {
      assert.equal(cardId, CARD_ID);
      assert.deepEqual(blocks, [{ type: "section", text: "updated" }]);
      return {};
    },
  };
  const result = await runKeylessTool("update_card", { card_id: CARD_ID, blocks: [{ type: "section", text: "updated" }] }, { rest, bearerToken: "tok" });
  assert.deepEqual(result, { updated: true, card_id: CARD_ID, blocks: [{ type: "section", text: "updated" }] });
});

test("request_payment resolves the payee by handle within the chat and spends the wallet the grant attached for that chain", async () => {
  const rest = {
    async getChat() {
      return { session: { users: [{ id: RECEIVER_ID, username: "bob", display_name: "Bob" }] } };
    },
    async createTransferRequest(token, params) {
      assert.equal(params.chatId, CHAT_ID);
      assert.equal(params.receiverId, RECEIVER_ID);
      assert.equal(params.walletId, WALLET_ID);
      assert.equal(params.amount, "10.00");
      return { id: REQUEST_ID, status: "Pending", amount: "10.00" };
    },
  };
  const result = await runKeylessTool(
    "request_payment",
    { chat_id: CHAT_ID, to: "bob", amount: "10.00", chain: "Ethereum" },
    { rest, bearerToken: "tok", grant: ETH_GRANT }
  );
  assert.deepEqual(result, { request_id: REQUEST_ID, status: "Pending", amount: "10.00" });
});

test("request_payment refuses when the grant has no wallet for the requested chain, and NEVER reads /api/v1/wallets", async () => {
  const rest = {
    async getChat() {
      return { session: { users: [{ id: RECEIVER_ID, username: "bob" }] } };
    },
    // Deliberately no listWallets on this mock at all -- if the tool tried
    // to call it, the test would throw "rest.listWallets is not a
    // function" rather than the expected refusal, catching a regression
    // back to reading /api/v1/wallets.
  };
  await assert.rejects(
    () => runKeylessTool("request_payment", { chat_id: CHAT_ID, to: "bob", amount: "1", chain: "base" }, { rest, bearerToken: "tok", grant: ETH_GRANT }),
    /This connection can't receive payments on base\. The owner can add a wallet in Salt/
  );
});

test("request_payment refuses on testnet even when a mainnet wallet for the same chain is granted", async () => {
  const rest = { async getChat() { return { session: { users: [{ id: RECEIVER_ID, username: "bob" }] } }; } };
  await assert.rejects(
    () =>
      runKeylessTool(
        "request_payment",
        { chat_id: CHAT_ID, to: "bob", amount: "1", chain: "ethereum", testnet: true },
        { rest, bearerToken: "tok", grant: ETH_GRANT }
      ),
    /ethereum testnet/
  );
});

test("send_invoice computes subtotal = qty x unit_price and amount = sum of subtotals, matching salt-api's line_items_shape validator", async () => {
  let sentBody;
  const rest = {
    async getChat() {
      return { session: { users: [{ id: RECEIVER_ID, username: "carol" }] } };
    },
    async createTransferRequest(token, params) {
      sentBody = params;
      return { id: REQUEST_ID, status: "Pending" };
    },
  };
  const result = await runKeylessTool(
    "send_invoice",
    {
      chat_id: CHAT_ID,
      to: "carol",
      chain: "ethereum",
      line_items: [
        { name: "Widget", qty: 2, unit_price: 5 },
        { name: "Gadget", qty: 1, unit_price: 2.5 },
      ],
    },
    { rest, bearerToken: "tok", grant: ETH_GRANT }
  );
  assert.equal(sentBody.requestType, "invoice");
  assert.equal(sentBody.walletId, WALLET_ID);
  assert.equal(sentBody.lineItems[0].subtotal, "10");
  assert.equal(sentBody.lineItems[1].subtotal, "2.5");
  assert.equal(sentBody.amount, "12.5");
  assert.equal(result.amount, "12.5");
  assert.equal(result.request_id, REQUEST_ID);
});

test("get_payment_status finds the matching request by id from the index and refuses an unknown id", async () => {
  const rest = {
    async listTransferRequests() {
      return [{ id: REQUEST_ID, status: "Confirmed", amount: "5", request_type: "request" }];
    },
  };
  const found = await runKeylessTool("get_payment_status", { request_id: REQUEST_ID }, { rest, bearerToken: "tok" });
  assert.equal(found.status, "Confirmed");
  await assert.rejects(
    () => runKeylessTool("get_payment_status", { request_id: "99999999-0000-0000-0000-000000000000" }, { rest, bearerToken: "tok" }),
    /No payment request found/
  );
});

test("list_products / create_product / list_salt_agents pass through to the rest client, create_product spending the granted wallet", async () => {
  const rest = {
    async listProducts(token, sellerId) {
      assert.equal(sellerId, SELLER_ID);
      return [{ id: "p1" }];
    },
    async createProduct(token, params) {
      assert.equal(params.wallet_id, WALLET_ID);
      assert.equal(params.title, "Coffee");
      assert.equal("chain" in params, false, "chain/testnet are consumed for wallet resolution, never forwarded to salt-api");
      return { id: "p2" };
    },
    async listAgentsDirectory() {
      return [{ id: RECEIVER_ID, username: "faucet", display_name: "Faucet", category: "utility" }];
    },
  };
  assert.deepEqual(await runKeylessTool("list_products", { seller_id: SELLER_ID }, { rest, bearerToken: "tok" }), { products: [{ id: "p1" }] });
  assert.deepEqual(
    await runKeylessTool("create_product", { title: "Coffee", kind: "one_time", price: "3", chain: "ethereum" }, { rest, bearerToken: "tok", grant: ETH_GRANT }),
    { created: true, product: { id: "p2" } }
  );
  assert.deepEqual(await runKeylessTool("list_salt_agents", {}, { rest, bearerToken: "tok" }), {
    agents: [{ id: RECEIVER_ID, username: "faucet", display_name: "Faucet", category: "utility" }],
  });
});

// --- send_message: real encryption, decrypted for real ---------------------

test("send_message encrypts for every member's real public key -- including this connection's own agent row -- with no self-copy, and refuses a chat where a member has no key", async () => {
  const alice = await generateKeypair("alice-pass");
  const bob = await generateKeypair("bob-pass");

  const rest = {
    async getChat() {
      return {
        session: {
          users: [
            { id: "alice-0000-0000-0000-000000000000", username: "alice", display_name: "Alice", public_key: alice.publicKey },
            { id: "bob-00000-0000-0000-000000000000", username: "bob", display_name: "Bob", public_key: bob.publicKey },
          ],
        },
      };
    },
    async postMessage(token, chatId, message) {
      this.sentMessage = message;
      return { id: "msg-1" };
    },
  };

  const result = await runKeylessTool("send_message", { chat_id: CHAT_ID, text: "hello both" }, { rest, bearerToken: "tok" });
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
            { id: "alice-0000-0000-0000-000000000000", username: "alice", display_name: "Alice", public_key: alice.publicKey },
            { id: "dave-00000-0000-0000-000000000000", username: "dave", display_name: "Dave", public_key: null },
          ],
        },
      };
    },
  };
  await assert.rejects(
    () => runKeylessTool("send_message", { chat_id: CHAT_ID, text: "hi" }, { rest, bearerToken: "tok" }),
    /Dave hasn't set up an encryption key yet/
  );
});

test("send_message INCLUDES a silent observer in the recipient set -- an owner observes a delegation chat precisely to audit it", async () => {
  // A 2026-09-18 security review reversed this: an earlier version of
  // sendMessage excluded observer=true members from encryption, which
  // silently defeated the whole point of CLAUDE.md's "Delegation
  // observability" feature (the owner is added as an observer BECAUSE
  // they should be able to read what happened). Every member with a key
  // gets the ciphertext now, full stop -- observer or not.
  const alice = await generateKeypair("alice-pass");
  const observerOwner = await generateKeypair("observer-pass");
  let ciphertext;
  const rest = {
    async getChat() {
      return {
        session: {
          users: [
            { id: "alice-0000-0000-0000-000000000000", username: "alice", public_key: alice.publicKey },
            { id: "owner-0000-0000-0000-000000000000", username: "root_owner", public_key: observerOwner.publicKey, observer: true },
          ],
        },
      };
    },
    async postMessage(token, chatId, message) {
      ciphertext = message;
      return { id: "m1" };
    },
  };
  await runKeylessTool("send_message", { chat_id: CHAT_ID, text: "auditable" }, { rest, bearerToken: "tok" });
  const readByAlice = await decrypt(ciphertext, alice.privateKey, "alice-pass");
  const readByObserver = await decrypt(ciphertext, observerOwner.privateKey, "observer-pass");
  assert.equal(readByAlice, "auditable");
  assert.equal(readByObserver, "auditable", "the observing owner can decrypt too -- that's the audit trail working");
});

// --- id validation at the tool boundary (path-traversal hardening) --------

test("update_card refuses a card_id crafted to redirect the outbound request to a different salt-api endpoint", async () => {
  const rest = {
    async updateCard() {
      throw new Error("updateCard should never have been called -- assertPlainId must refuse first");
    },
  };
  await assert.rejects(
    () =>
      runKeylessTool(
        "update_card",
        { card_id: "../agents/callback?webhook=https://attacker.example/hook", blocks: [{ type: "divider" }] },
        { rest, bearerToken: "tok" }
      ),
    /card_id must be a plain Salt id/
  );
});

test("id validation refuses a non-plain id on every id-shaped argument, not just card_id", async () => {
  const hostile = "../agents/callback?webhook=https://attacker.example/hook";
  const rest = {}; // never reached -- validation must throw first in every case below
  await assert.rejects(() => runKeylessTool("send_message", { chat_id: hostile, text: "hi" }, { rest, bearerToken: "tok" }), /chat_id must be a plain Salt id/);
  await assert.rejects(() => runKeylessTool("post_card", { chat_id: hostile, blocks: [{ type: "divider" }] }, { rest, bearerToken: "tok" }), /chat_id must be a plain Salt id/);
  await assert.rejects(() => runKeylessTool("get_payment_status", { request_id: hostile }, { rest, bearerToken: "tok" }), /request_id must be a plain Salt id/);
  await assert.rejects(
    () => runKeylessTool("ask_human", { chat_id: hostile, to: "dan", question: "Q?", options: ["A", "B"] }, { rest, bearerToken: "tok" }),
    /chat_id must be a plain Salt id/
  );
  await assert.rejects(
    () => runKeylessTool("list_products", { seller_id: hostile }, { rest, bearerToken: "tok" }),
    /seller_id must be a plain Salt id/
  );
});

test("id validation accepts both uuid and plain-integer ids", async () => {
  const rest = {
    async listTransferRequests() {
      return [{ id: "42", status: "Confirmed", amount: "1" }];
    },
  };
  const byInteger = await runKeylessTool("get_payment_status", { request_id: "42" }, { rest, bearerToken: "tok" });
  assert.equal(byInteger.status, "Confirmed");
  const byUuid = await runKeylessTool("get_payment_status", { request_id: REQUEST_ID }, { rest: { async listTransferRequests() { return [{ id: REQUEST_ID, status: "Pending", amount: "1" }]; } }, bearerToken: "tok" });
  assert.equal(byUuid.status, "Pending");
});

// --- scope refusal ----------------------------------------------------------

test("a salt-api 403 on a money tool becomes the exact plain-sentence scope refusal", async () => {
  const rest = {
    async listTransferRequests() {
      throw new SaltBearerApiError("GET", "/api/v1/transfer_requests", 403, { error: "insufficient scope" });
    },
  };
  await assert.rejects(
    () => runKeylessTool("get_payment_status", { request_id: REQUEST_ID }, { rest, bearerToken: "tok" }),
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
//
// `maxTotalMsOverride` below rides in the OPTIONS object (this test file's
// own `runKeylessTool(name, args, {...})` third argument), never in
// `args`/`input` -- exactly the boundary that keeps a real MCP client from
// ever setting it (src/http.mjs's one real call site never populates it).
// See keyless-tools.mjs's runKeylessTool doc comment.
//
// Every `rest.getCard` mock below returns `{ interactions: [...] }`
// (salt-api 0.96.0's `GET /api/v1/cards/:id` shape, newest first) --
// polling THIS card directly, never the old shared socket-mode outbox
// (`GET /api/v1/agent/updates`), is the whole point of this file's
// rewrite: see keyless-tools.mjs's pollForCardInteraction doc comment for
// why the outbox's one-cursor-per-agent design could strand an ask.

test("ask_human posts a card with one restricted_to button per option, then resolves the matching tap", async () => {
  let postedBlocks;
  const rest = {
    async getChat() {
      return { session: { users: [{ id: HUMAN_ID, username: "dan", display_name: "Dan" }] } };
    },
    async postCard(token, chatId, blocks) {
      postedBlocks = blocks;
      return { resource_id: CARD_ID };
    },
    async getCard(token, cardId) {
      assert.equal(cardId, CARD_ID);
      return { interactions: [{ id: "i5", action_id: "opt_1", value: "", user_id: HUMAN_ID }] };
    },
  };
  const result = await runKeylessTool(
    "ask_human",
    { chat_id: CHAT_ID, to: "dan", question: "Pineapple on pizza?", options: ["Yes", "No"] },
    { rest, bearerToken: "tok", maxTotalMsOverride: 20 }
  );
  const actionsBlock = postedBlocks.find((b) => b.type === "actions");
  assert.equal(actionsBlock.elements.length, 2);
  assert.deepEqual(actionsBlock.elements[0].restricted_to, [HUMAN_ID]);
  assert.equal(result.answer, "No", "opt_1 maps to the second option, 'No'");
  assert.equal(typeof result.ask_id, "string");
});

test("ask_human ignores a card_interaction whose action_id isn't one of this ask's own option buttons", async () => {
  const rest = {
    async getChat() {
      return { session: { users: [{ id: HUMAN_ID, username: "dan" }] } };
    },
    async postCard() {
      return { resource_id: CARD_ID };
    },
    async getCard() {
      // A real interaction landed on this card, but its action_id isn't
      // one of THIS ask's opt_0.. buttons -- must not be mistaken for the
      // answer.
      return { interactions: [{ id: 1, action_id: "some_unrelated_action" }] };
    },
  };
  const result = await runKeylessTool(
    "ask_human",
    { chat_id: CHAT_ID, to: "dan", question: "Q?", options: ["A", "B"] },
    { rest, bearerToken: "tok", maxTotalMsOverride: 15, minEmptyPollMsOverride: 2 }
  );
  assert.equal(result.status, "pending");
  assert.equal(result.answer, undefined);
});

test("two concurrent asks for one agent each get their OWN answer -- the shared-outbox-cursor bug this fixes", async () => {
  // Before this fix, ask_human/get_ask_result drained the shared
  // socket-mode outbox (GET /api/v1/agent/updates), which has exactly ONE
  // forward-only cursor per agent -- so two asks running at once for the
  // same agent, filtering by card_id only to decide what to RETURN, could
  // each advance the other's cursor past its own answer and strand it.
  // Polling by card id means each ask reads only ITS OWN card, and this
  // test proves that by wiring the fake API to serve two distinct cards
  // whose answers would be wrong if either ask read the other's.
  const cardForQuestion = { "Pizza?": CARD_ID, "Color?": CARD_ID_2 };
  const interactionsByCard = {
    [CARD_ID]: [{ id: "i1", action_id: "opt_1" }], // "No"
    [CARD_ID_2]: [{ id: "i2", action_id: "opt_0" }], // "Red"
  };
  const rest = {
    async getChat() {
      return { session: { users: [{ id: HUMAN_ID, username: "dan" }] } };
    },
    async postCard(token, chatId, blocks, text) {
      const cardId = cardForQuestion[text];
      assert.ok(cardId, `unexpected question text: ${text}`);
      return { resource_id: cardId };
    },
    async getCard(token, cardId) {
      return { interactions: interactionsByCard[cardId] };
    },
  };
  const [pizza, color] = await Promise.all([
    runKeylessTool(
      "ask_human",
      { chat_id: CHAT_ID, to: "dan", question: "Pizza?", options: ["Yes", "No"] },
      { rest, bearerToken: "tok", maxTotalMsOverride: 20 }
    ),
    runKeylessTool(
      "ask_human",
      { chat_id: CHAT_ID, to: "dan", question: "Color?", options: ["Red", "Blue"] },
      { rest, bearerToken: "tok", maxTotalMsOverride: 20 }
    ),
  ]);
  assert.equal(pizza.answer, "No", "the pizza ask must resolve from CARD_ID, never CARD_ID_2");
  assert.equal(color.answer, "Red", "the color ask must resolve from CARD_ID_2, never CARD_ID");
});

test("ask_human returns {status: 'pending', ask_id} when nobody has answered within its time budget", async () => {
  const rest = {
    async getChat() {
      return { session: { users: [{ id: HUMAN_ID, username: "dan" }] } };
    },
    async postCard() {
      return { resource_id: CARD_ID };
    },
    async getCard() {
      return { interactions: [] };
    },
  };
  const result = await runKeylessTool(
    "ask_human",
    { chat_id: CHAT_ID, to: "dan", question: "Q?", options: ["A", "B"] },
    { rest, bearerToken: "tok", maxTotalMsOverride: 10, minEmptyPollMsOverride: 2 }
  );
  assert.deepEqual(Object.keys(result).sort(), ["ask_id", "status"]);
  assert.equal(result.status, "pending");
});

test("ask_human's polling budget cannot be set from tool arguments -- only from the internal options object", async () => {
  // Passing `_maxTotalMs` (or any name) inside `args` must be a no-op: it
  // is not in ask_human's inputSchema and nothing reads it off `input`.
  // This proves the fix, not just the absence of the old field: with NO
  // maxTotalMsOverride at all, the real ~50s production budget is what's
  // in effect, so a mock that answers on the FIRST poll still resolves
  // immediately (the loop simply never needs a second iteration) -- but a
  // wire-supplied override asking for an instant timeout is ignored.
  let pollCount = 0;
  const rest = {
    async getChat() {
      return { session: { users: [{ id: HUMAN_ID, username: "dan" }] } };
    },
    async postCard() {
      return { resource_id: CARD_ID };
    },
    async getCard() {
      pollCount += 1;
      // Answers on the very first poll -- so this resolves fast
      // regardless of the (huge, real) production budget, proving the
      // request-shaped `_maxTotalMs` argument below did nothing rather
      // than shrinking the budget to something suspiciously small.
      return { interactions: [{ id: 1, action_id: "opt_0" }] };
    },
  };
  const result = await runKeylessTool(
    "ask_human",
    { chat_id: CHAT_ID, to: "dan", question: "Q?", options: ["A", "B"], _maxTotalMs: 999999999 },
    { rest, bearerToken: "tok" } // no maxTotalMsOverride -- the real ~50s cap applies
  );
  assert.equal(result.answer, "A");
  assert.equal(pollCount, 1);
});

test("ask_human refuses a `to` handle that isn't a member of the chat", async () => {
  const rest = { async getChat() { return { session: { users: [{ id: RECEIVER_ID, username: "someoneelse" }] } }; } };
  await assert.rejects(
    () => runKeylessTool("ask_human", { chat_id: CHAT_ID, to: "dan", question: "Q?", options: ["A", "B"] }, { rest, bearerToken: "tok" }),
    /dan isn't in this chat/
  );
});

test("ask_human requires 2..5 options", async () => {
  const rest = { async getChat() { return { session: { users: [{ id: HUMAN_ID, username: "dan" }] } }; } };
  await assert.rejects(
    () => runKeylessTool("ask_human", { chat_id: CHAT_ID, to: "dan", question: "Q?", options: ["only one"] }, { rest, bearerToken: "tok" }),
    /2\.\.5 choices/
  );
});

test("get_ask_result resumes from a pending ask_id and resolves once the tap lands", async () => {
  const pendingAsk = await runKeylessTool(
    "ask_human",
    { chat_id: CHAT_ID, to: "dan", question: "Q?", options: ["Yes", "No"] },
    {
      rest: {
        async getChat() {
          return { session: { users: [{ id: HUMAN_ID, username: "dan" }] } };
        },
        async postCard() {
          return { resource_id: CARD_ID };
        },
        async getCard() {
          // A stray, non-matching interaction (not one of this ask's own
          // option buttons) -- proves the cursor advances past it even
          // though it isn't the answer, and that get_ask_result resumes
          // from exactly that point rather than from the beginning.
          return { interactions: [{ id: "stray-3", action_id: "not_an_option" }] };
        },
      },
      bearerToken: "tok",
      maxTotalMsOverride: 5,
      minEmptyPollMsOverride: 2,
    }
  );
  assert.equal(pendingAsk.status, "pending");

  const rest = {
    async getCard(token, cardId, { after }) {
      assert.equal(cardId, CARD_ID);
      assert.equal(after, "stray-3", "get_ask_result resumes from the newest interaction id the pending ask already saw");
      return { interactions: [{ id: "tap-4", action_id: "opt_0" }] };
    },
  };
  const resolved = await runKeylessTool("get_ask_result", { ask_id: pendingAsk.ask_id }, { rest, bearerToken: "tok" });
  assert.equal(resolved.answer, "Yes");
});

test("get_ask_result refuses a malformed ask_id", async () => {
  await assert.rejects(() => runKeylessTool("get_ask_result", { ask_id: "not-base64-json" }, { rest: {}, bearerToken: "tok" }), /isn't valid or has expired/);
});

test("get_ask_result still resolves even with a corrupt or unrecognised `after` cursor in its ask_id", async () => {
  // Simulates a stale/foreign ask_id whose `after` isn't a real
  // interaction id on this card (e.g. carried over from a different
  // scheme, or hand-crafted) -- salt-api's route fails OPEN on an
  // unrecognised `after` (the full list, never a 500), and this client
  // forwards whatever `after` it's given as-is, never validating it
  // itself.
  const askId = Buffer.from(
    JSON.stringify({ cardId: CARD_ID, actionMap: { opt_0: "Yes", opt_1: "No" }, after: "not-a-real-interaction-id" }),
    "utf8"
  ).toString("base64url");
  const rest = {
    async getCard(token, cardId, { after }) {
      assert.equal(cardId, CARD_ID);
      assert.equal(after, "not-a-real-interaction-id", "the corrupt cursor is forwarded as-is, never validated client-side");
      return { interactions: [{ id: "tap-1", action_id: "opt_1" }] };
    },
  };
  const result = await runKeylessTool("get_ask_result", { ask_id: askId }, { rest, bearerToken: "tok" });
  assert.equal(result.answer, "No");
});

test("a pay-tap answer carries transfer_request_id and its live transfer_request_status", async () => {
  const askId = Buffer.from(JSON.stringify({ cardId: CARD_ID, actionMap: { opt_0: "Pay now" }, after: null }), "utf8").toString("base64url");
  const rest = {
    async getCard() {
      return {
        interactions: [
          { id: "tap-9", action_id: "opt_0", transfer_request_id: REQUEST_ID, transfer_request_status: "Pending" },
        ],
      };
    },
  };
  const result = await runKeylessTool("get_ask_result", { ask_id: askId }, { rest, bearerToken: "tok" });
  assert.equal(result.answer, "Pay now");
  assert.equal(result.transfer_request_id, REQUEST_ID);
  assert.equal(result.transfer_request_status, "Pending");
});

test("get_ask_result's polling budget also cannot be set from tool arguments", async () => {
  const pendingAsk = await runKeylessTool(
    "ask_human",
    { chat_id: CHAT_ID, to: "dan", question: "Q?", options: ["Yes", "No"] },
    {
      rest: {
        async getChat() { return { session: { users: [{ id: HUMAN_ID, username: "dan" }] } }; },
        async postCard() { return { resource_id: CARD_ID }; },
        async getCard() { return { interactions: [] }; },
      },
      bearerToken: "tok",
      maxTotalMsOverride: 5,
      minEmptyPollMsOverride: 2,
    }
  );
  let pollCount = 0;
  const rest = {
    async getCard() {
      pollCount += 1;
      return { interactions: [{ id: 2, action_id: "opt_1" }] };
    },
  };
  const result = await runKeylessTool("get_ask_result", { ask_id: pendingAsk.ask_id, _maxTotalMs: 999999999 }, { rest, bearerToken: "tok" });
  assert.equal(result.answer, "No");
  assert.equal(pollCount, 1);
});

test("neither ask_human nor get_ask_result ever calls the old socket-mode outbox endpoint", async () => {
  const calls = [];
  const rest = {
    async getChat() {
      return { session: { users: [{ id: HUMAN_ID, username: "dan" }] } };
    },
    async postCard() {
      return { resource_id: CARD_ID };
    },
    async getCard(token, cardId, opts) {
      calls.push({ method: "getCard", cardId, opts });
      return { interactions: [{ id: 1, action_id: "opt_0" }] };
    },
    async agentUpdates() {
      calls.push({ method: "agentUpdates" });
      throw new Error("agentUpdates must never be called by ask_human/get_ask_result any more");
    },
  };
  const result = await runKeylessTool(
    "ask_human",
    { chat_id: CHAT_ID, to: "dan", question: "Q?", options: ["A", "B"] },
    { rest, bearerToken: "tok", maxTotalMsOverride: 20 }
  );
  assert.equal(result.answer, "A");
  const askId = Buffer.from(JSON.stringify({ cardId: CARD_ID, actionMap: { opt_0: "A" }, after: null }), "utf8").toString("base64url");
  await runKeylessTool("get_ask_result", { ask_id: askId }, { rest, bearerToken: "tok" });
  assert.ok(calls.every((c) => c.method === "getCard"), `expected only getCard calls, got: ${JSON.stringify(calls.map((c) => c.method))}`);
});

// --- pollForCardInteraction: signal/abort and budget -----------------------

test("pollForCardInteraction stops within its wall-clock budget when nothing ever matches", async () => {
  let calls = 0;
  const rest = { async getCard() { calls += 1; return { interactions: [] }; } };
  const result = await pollForCardInteraction(rest, "tok", { cardId: CARD_ID, maxTotalMs: 15, minEmptyPollMs: 2 });
  assert.equal(result.found, false);
  assert.ok(calls >= 1);
});

test("pollForCardInteraction stops immediately when its AbortSignal is already aborted", async () => {
  let calls = 0;
  const rest = { async getCard() { calls += 1; return { interactions: [] }; } };
  const controller = new AbortController();
  controller.abort();
  const result = await pollForCardInteraction(rest, "tok", { cardId: CARD_ID, maxTotalMs: 50_000, signal: controller.signal });
  assert.equal(result.found, false);
  assert.equal(calls, 0, "an already-aborted signal must skip calling salt-api at all");
});

test("pollForCardInteraction stops after the signal aborts mid-poll, without waiting out the full budget", async () => {
  let calls = 0;
  const controller = new AbortController();
  const rest = {
    async getCard() {
      calls += 1;
      if (calls === 1) controller.abort(); // simulates the client disconnecting after the first round-trip
      return { interactions: [] };
    },
  };
  const result = await pollForCardInteraction(rest, "tok", { cardId: CARD_ID, maxTotalMs: 50_000, signal: controller.signal });
  assert.equal(result.found, false);
  assert.equal(calls, 1, "the loop must not run a second round after the signal aborts");
});

// --- pacing floor + Retry-After (2026-09-19 availability review, N2) ------

test("an empty poll that returns instantly is still followed by at least minEmptyPollMs before the next round -- salt-api's own pacing is never the only guard", async () => {
  const calls = [];
  const rest = {
    async getCard() {
      calls.push(Date.now());
      return { interactions: [] }; // answers instantly, no interactions at all
    },
  };
  const start = Date.now();
  await pollForCardInteraction(rest, "tok", { cardId: CARD_ID, maxTotalMs: 60, minEmptyPollMs: 25 });
  assert.ok(calls.length >= 2, "the loop ran more than one round within the budget");
  for (let i = 1; i < calls.length; i++) {
    assert.ok(calls[i] - calls[i - 1] >= 25, `round ${i} started only ${calls[i] - calls[i - 1]}ms after the previous one`);
  }
  assert.ok(Date.now() - start >= 25);
});

test("a poll that returns REAL interactions (even non-matching ones) is not held back by the empty-poll floor", async () => {
  let calls = 0;
  const rest = {
    async getCard() {
      calls += 1;
      // Not empty -- there IS an interaction, it just never matches.
      return { interactions: [{ id: calls, action_id: "opt_0" }] };
    },
  };
  const start = Date.now();
  const result = await pollForCardInteraction(rest, "tok", { cardId: CARD_ID, maxTotalMs: 40, minEmptyPollMs: 5_000, matches: () => false });
  assert.equal(result.found, false);
  assert.ok(calls >= 3, `expected several fast rounds within the 40ms budget, got ${calls}`);
  assert.ok(Date.now() - start < 5_000, "a 5s empty-poll floor must never apply when the response wasn't actually empty");
});

test("a 429 from getCard is retried after Retry-After, not treated as fatal and not retried immediately", async () => {
  const calls = [];
  const rest = {
    async getCard() {
      calls.push(Date.now());
      if (calls.length === 1) {
        throw new SaltBearerApiError("GET", "/api/v1/cards/x", 429, { error: "slow down" }, 1); // retryAfterSeconds: 1
      }
      return { interactions: [{ id: 9, action_id: "opt_0" }] };
    },
  };
  const result = await pollForCardInteraction(rest, "tok", { cardId: CARD_ID, maxTotalMs: 5_000 });
  assert.equal(result.found, true);
  assert.equal(calls.length, 2);
  assert.ok(calls[1] - calls[0] >= 900, `expected roughly a 1s (retryAfterSeconds=1) wait before retrying, got ${calls[1] - calls[0]}ms`);
});

test("a 429 with no Retry-After still backs off (defaults to 1s) rather than retrying immediately", async () => {
  const calls = [];
  const rest = {
    async getCard() {
      calls.push(Date.now());
      if (calls.length === 1) throw new SaltBearerApiError("GET", "/api/v1/cards/x", 429, { error: "slow down" }, undefined);
      // Resolves on the second call so the loop ends there -- this test
      // is only about the SPACING before that call, not about how many
      // more empty rounds would otherwise follow.
      return { interactions: [{ id: 1, action_id: "opt_0" }] };
    },
  };
  const result = await pollForCardInteraction(rest, "tok", { cardId: CARD_ID, maxTotalMs: 5_000 });
  assert.equal(result.found, true);
  assert.equal(calls.length, 2);
  assert.ok(calls[1] - calls[0] >= 900, `expected roughly a 1s default backoff, got ${calls[1] - calls[0]}ms`);
});

test("an aborted signal cuts a Retry-After wait short instead of waiting it out", async () => {
  const controller = new AbortController();
  let calls = 0;
  const rest = {
    async getCard() {
      calls += 1;
      if (calls === 1) {
        setTimeout(() => controller.abort(), 5);
        throw new SaltBearerApiError("GET", "/api/v1/cards/x", 429, {}, 30); // a 30s Retry-After
      }
      return { interactions: [] };
    },
  };
  const start = Date.now();
  const result = await pollForCardInteraction(rest, "tok", { cardId: CARD_ID, maxTotalMs: 60_000, signal: controller.signal });
  assert.equal(result.found, false);
  assert.ok(Date.now() - start < 1_000, "the abort must cut the 30s Retry-After wait short, not wait it out");
  assert.equal(calls, 1, "the loop must not retry after the signal aborts, even mid-backoff");
});

test("searchContacts sends username= with the leading @ stripped, so it works against an API without q", async () => {
  const { createSaltBearerClient } = await import("../src/salt-bearer-client.mjs");
  let seenUrl;
  const client = createSaltBearerClient({
    host: "https://salt.test",
    fetchImpl: async (url) => {
      seenUrl = url;
      return { ok: true, status: 200, text: async () => JSON.stringify([{ id: RECEIVER_ID, username: "ada" }]) };
    },
  });
  const result = await client.searchContacts("tok", "@ada");
  assert.equal(seenUrl, "https://salt.test/api/v1/search/contacts?username=ada");
  assert.equal(result[0].username, "ada");
});
