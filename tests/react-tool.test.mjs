// react_to_message on the local server: listed with truthful annotations and
// the owner's rule in its description, and a call goes through the SDK to
// POST /api/v1/messages/:id/reactions (mock server shaped like the real
// ReactionsController answer).
import { test } from "node:test";
import assert from "node:assert/strict";
import pkg from "salt-agent-sdk";
import { createLocalHandlers } from "../src/index.mjs";
import { TOOL_ANNOTATIONS } from "../src/annotations.mjs";

const { createSaltClient, createIdentityStore, createActions } = pkg;

function handlersWith(fetchImpl) {
  const caller = { saltAppId: "1", username: "b", displayName: "B", apiKey: "k", publicKey: "p", privateKey: "x" };
  const identities = createIdentityStore();
  identities.register(caller);
  const client = createSaltClient({ host: "https://x.test", fetchImpl });
  const actions = createActions({ client, identities, pgpPassphrase: "p", publicWebhookUrl: "", walletMasterKey: "u" });
  return createLocalHandlers({ actions, caller, host: "https://x.test", fetchImpl });
}

test("react_to_message is listed, annotated truthfully, and carries the owner's rule", () => {
  const tool = handlersWith(async () => ({})).listTools().find((t) => t.name === "react_to_message");
  assert.ok(tool);
  assert.match(tool.description, /relevantly complements the chat in a friendly way/);
  assert.match(tool.description, /never to every message/i);
  assert.deepEqual([...tool.inputSchema.required].sort(), ["emoji", "message_id"]);
  const a = TOOL_ANNOTATIONS.react_to_message;
  assert.equal(a.readOnlyHint, false);
  assert.equal(a.destructiveHint, false);
  assert.equal(a.idempotentHint, false, "a toggle is not idempotent");
});

test("calling react_to_message posts the emoji and returns the server's summary", async () => {
  const calls = [];
  const fetchImpl = async (url, opts) => {
    calls.push({ url, method: opts?.method, body: opts?.body ? JSON.parse(opts.body) : undefined });
    if (url.endsWith("/reactions")) {
      const body = { message_id: "m-7", reactions: [{ emoji: "✅", count: 1, user_ids: ["1"] }] };
      return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) };
    }
    return { ok: true, status: 200, json: async () => ({}), text: async () => "{}" };
  };
  const out = await handlersWith(fetchImpl).callTool("react_to_message", { message_id: "m-7", emoji: "✅" });
  assert.equal(out.ok, true);
  assert.deepEqual(out.reactions, [{ emoji: "✅", count: 1, user_ids: ["1"] }]);
  const call = calls.find((c) => c.url.endsWith("/reactions"));
  assert.equal(call.url, "https://x.test/api/v1/messages/m-7/reactions");
  assert.equal(call.method, "POST");
  assert.deepEqual(call.body, { emoji: "✅" });
});
