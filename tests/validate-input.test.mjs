// Unit tests for src/validate-input.mjs -- the ajv-based inputSchema
// validation src/http.mjs now runs before executing any keyless tool
// (the low-level @modelcontextprotocol/sdk Server does not do this
// itself; a 2026-09-18 security review flagged that gap directly).

import { test } from "node:test";
import assert from "node:assert/strict";
import { validateAgainstSchema } from "../src/validate-input.mjs";

const SCHEMA = {
  type: "object",
  properties: {
    chat_id: { type: "string" },
    amount: { type: "string" },
  },
  required: ["chat_id", "amount"],
};

test("valid data against a schema returns {valid: true}", () => {
  assert.deepEqual(validateAgainstSchema(SCHEMA, { chat_id: "c1", amount: "1.00" }), { valid: true });
});

test("missing a required field is refused with a readable message naming the field", () => {
  const result = validateAgainstSchema(SCHEMA, { chat_id: "c1" });
  assert.equal(result.valid, false);
  assert.match(result.message, /amount/);
});

test("a wrong type is refused with a readable message", () => {
  const result = validateAgainstSchema(SCHEMA, { chat_id: "c1", amount: 5 });
  assert.equal(result.valid, false);
  assert.match(result.message, /amount/);
});

test("extra/unknown properties are allowed (schemas here are not `additionalProperties: false`)", () => {
  assert.deepEqual(validateAgainstSchema(SCHEMA, { chat_id: "c1", amount: "1.00", extra: "ignored" }), { valid: true });
});

test("a schema with no properties (e.g. list_chats' {}) accepts an empty object", () => {
  assert.deepEqual(validateAgainstSchema({ type: "object", properties: {} }, {}), { valid: true });
});

test("the same schema object is only compiled once (cached by identity) but still validates correctly across repeated calls", () => {
  const schema = { type: "object", properties: { x: { type: "number" } }, required: ["x"] };
  assert.deepEqual(validateAgainstSchema(schema, { x: 1 }), { valid: true });
  assert.equal(validateAgainstSchema(schema, { x: "not a number" }).valid, false);
  assert.deepEqual(validateAgainstSchema(schema, { x: 2 }), { valid: true });
});
