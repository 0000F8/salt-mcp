// Guards the thing the Claude and ChatGPT app directories both require:
// every tool salt-mcp exposes over MCP must carry annotations (title +
// readOnlyHint/destructiveHint/idempotentHint/openWorldHint). This test
// builds the REAL action catalog straight from the installed salt-agent-sdk
// (not a hand-copied list), so a new SDK action fails this test the moment
// it lands here, before anyone ships it unannotated.
//
// Extended for the K5 OAuth lane's keyless toolset (src/keyless-tools.mjs)
// below -- those tools are NOT salt-agent-sdk actions (see that module's
// header comment for why they live in a separate map), so they get their
// own lightweight annotation-coverage check here rather than being folded
// into TOOL_ANNOTATIONS itself. Deeper behavioral coverage for them lives
// in tests/keyless-tools.test.mjs.

import { test } from "node:test";
import assert from "node:assert/strict";
import pkg from "salt-agent-sdk";
import { TOOL_ANNOTATIONS, annotationsFor, toMcpTools } from "../src/annotations.mjs";
import { HOSTED_TOOLS } from "../src/http.mjs";
import { KEYLESS_TOOLS, toKeylessMcpTools } from "../src/keyless-tools.mjs";

const { createSaltClient, createIdentityStore, createActions } = pkg;

// A dummy client/identity store is fine here: building the action
// definitions list never calls the client, it only wires up closures that
// would call it if executed. We never call actions.execute() in this file.
function buildDefinitions() {
  const client = createSaltClient({ host: "https://example.invalid" });
  const actions = createActions({
    client,
    identities: createIdentityStore(),
    pgpPassphrase: "unused-in-tests",
    publicWebhookUrl: "https://example.invalid/",
    walletMasterKey: "unused-in-tests", // include wallet/agent-creation actions in the catalog too
  });
  return actions.definitions;
}

const HINT_FIELDS = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"];

test("every live salt-agent-sdk action has a registered annotation", () => {
  const definitions = buildDefinitions();
  assert.ok(definitions.length > 0, "expected salt-agent-sdk to expose at least one action");

  const missing = [];
  for (const def of definitions) {
    if (!TOOL_ANNOTATIONS[def.name]) missing.push(def.name);
  }
  assert.deepEqual(
    missing,
    [],
    `Tool(s) missing from TOOL_ANNOTATIONS in src/annotations.mjs: ${missing.join(", ")}. ` +
      "Add title/readOnlyHint/destructiveHint/idempotentHint/openWorldHint for each before exposing it."
  );
});

test("no stale annotation entries for tools the SDK no longer defines", () => {
  const definitions = buildDefinitions();
  const liveNames = new Set(definitions.map((d) => d.name));
  const stale = Object.keys(TOOL_ANNOTATIONS).filter((name) => !liveNames.has(name));
  assert.deepEqual(stale, [], `Annotated tool(s) no longer in the SDK's action catalog: ${stale.join(", ")}`);
});

test("every annotation entry has a title and all four boolean hints", () => {
  for (const [name, annotation] of Object.entries(TOOL_ANNOTATIONS)) {
    assert.equal(typeof annotation.title, "string", `${name}.title must be a string`);
    assert.ok(annotation.title.length > 0, `${name}.title must not be empty`);
    for (const field of HINT_FIELDS) {
      assert.equal(typeof annotation[field], "boolean", `${name}.${field} must be a boolean`);
    }
  }
});

test("annotationsFor() throws for an unknown tool name instead of silently returning nothing", () => {
  assert.throws(() => annotationsFor("not_a_real_tool"), /No tool annotations registered/);
});

test("toMcpTools() attaches annotations to every tool, alongside name/description/inputSchema", () => {
  const definitions = buildDefinitions();
  const tools = toMcpTools(definitions);
  assert.equal(tools.length, definitions.length);
  for (const tool of tools) {
    assert.equal(typeof tool.name, "string");
    assert.equal(typeof tool.description, "string");
    assert.equal(typeof tool.inputSchema, "object");
    assert.ok(tool.annotations, `${tool.name} is missing annotations`);
    for (const field of HINT_FIELDS) {
      assert.equal(typeof tool.annotations[field], "boolean", `${tool.name}.annotations.${field}`);
    }
  }
});

test("read/list tools are annotated read-only; money and message tools are not", () => {
  // A cross-check against ground truth, not just internal self-consistency:
  // these specific tools MUST be read-only, and these specific ones (which
  // send a message, move money, or hand off) MUST NOT be marked read-only.
  const mustBeReadOnly = ["list_salt_agents", "list_products"];
  const mustNotBeReadOnly = [
    "create_salt_agent",
    "delegate_to_agent",
    "consult_agent",
    "post_card",
    "update_card",
    "create_product",
    "offer_product",
    "send_invoice",
    "add_usage",
    "create_wallet",
    "hand_off_to_agent",
    "hand_back_to_concierge",
    "offer_handoff_choices",
  ];
  for (const name of mustBeReadOnly) {
    assert.equal(annotationsFor(name).readOnlyHint, true, `${name} should be readOnlyHint: true`);
  }
  for (const name of mustNotBeReadOnly) {
    assert.equal(annotationsFor(name).readOnlyHint, false, `${name} should be readOnlyHint: false`);
    assert.equal(annotationsFor(name).destructiveHint, true, `${name} should be destructiveHint: true`);
  }
});

test("the hosted HTTP server only exposes api-key-only, chat-free tools, and they're all annotated", () => {
  const definitions = buildDefinitions();
  const liveNames = new Set(definitions.map((d) => d.name));
  assert.ok(HOSTED_TOOLS.size > 0);
  for (const name of HOSTED_TOOLS) {
    assert.ok(liveNames.has(name), `HOSTED_TOOLS names a tool the SDK doesn't define: ${name}`);
    assert.ok(TOOL_ANNOTATIONS[name], `hosted tool "${name}" has no annotation entry`);
  }
});

// --- keyless (OAuth) toolset: same coverage bar, own map ------------------

test("every keyless tool (K5 OAuth toolset) carries a title and all four MCP annotation hints", () => {
  assert.ok(KEYLESS_TOOLS.length > 0);
  for (const tool of KEYLESS_TOOLS) {
    assert.equal(typeof tool.title, "string");
    assert.ok(tool.title.length > 0, `${tool.name} needs a title`);
    for (const field of HINT_FIELDS) {
      assert.equal(typeof tool.annotations[field], "boolean", `${tool.name}.${field}`);
    }
  }
});

test("toKeylessMcpTools() attaches annotations to every keyless tool, alongside name/description/inputSchema", () => {
  const tools = toKeylessMcpTools();
  assert.equal(tools.length, KEYLESS_TOOLS.length);
  for (const tool of tools) {
    assert.equal(typeof tool.name, "string");
    assert.equal(typeof tool.description, "string");
    assert.equal(typeof tool.inputSchema, "object");
    assert.ok(tool.annotations, `${tool.name} is missing annotations`);
    for (const field of HINT_FIELDS) {
      assert.equal(typeof tool.annotations[field], "boolean", `${tool.name}.annotations.${field}`);
    }
  }
});

test("no keyless tool name collides with a legacy HOSTED_TOOLS name of a different shape", () => {
  // list_salt_agents/list_products/create_product legitimately exist in
  // BOTH catalogs (same name, different backing implementation per auth
  // path -- see src/http.mjs) -- that overlap is intentional. This just
  // guards that the keyless catalog didn't accidentally drop one of them.
  for (const name of HOSTED_TOOLS) {
    assert.ok(KEYLESS_TOOLS.some((t) => t.name === name), `keyless toolset dropped ${name}, which HOSTED_TOOLS still expects to exist`);
  }
});
