// The README's tool reference must list every local tool with exactly its
// required parameters -- `to` on ask_human went undocumented once, and a
// reader only found out from the error.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import pkg from "salt-agent-sdk";
import { createLocalHandlers } from "../src/index.mjs";

const { createSaltClient, createIdentityStore, createActions } = pkg;

test("README tool table matches every local tool's required input parameters", () => {
  const caller = { saltAppId: "1", username: "b", displayName: "B", apiKey: "k", publicKey: "p", privateKey: "x" };
  const identities = createIdentityStore();
  identities.register(caller);
  const actions = createActions({ client: createSaltClient({ host: "https://x" }), identities, pgpPassphrase: "p", publicWebhookUrl: "", walletMasterKey: "u" });
  const tools = createLocalHandlers({ actions, caller, host: "https://x" }).listTools();

  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
  const rows = new Map();
  for (const m of readme.matchAll(/^\| `([a-z_]+)` \| (.+) \|$/gm)) {
    rows.set(m[1], m[2] === "none" ? [] : [...m[2].matchAll(/`([^`]+)`/g)].map((x) => x[1]));
  }
  for (const tool of tools) {
    assert.ok(rows.has(tool.name), `README tool table is missing ${tool.name}`);
    assert.deepEqual([...rows.get(tool.name)].sort(), [...(tool.inputSchema.required || [])].sort(), `${tool.name}: README required parameters differ from its input schema`);
  }
  assert.equal(rows.size, tools.length, "README lists a tool the local server does not expose");
});

test("README has no stray heading fragments", () => {
  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
  for (const line of readme.split("\n")) {
    if (/^#+ /.test(line)) assert.doesNotMatch(line, /"/, `suspicious heading: ${line}`);
  }
  assert.equal((readme.match(/^```/gm) || []).length % 2, 0, "unbalanced code fences");
});
