#!/usr/bin/env node
// Salt MCP server.
//
// Exposes the salt-agent-sdk action layer (the SAME tools the first-party
// Claude agent runs -- list_salt_agents, create_product, send_invoice,
// create_wallet, create_salt_agent, ...) as Model Context Protocol tools, so
// any MCP client (Claude Desktop, an IDE, another agent framework) can
// discover agents and transact on the Salt network without writing a line of
// Salt-specific integration code.
//
// It is a THIN adapter: the tool catalog and their behavior come entirely
// from `createActions(...).definitions` / `.execute(...)`, so it stays in
// lockstep with the SDK -- a new SDK action shows up here automatically.
//
// Auth is one Salt agent identity, from env (same vars as any Salt agent):
//   HOST, SALT_API_KEY, SALT_APP_ID, APP_PUBLIC_KEY, APP_PRIVATE_KEY,
//   PGP_PASSPHRASE  (+ optional WALLET_MASTER_KEY, CONCIERGE_AGENT_ID).
// Every tool call acts AS that agent.

import { readFileSync } from "node:fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import pkg from "salt-agent-sdk";
import { toMcpTools } from "./annotations.mjs";

const {
  loadSaltAgentConfig,
  validateSaltAgentConfig,
  createSaltClient,
  createIdentityStore,
  createActions,
} = pkg;

// Read straight from package.json rather than hardcoding, so a version bump
// there (the coordinator's job, per this repo's HANDOFF.md convention) is
// the only place that needs to change. A plain file read, so it's safe at
// module scope even when this file is only imported (e.g. by a test) rather
// than run as the server.
const { version: PACKAGE_VERSION } = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8")
);

// stdio is the MCP channel, so anything on stdout that isn't a protocol
// message corrupts the stream -- all diagnostics go to stderr.
const log = (...args) => console.error("[salt-mcp]", ...args);

// Maps a loaded SaltAgentConfig to the options object createActions expects.
// Pulled out and exported (pure, no side effects) so
// tests/config-wiring.test.mjs can catch a config-field-name mismatch like
// the one this fixes: this line used to pass `globalAgentId:
// config.globalAgentId` into createActions, which only ever reads
// `conciergeAgentId` -- so hand_back_to_concierge's fallback destination was
// silently a no-op in every salt-mcp deployment, regardless of
// CONCIERGE_AGENT_ID/GLOBAL_AGENT_ID being set correctly in env.
export function buildActionsOptions(config, { client, identities }) {
  return {
    client,
    identities,
    pgpPassphrase: config.pgpPassphrase,
    publicWebhookUrl: config.publicWebhookUrl,
    walletMasterKey: config.walletMasterKey,
    conciergeAgentId: config.conciergeAgentId,
  };
}

// Everything below has real side effects (reads env, may process.exit,
// speaks MCP over stdio) so it only runs when this file is the process
// entry point -- never on import, e.g. from a test.
async function main() {
  const config = loadSaltAgentConfig();
  const missing = validateSaltAgentConfig(config);
  if (missing.length) {
    log(`Missing required env vars: ${missing.join(", ")}. See README.`);
    process.exit(1);
  }

  const client = createSaltClient({ host: config.host });

  // A single-identity store: this server always acts as the one agent its env
  // configures. create_salt_agent can still register spawned children here at
  // runtime (they'd share this process), mirroring the agent runtime.
  const identities = createIdentityStore();
  const caller = {
    saltAppId: config.saltAppId,
    username: config.saltUsername,
    displayName: config.saltDisplayName,
    apiKey: config.saltApiKey,
    publicKey: config.appPublicKey,
    privateKey: config.appPrivateKey,
  };
  identities.register(caller);

  const actions = createActions(buildActionsOptions(config, { client, identities }));

  const server = new Server(
    { name: "salt-mcp", version: PACKAGE_VERSION },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: toMcpTools(actions.definitions),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    try {
      // No chat context in an MCP session -- depth 0, mainChatId null. Actions
      // that require a live chat (delegate_to_agent, post_card, hand_off_*)
      // will report that clearly rather than misbehave.
      const result = await actions.execute(name, args ?? {}, caller, { depth: 0, mainChatId: null });
      const text = typeof result === "string" ? result : JSON.stringify(result, null, 2);
      return { content: [{ type: "text", text }] };
    } catch (err) {
      return {
        content: [{ type: "text", text: `Salt tool "${name}" failed: ${err?.message || err}` }],
        isError: true,
      };
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
  log(`ready as agent #${config.saltAppId} (${config.host}); ${actions.definitions.length} tools exposed`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
