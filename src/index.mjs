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
import { createApiKeyRequest, toRoomMcpTools, runRoomTool, ROOM_TOOL_NAMES } from "./room-tools.mjs";
import { LOCAL_TOOL_NAMES, toLocalMcpTools, createLocalRest, runLocalTool } from "./local-tools.mjs";
import { createDecryptor } from "./local-decrypt.mjs";
import { checkCredentials } from "./startup-check.mjs";

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

const PLAIN_ID_RE = /^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9]+)$/;

// post_card is an SDK action that posts into the CURRENT chat of a reply
// (`ctx.mainChatId`) -- there is no safety reason behind that, an MCP session
// just has no current chat. Here the caller names the chat instead: `chat_id`
// (from open_chat) becomes that context for this one call, still posting as
// this agent through its own api key.
function withChatIdForPostCard(tool) {
  return {
    ...tool,
    description:
      tool.description.replace("into the CURRENT chat", "into the chat named by `chat_id`") +
      " In this local server, pass `chat_id` (from open_chat).",
    inputSchema: {
      ...tool.inputSchema,
      properties: { ...tool.inputSchema.properties, chat_id: { type: "string", description: "The chat to post into (from open_chat)." } },
    },
  };
}

/**
 * The local server's whole tool surface as two functions, so tests can drive
 * it without stdio. `decrypt` opens messages for salt_read_room (omit it and
 * ciphertext comes back untouched, as on the hosted server).
 */
export function createLocalHandlers({ actions, caller, host, decrypt, fetchImpl }) {
  const roomRequest = createApiKeyRequest({ host, apiKey: caller.apiKey, fetchImpl });
  const rest = createLocalRest({ host, fetchImpl });
  return {
    toolCount: actions.definitions.length + LOCAL_TOOL_NAMES.size + ROOM_TOOL_NAMES.size,
    listTools() {
      const sdkTools = toMcpTools(actions.definitions).map((t) => (t.name === "post_card" ? withChatIdForPostCard(t) : t));
      return [...sdkTools, ...toLocalMcpTools(), ...toRoomMcpTools({ decrypts: Boolean(decrypt) })];
    },
    async callTool(name, args = {}, extra = {}) {
      if (ROOM_TOOL_NAMES.has(name)) return runRoomTool(name, args, { request: roomRequest, decrypt });
      if (LOCAL_TOOL_NAMES.has(name)) return runLocalTool(name, args, { rest, apiKey: caller.apiKey, ...extra });
      // No chat context in an MCP session -- depth 0, mainChatId null. Actions
      // that require a live chat (delegate_to_agent, hand_off_*, ...) report
      // that clearly rather than misbehave; post_card takes it as `chat_id`.
      let mainChatId = null;
      if (name === "post_card") {
        const { chat_id: chatId, ...rest2 } = args;
        const id = typeof chatId === "string" ? chatId.trim() : "";
        if (!id) throw new Error("post_card needs a chat_id here -- open one with open_chat first.");
        if (!PLAIN_ID_RE.test(id)) throw new Error(`chat_id must be a plain Salt id (a uuid or an integer) -- refusing "${id.slice(0, 60)}".`);
        mainChatId = id;
        args = rest2;
      }
      return actions.execute(name, args, caller, { depth: 0, mainChatId });
    },
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

  // Fail on a bad api key here, not as a 401 on the first tool call. A network
  // failure only warns: an offline launch should still come up.
  const check = await checkCredentials({ host: config.host, apiKey: caller.apiKey, appId: config.saltAppId });
  if (check.status === "unauthorized") {
    log(`ERROR: ${check.message}`);
    process.exit(1);
  }
  if (check.status !== "ok" || check.mismatch) log(`WARNING: ${check.message}`);

  // Local mode holds this agent's private key, so salt_read_room can open
  // the encrypted messages it was a recipient of.
  const decrypt = caller.privateKey ? createDecryptor({ privateKey: caller.privateKey, passphrase: config.pgpPassphrase }) : undefined;
  const handlers = createLocalHandlers({ actions, caller, host: config.host, decrypt });

  const server = new Server(
    { name: "salt-mcp", version: PACKAGE_VERSION },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: handlers.listTools() }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    try {
      const result = await handlers.callTool(name, args ?? {});
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
  log(`ready as agent #${config.saltAppId} (${config.host}); ${handlers.toolCount} tools exposed${check.status === "ok" ? "" : " (credentials not verified)"}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
