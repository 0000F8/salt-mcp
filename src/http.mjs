#!/usr/bin/env node
// Salt MCP server -- HOSTED (Streamable HTTP) variant.
//
// Unlike src/index.mjs (local, stdio, one env-configured identity), this runs
// as a network service any remote MCP client can connect to. It is
// intentionally SCOPED to the api-key-only, chat-free tools -- discovery and
// product-catalog commerce -- so it NEVER needs, holds, or stores a caller's
// PGP private keys. The transactional/messaging tools (which need a live chat
// + the caller's private key to encrypt) stay in the local stdio server,
// where keys never leave the user's machine.
//
// AUTH IS PASS-THROUGH, NEVER STORED: each request presents its own Salt
// credentials as headers and they're used only for that request's tool call:
//   X-Salt-Api-Key: <the agent's api key>
//   X-Salt-App-Id:  <the agent's numeric Salt id>
//
// Env: HOST (Salt API base), PORT (default 5200).

import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import pkg from "salt-agent-sdk";

const { createSaltClient, createIdentityStore, createActions } = pkg;

const HOST = (process.env.HOST || "").replace(/\/$/, "");
const PORT = parseInt(process.env.PORT || "5200", 10);
if (!HOST) {
  console.error("[salt-mcp-http] HOST is required");
  process.exit(1);
}

// The api-key-only, chat-free tools this hosted endpoint exposes. Everything
// else the SDK offers (messaging, delegation, hand-off, cards, wallet/agent
// creation) needs a live chat and/or the caller's private key, so it is NOT
// served here -- see the local stdio server for those.
const HOSTED_TOOLS = new Set(["list_salt_agents", "list_products", "create_product"]);

// One shared client + action layer. The caller identity is supplied
// per-request (below); this store is just the empty scaffold createActions
// requires. No walletMasterKey/globalAgentId -> wallet/agent provisioning off.
const client = createSaltClient({ host: HOST });
const actions = createActions({
  client,
  identities: createIdentityStore(),
  pgpPassphrase: "unused-on-hosted",
  publicWebhookUrl: "",
});
const hostedDefinitions = actions.definitions.filter((d) => HOSTED_TOOLS.has(d.name));

// A per-request caller built ONLY from that request's headers. Empty PGP keys:
// the hosted tools never touch them, and we never want them here.
function callerFromHeaders(req) {
  const apiKey = req.get("X-Salt-Api-Key");
  const appId = req.get("X-Salt-App-Id");
  if (!apiKey || !appId) return null;
  return { saltAppId: parseInt(appId, 10), apiKey, publicKey: "", privateKey: "" };
}

function buildServer(caller) {
  const server = new Server({ name: "salt-mcp-hosted", version: "0.1.0" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: hostedDefinitions.map((d) => ({ name: d.name, description: d.description, inputSchema: d.schema })),
  }));
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    if (!HOSTED_TOOLS.has(name)) {
      return { content: [{ type: "text", text: `Tool "${name}" is not available on the hosted endpoint.` }], isError: true };
    }
    try {
      const result = await actions.execute(name, args ?? {}, caller, { depth: 0, mainChatId: null });
      const text = typeof result === "string" ? result : JSON.stringify(result, null, 2);
      return { content: [{ type: "text", text }] };
    } catch (err) {
      return { content: [{ type: "text", text: `Salt tool "${name}" failed: ${err?.message || err}` }], isError: true };
    }
  });
  return server;
}

const app = express();
app.use(express.json());

// Unauthenticated liveness probe for the ALB target group.
app.get("/health", (_req, res) => res.status(200).json({ status: "ok", tools: hostedDefinitions.length }));

// Stateless Streamable HTTP: each POST is an independent MCP request carrying
// its own credentials. A fresh server+transport per request keeps callers
// fully isolated -- no shared session state, nothing to leak between clients.
app.post("/mcp", async (req, res) => {
  const caller = callerFromHeaders(req);
  if (!caller) {
    return res.status(401).json({
      jsonrpc: "2.0",
      error: { code: -32001, message: "Missing X-Salt-Api-Key / X-Salt-App-Id headers" },
      id: null,
    });
  }
  const server = buildServer(caller);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => { transport.close(); server.close(); });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(PORT, () => {
  console.error(`[salt-mcp-http] listening on :${PORT} -> ${HOST}; ${hostedDefinitions.length} hosted tools`);
});
