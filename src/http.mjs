#!/usr/bin/env node
// Salt MCP server -- HOSTED (Streamable HTTP) variant.
//
// Unlike src/index.mjs (local, stdio, one env-configured identity), this runs
// as a network service any remote MCP client can connect to. It now speaks
// TWO different auth/identity models on the same /mcp endpoint:
//
// 1. LEGACY header auth (unchanged): X-Salt-Api-Key + X-Salt-App-Id name one
//    long-lived Salt agent identity per request, and the tool catalog is
//    HOSTED_TOOLS -- a small, api-key-only, chat-free slice of
//    salt-agent-sdk's action layer (list_salt_agents, list_products,
//    create_product). See callerFromHeaders/buildLegacyServer.
//
// 2. OAuth bearer auth (new, K5 contract -- see
//    design-fleet/runs/2026-09-17-distribution/LANES.md's "Remote MCP OAuth
//    contract"): an `Authorization: Bearer sat_...` token, minted by
//    salt-api acting as the OAuth 2.1 authorization server, names a
//    KEYLESS agent the connecting human owns. The tool catalog is
//    src/keyless-tools.mjs's KEYLESS_TOOLS. No PGP private key exists for
//    this identity anywhere, on this server or salt-api's -- see that
//    module's header comment.
//
// Legacy headers are checked FIRST; a request with neither valid legacy
// headers nor a bearer token gets the MCP-spec-conformant 401 (RFC 9728
// WWW-Authenticate, see src/oauth.mjs), which is also how a client first
// discovers the OAuth flow at all.
//
// AUTH IS PASS-THROUGH, NEVER STORED in either model: each request presents
// its own Salt credentials and they're used only for that request's tool
// call(s).
//
// Env: HOST (Salt API base), PORT (default 5200), MCP_RESOURCE_URL,
// MCP_ISSUER (OAuth config overrides, see src/oauth.mjs).

import { readFileSync } from "node:fs";
import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import pkg from "salt-agent-sdk";
import { toMcpTools } from "./annotations.mjs";
import { loadOAuthConfig, registerProtectedResourceRoutes, extractBearerToken, sendUnauthorized } from "./oauth.mjs";
import { createSaltBearerClient } from "./salt-bearer-client.mjs";
import { KEYLESS_TOOL_NAMES, toKeylessMcpTools, runKeylessTool } from "./keyless-tools.mjs";
import { CARD_UI_RESOURCE_URI, CARD_UI_MIME_TYPE, renderCardAppHtml } from "./card-ui.mjs";

const { createSaltClient, createIdentityStore, createActions } = pkg;

const { version: PACKAGE_VERSION } = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8")
);

// The api-key-only, chat-free tools the LEGACY header-auth path exposes.
// Everything else the SDK offers (messaging, delegation, hand-off, cards,
// wallet/agent creation) needs a live chat and/or the caller's private
// key, so it is NOT served here -- see src/index.mjs for those, and
// src/keyless-tools.mjs for the OAuth path's much larger keyless catalog.
// Exported (and re-checked in tests/annotations.test.mjs) so a change here
// is what a test diffs against, not a second hand-maintained list.
export const HOSTED_TOOLS = new Set(["list_salt_agents", "list_products", "create_product"]);

// A per-request caller built ONLY from that request's legacy headers. Empty
// PGP keys: the hosted tools never touch them, and we never want them
// here. Pure and side-effect-free, so tests import it directly.
export function callerFromHeaders(req) {
  const apiKey = req.get("X-Salt-Api-Key");
  const appId = req.get("X-Salt-App-Id");
  if (!apiKey || !appId) return null;
  // The header is the id, verbatim. parseInt made it NaN for every real
  // caller, so every hosted tool call ran under an identity that matched
  // nothing -- and nothing said so.
  return { saltAppId: appId, apiKey, publicKey: "", privateKey: "" };
}

/**
 * Builds the whole Express app (routes, both MCP identity paths) WITHOUT
 * starting a listener -- side-effect-free apart from constructing the
 * salt-agent-sdk action layer, so tests can build one against a mocked
 * `fetchImpl` and drive it with real HTTP on an ephemeral port instead of
 * stubbing Express itself.
 *
 * @param {{host?: string, fetchImpl?: typeof fetch, oauthConfig?: object}} options
 */
export function createApp({ host, fetchImpl, oauthConfig } = {}) {
  const HOST = (host ?? process.env.HOST ?? "").replace(/\/$/, "");
  if (!HOST) throw new Error("HOST is required");
  const config = oauthConfig ?? loadOAuthConfig();

  // --- legacy header-auth path: unchanged from the pre-OAuth server ------
  const legacyClient = createSaltClient({ host: HOST, fetchImpl });
  const legacyActions = createActions({
    client: legacyClient,
    identities: createIdentityStore(),
    pgpPassphrase: "unused-on-hosted",
    publicWebhookUrl: "",
  });
  const hostedDefinitions = legacyActions.definitions.filter((d) => HOSTED_TOOLS.has(d.name));

  function buildLegacyServer(caller) {
    const server = new Server({ name: "salt-mcp-hosted", version: PACKAGE_VERSION }, { capabilities: { tools: {} } });
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: toMcpTools(hostedDefinitions),
    }));
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      if (!HOSTED_TOOLS.has(name)) {
        return { content: [{ type: "text", text: `Tool "${name}" is not available on the hosted endpoint.` }], isError: true };
      }
      try {
        const result = await legacyActions.execute(name, args ?? {}, caller, { depth: 0, mainChatId: null });
        const text = typeof result === "string" ? result : JSON.stringify(result, null, 2);
        return { content: [{ type: "text", text }] };
      } catch (err) {
        return { content: [{ type: "text", text: `Salt tool "${name}" failed: ${err?.message || err}` }], isError: true };
      }
    });
    return server;
  }

  // --- OAuth bearer path: the keyless toolset -----------------------------
  const rest = createSaltBearerClient({ host: HOST, fetchImpl });

  function buildKeylessServer(bearerToken) {
    const server = new Server(
      { name: "salt-mcp-keyless", version: PACKAGE_VERSION },
      { capabilities: { tools: {}, resources: {} } }
    );
    server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: toKeylessMcpTools() }));
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      if (!KEYLESS_TOOL_NAMES.has(name)) {
        return { content: [{ type: "text", text: `Tool "${name}" is not available on this connection.` }], isError: true };
      }
      try {
        const result = await runKeylessTool(name, args, { rest, bearerToken });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }], structuredContent: result };
      } catch (err) {
        return { content: [{ type: "text", text: err?.message || String(err) }], isError: true };
      }
    });
    // The one MCP Apps UI resource every card-producing tool links to via
    // _meta.ui.resourceUri (see keyless-tools.mjs and card-ui.mjs). A host
    // without MCP Apps support simply never calls resources/read, and gets
    // the tool's ordinary text/structuredContent instead.
    server.setRequestHandler(ListResourcesRequestSchema, async () => ({
      resources: [{ uri: CARD_UI_RESOURCE_URI, name: "Salt Card", mimeType: CARD_UI_MIME_TYPE }],
    }));
    server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      if (request.params.uri !== CARD_UI_RESOURCE_URI) {
        throw new Error(`Unknown resource: ${request.params.uri}`);
      }
      return { contents: [{ uri: CARD_UI_RESOURCE_URI, mimeType: CARD_UI_MIME_TYPE, text: renderCardAppHtml() }] };
    });
    return server;
  }

  const app = express();
  app.use(express.json());

  // RFC 9728 discovery -- unauthenticated, both well-known paths.
  registerProtectedResourceRoutes(app, config);

  // Unauthenticated liveness probe for the ALB target group.
  app.get("/health", (_req, res) =>
    res.status(200).json({ status: "ok", tools: hostedDefinitions.length + toKeylessMcpTools().length })
  );

  // Stateless Streamable HTTP: each POST is an independent MCP request
  // carrying its own credentials. A fresh server+transport per request
  // keeps callers fully isolated -- no shared session state, nothing to
  // leak between clients.
  app.post("/mcp", async (req, res) => {
    const legacyCaller = callerFromHeaders(req);
    let server;
    if (legacyCaller) {
      server = buildLegacyServer(legacyCaller);
    } else {
      const bearerToken = extractBearerToken(req.get("Authorization"));
      if (!bearerToken) {
        return sendUnauthorized(res, config);
      }
      server = buildKeylessServer(bearerToken);
    }
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => { transport.close(); server.close(); });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  return app;
}

// Everything below has real side effects (reads env, may process.exit, opens
// a listening socket) so it only runs when this file is the process entry
// point -- never on import, e.g. from a test.
function main() {
  const HOST = (process.env.HOST || "").replace(/\/$/, "");
  const PORT = parseInt(process.env.PORT || "5200", 10);
  if (!HOST) {
    console.error("[salt-mcp-http] HOST is required");
    process.exit(1);
  }

  const app = createApp({ host: HOST });
  app.listen(PORT, () => {
    console.error(`[salt-mcp-http] listening on :${PORT} -> ${HOST}`);
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
