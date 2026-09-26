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
// AVAILABILITY (2026-09-19 review, N2): every request to /mcp is rate
// limited per caller IP BEFORE any auth-specific work happens (including
// token validation itself), and every outbound call this server makes to
// salt-api -- legacy or keyless -- carries this task's edge secret and
// the real caller's IP, relayed the same way CloudFront's own viewer-IP
// headers work. See src/rate-limiter.mjs and src/edge-headers.mjs.
//
// Env: HOST (Salt API base), PORT (default 5200), MCP_RESOURCE_URL,
// MCP_ISSUER (OAuth config overrides, see src/oauth.mjs), EDGE_SECRET
// (see src/edge-headers.mjs; unset in local dev).

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
import { loadOAuthConfig, registerProtectedResourceRoutes, extractBearerToken, sendUnauthorized, sendInvalidToken } from "./oauth.mjs";
import { createSaltBearerClient } from "./salt-bearer-client.mjs";
import { KEYLESS_TOOLS, toKeylessMcpTools, runKeylessTool } from "./keyless-tools.mjs";
import { CARD_UI_RESOURCE_URI, CARD_UI_MIME_TYPE, renderCardAppHtml } from "./card-ui.mjs";
import { createTokenValidator } from "./token-validator.mjs";
import { validateAgainstSchema } from "./validate-input.mjs";
import { createRateLimiter } from "./rate-limiter.mjs";
import { buildEdgeHeaders, withEdgeHeaders } from "./edge-headers.mjs";
import { callerIpFromRequest } from "./caller-ip.mjs";

// Every access token this resource server issues starts with `sat_` (the
// K5 contract's own naming). A bearer that doesn't -- most dangerously, a
// JWT, since one might genuinely be a valid credential for some OTHER
// service -- is refused before this server so much as looks at it: never
// forwarded to salt-api, never treated as a candidate. A 2026-09-18
// security review found the pre-fix code forwarding a JWT-shaped bearer
// straight through unchanged.
const ACCESS_TOKEN_PREFIX = "sat_";

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
 * @param {{
 *   host?: string, fetchImpl?: typeof fetch, oauthConfig?: object,
 *   env?: NodeJS.ProcessEnv,
 *   rateLimiter?: {check: (ip: string) => {allowed: boolean, retryAfterSeconds?: number}},
 *   rateLimitOptions?: {limit?: number, windowMs?: number, now?: () => number},
 * }} options
 */
export function createApp({ host, fetchImpl, oauthConfig, env, rateLimiter, rateLimitOptions } = {}) {
  const HOST = (host ?? process.env.HOST ?? "").replace(/\/$/, "");
  if (!HOST) throw new Error("HOST is required");
  const config = oauthConfig ?? loadOAuthConfig();
  const baseFetch = fetchImpl ?? fetch;
  const requestEnv = env ?? process.env;

  // Stops an obvious flood -- including one made entirely of garbage
  // bearer tokens -- before it costs this server anything beyond a Map
  // lookup, and before token validation ever spends a call on salt-api.
  // Shared across every request to this app instance (per-IP counters
  // must persist to mean anything); see src/rate-limiter.mjs.
  const limiter = rateLimiter ?? createRateLimiter(rateLimitOptions ?? {});

  // --- legacy header-auth path: unchanged from the pre-OAuth server ------
  // Tool metadata (names/schemas) never depends on which client executes
  // a call, so this one throwaway build (base fetch, never actually used
  // to call salt-api) is enough for tools/list and the /health count.
  // Real execution below builds a FRESH client per request, wrapped with
  // that request's own edge headers.
  const hostedDefinitions = createActions({
    client: createSaltClient({ host: HOST, fetchImpl: baseFetch }),
    identities: createIdentityStore(),
    pgpPassphrase: "unused-on-hosted",
    publicWebhookUrl: "",
  }).definitions.filter((d) => HOSTED_TOOLS.has(d.name));

  function buildLegacyServer(caller, edgeHeaders) {
    const scopedFetch = withEdgeHeaders(baseFetch, edgeHeaders);
    const legacyActions = createActions({
      client: createSaltClient({ host: HOST, fetchImpl: scopedFetch }),
      identities: createIdentityStore(),
      pgpPassphrase: "unused-on-hosted",
      publicWebhookUrl: "",
    });
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

  // Validates a bearer against salt-api (GET /api/v1/oauth2/grant) once
  // per request, cached ~30s (bounded LRU) by token digest -- see
  // token-validator.mjs's header comment for why this exists at all (an
  // unchecked bearer used to sail straight through to tools/list and
  // tools/call) and why the cache key is a digest, never the raw token.
  // Built once (the cache must persist across requests); the `rest`
  // client a cache MISS actually calls is passed in per-call below,
  // scoped to THAT request's edge headers.
  const tokenValidator = createTokenValidator({});

  // `requestCtx` carries the AbortSignal for this HTTP request (so
  // ask_human/get_ask_result stop polling salt-api the moment the client
  // disconnects -- see keyless-tools.mjs's pollForCardInteraction) and the
  // grant this token validated to (so money tools spend a wallet the
  // human actually attached to it, never a re-fetch, never a wallet of
  // the agent's own -- it has none).
  function buildKeylessServer(bearerToken, rest, requestCtx) {
    const server = new Server(
      { name: "salt-mcp-keyless", version: PACKAGE_VERSION },
      { capabilities: { tools: {}, resources: {} } }
    );
    server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: toKeylessMcpTools() }));
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      const tool = KEYLESS_TOOLS.find((t) => t.name === name);
      if (!tool) {
        return { content: [{ type: "text", text: `Tool "${name}" is not available on this connection.` }], isError: true };
      }
      // The low-level Server hands CallToolRequest.params.arguments to
      // this handler as-is -- it does NOT validate them against the
      // tool's own inputSchema. A 2026-09-18 security review flagged that
      // gap; this closes it with the same ajv setup
      // scripts/validate-server-json.mjs already uses for server.json.
      const { valid, message } = validateAgainstSchema(tool.inputSchema, args ?? {});
      if (!valid) {
        return { content: [{ type: "text", text: `Invalid arguments for "${name}": ${message}` }], isError: true };
      }
      try {
        const result = await runKeylessTool(name, args, { rest, bearerToken, signal: requestCtx.signal, grant: requestCtx.grant });
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
  // GET and DELETE on the MCP endpoint (2026-09-26). Streamable HTTP lets a
  // server open a standalone SSE stream on GET and end a session on DELETE;
  // this server does neither, and until now only POST was routed, so both
  // methods fell through to Express's bare 404 -- "nothing here". A health
  // checker that probes with GET (Glama's does) read the endpoint as down,
  // and an MCP client that tries GET first learned nothing about how to
  // authenticate. The endpoint exists; the right answers are the same 401 +
  // WWW-Authenticate that POST gives an anonymous caller (RFC 9728 -- this
  // is how a client discovers the authorization server), and 405 with
  // `Allow: POST` for anyone who is credentialed. No token is validated
  // here on purpose: there is nothing to serve on success, and validating
  // would let an anonymous prober spend this service's salt-api budget.
  const unsupportedMethod = (req, res) => {
    const callerIp = callerIpFromRequest(req, requestEnv) || "unknown";
    const rateCheck = limiter.check(callerIp);
    if (!rateCheck.allowed) {
      return res
        .status(429)
        .set("Retry-After", String(rateCheck.retryAfterSeconds))
        .json({ jsonrpc: "2.0", error: { code: -32004, message: "Too many requests. Slow down and retry later." }, id: null });
    }
    if (!callerFromHeaders(req) && !extractBearerToken(req.get("Authorization"))) {
      return sendUnauthorized(res, config);
    }
    return res
      .status(405)
      .set("Allow", "POST")
      .json({
        jsonrpc: "2.0",
        error: { code: -32601, message: `This server does not support ${req.method} on /mcp: it opens no standalone stream and keeps no session. Send JSON-RPC over POST.` },
        id: null,
      });
  };
  app.get("/mcp", unsupportedMethod);
  app.delete("/mcp", unsupportedMethod);

  app.post("/mcp", async (req, res) => {
    // Rate limit FIRST -- ahead of legacy/bearer branching, ahead of
    // token validation, ahead of everything. See src/rate-limiter.mjs's
    // header comment for why this sits here specifically.
    // requestEnv, not process.env: the rate limiter and the edge-header
    // relay must bucket on exactly the same notion of "who is this", and
    // TRUSTED_PROXY_HOPS is what decides it. Two sources would let them
    // disagree, which is the shape of the bug this whole path just had.
    const callerIp = callerIpFromRequest(req, requestEnv) || "unknown";
    const rateCheck = limiter.check(callerIp);
    if (!rateCheck.allowed) {
      return res
        .status(429)
        .set("Retry-After", String(rateCheck.retryAfterSeconds))
        .json({ jsonrpc: "2.0", error: { code: -32004, message: "Too many requests. Slow down and retry later." }, id: null });
    }

    const legacyCaller = callerFromHeaders(req);

    // Stops any in-flight ask_human/get_ask_result poll (see
    // keyless-tools.mjs's pollForCardInteraction) the instant this
    // request's connection closes -- a client that hangs up shouldn't
    // leave this server hitting salt-api on its behalf for up to another
    // 50s. Harmless to create even on the legacy path, which never reads it.
    const controller = new AbortController();
    res.on("close", () => controller.abort());

    // Every outbound call THIS request makes to salt-api -- legacy or
    // keyless, including the token-validation call below -- carries this
    // task's edge secret and this caller's real IP (empty when
    // EDGE_SECRET is unset, e.g. local dev; see src/edge-headers.mjs).
    const edgeHeaders = buildEdgeHeaders(req, requestEnv);

    let server;
    if (legacyCaller) {
      server = buildLegacyServer(legacyCaller, edgeHeaders);
    } else {
      const bearerToken = extractBearerToken(req.get("Authorization"));
      if (!bearerToken) {
        return sendUnauthorized(res, config);
      }
      // Refuse anything that isn't shaped like a token THIS resource
      // issues -- before it ever reaches salt-api. A JWT, an api-key, or
      // plain garbage all fail this the same way.
      if (!bearerToken.startsWith(ACCESS_TOKEN_PREFIX)) {
        return sendInvalidToken(res, config);
      }
      const rest = createSaltBearerClient({ host: HOST, fetchImpl: withEdgeHeaders(baseFetch, edgeHeaders) });
      let validation;
      try {
        validation = await tokenValidator.validate(bearerToken, { rest });
      } catch {
        // salt-api itself is unreachable/erroring -- not the same claim
        // as "this token is bad", so this is a 502, not a 401 (and the
        // token validator deliberately does not cache this outcome).
        return res.status(502).json({
          jsonrpc: "2.0",
          error: { code: -32003, message: "Could not reach Salt to validate this token. Try again shortly." },
          id: null,
        });
      }
      if (!validation.valid) {
        return sendInvalidToken(res, config);
      }
      server = buildKeylessServer(bearerToken, rest, { signal: controller.signal, grant: validation });
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
