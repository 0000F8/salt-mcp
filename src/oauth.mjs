// OAuth 2.0 resource-server behavior for the hosted MCP endpoint
// (mcp.saltapp.ai), per the K5 contract in
// design-fleet/runs/2026-09-17-distribution/LANES.md ("Remote MCP OAuth
// contract (K5)") and the MCP authorization spec
// (https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization),
// which itself layers on:
//   - RFC 9728  OAuth 2.0 Protected Resource Metadata
//   - RFC 8707  Resource Indicators for OAuth 2.0
//
// Salt itself (salt-api, built in parallel by the k5-oauth lane) is the
// OAuth 2.1 authorization server. This module only plays the RESOURCE
// SERVER's part for the MCP endpoint: it advertises where the
// authorization server is, and it demands a bearer token be present (in
// shape) before letting a request through. It does NOT validate the
// token's signature/claims -- that authority lives at salt-api, which the
// caller's tool calls hit directly (see src/http.mjs and
// src/keyless-tools.mjs). A bearer that LOOKS well-formed but is expired,
// revoked, or forged fails downstream at salt-api, and that failure comes
// back as an ordinary tool error (isError: true), not a second 401 --
// this server has no way to distinguish "revoked" from "never existed"
// without asking salt-api, and asking on every request would mean an
// extra round trip before every tool call.
//
// Pure functions only, deliberately -- no Express/HTTP objects cross this
// module's boundary except inside registerProtectedResourceRoutes, so the
// interesting logic (metadata shape, WWW-Authenticate framing, bearer
// parsing) is directly unit-testable.

/** The MCP path this server's protected resource sits at. Fixed by the K5 contract. */
export const MCP_RESOURCE_PATH = "/mcp";

/**
 * Everything the K5 contract fixes about this deployment. Overridable via
 * env for local/dev runs and tests; production leaves these at their
 * contract defaults.
 */
export function loadOAuthConfig(env = process.env) {
  return {
    // RFC 8707 canonical resource URI -- the MCP client's `resource` param
    // and this server's own self-identification MUST match this exactly.
    resource: env.MCP_RESOURCE_URL || "https://mcp.saltapp.ai/mcp",
    // Salt is the OAuth 2.1 authorization server for this resource.
    issuer: env.MCP_ISSUER || "https://saltapp.ai",
    scopesSupported: ["chat", "money"],
  };
}

/**
 * RFC 9728 Protected Resource Metadata document. Field names are the
 * RFC's own: `resource`, `authorization_servers`, `scopes_supported`,
 * `bearer_methods_supported`.
 */
export function buildProtectedResourceMetadata({ resource, issuer, scopesSupported }) {
  return {
    resource,
    authorization_servers: [issuer],
    scopes_supported: [...scopesSupported],
    bearer_methods_supported: ["header"],
  };
}

/**
 * Both well-known paths RFC 9728 allows for a resource with a path
 * component: the bare well-known path (several real-world clients probe
 * this first, treating it as the default resource on the host) and the
 * path-suffixed variant (RFC 9728 Section 3.1, mirroring RFC 8414's
 * insertion rule: `/.well-known/oauth-protected-resource` + the resource's
 * own path). For `resourcePath = "/mcp"` this returns
 * `["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]`.
 */
export function protectedResourceMetadataPaths(resourcePath) {
  const base = "/.well-known/oauth-protected-resource";
  const suffixed = resourcePath && resourcePath !== "/" ? `${base}${resourcePath}` : base;
  return suffixed === base ? [base] : [base, suffixed];
}

/**
 * The exact WWW-Authenticate header value for a 401 response, per RFC 9728
 * Section 5.1: `Bearer resource_metadata="<url>"`. `metadataUrl` should be
 * the ABSOLUTE URL of the (suffixed, most-specific) protected resource
 * metadata document. Used when there's no credential at all -- see
 * wwwAuthenticateInvalidTokenHeader for a token that WAS presented but is
 * wrong (wrong shape, or rejected by salt-api).
 */
export function wwwAuthenticateHeader(metadataUrl) {
  return `Bearer resource_metadata="${metadataUrl}"`;
}

/**
 * The WWW-Authenticate value for a token that was presented but is
 * invalid -- doesn't have the `sat_` prefix this resource's tokens always
 * carry, or salt-api itself rejected it (expired/revoked/malformed). Per
 * RFC 6750 Section 3.1, the `error="invalid_token"` parameter is what
 * tells a compliant client its token is bad and it should re-authenticate
 * (get a fresh one) rather than retry the same one.
 */
export function wwwAuthenticateInvalidTokenHeader(metadataUrl) {
  return `Bearer error="invalid_token", resource_metadata="${metadataUrl}"`;
}

/**
 * Parses an `Authorization` header value and returns the bearer token, or
 * null if the header is missing, empty, or not a well-formed
 * `Bearer <token>` credential (case-insensitive scheme, exactly one
 * token, no embedded whitespace -- a raw access token never contains
 * spaces). Deliberately permissive about the token's own alphabet (opaque
 * tokens are salt-api's to define; this module only enforces the HTTP
 * framing OAuth 2.1 requires).
 *
 * This is a SHAPE check, not a validity check -- see the module header
 * comment for why full validation happens at salt-api instead.
 */
export function extractBearerToken(authorizationHeaderValue) {
  if (typeof authorizationHeaderValue !== "string") return null;
  const match = authorizationHeaderValue.match(/^Bearer\s+(\S+)$/i);
  if (!match) return null;
  return match[1];
}

/**
 * Mounts the PRM document at both allowed well-known paths. Unauthenticated
 * by design -- RFC 9728 metadata is meant to be discoverable before a
 * client has any token at all.
 */
export function registerProtectedResourceRoutes(app, config) {
  const metadata = buildProtectedResourceMetadata(config);
  for (const path of protectedResourceMetadataPaths(new URL(config.resource).pathname)) {
    app.get(path, (_req, res) => {
      res.status(200).json(metadata);
    });
  }
}

/**
 * The absolute URL of the most-specific (path-suffixed) protected resource
 * metadata document, for use in a 401's WWW-Authenticate header.
 */
export function protectedResourceMetadataUrl(config) {
  const resourceUrl = new URL(config.resource);
  const paths = protectedResourceMetadataPaths(resourceUrl.pathname);
  const mostSpecific = paths[paths.length - 1];
  return `${resourceUrl.protocol}//${resourceUrl.host}${mostSpecific}`;
}

/**
 * Sends the spec-conformant 401 for "no valid bearer" -- both the JSON-RPC
 * error body this codebase's other 401 (missing legacy headers) already
 * used, and the WWW-Authenticate header RFC 9728 requires. Use this ONLY
 * when no credential was presented at all (or the Authorization header
 * doesn't even parse as `Bearer <token>`) -- a token that WAS presented
 * but is wrong gets sendInvalidToken instead, so a client can tell "you
 * never tried" from "that token is bad, get a new one."
 */
export function sendUnauthorized(res, config) {
  res
    .status(401)
    .set("WWW-Authenticate", wwwAuthenticateHeader(protectedResourceMetadataUrl(config)))
    .json({
      jsonrpc: "2.0",
      error: { code: -32001, message: "Missing or malformed Authorization: Bearer token" },
      id: null,
    });
}

/**
 * Sends the 401 for a token that WAS presented (parsed as `Bearer <token>`)
 * but is invalid -- wrong prefix (never a `sat_...` token this resource
 * issues, e.g. a JWT from somewhere else) or rejected by salt-api itself.
 * `error="invalid_token"` (RFC 6750 Section 3.1) is the signal a compliant
 * OAuth client uses to know it should discard this token and get a fresh
 * one, rather than retry the same bad token forever.
 */
export function sendInvalidToken(res, config) {
  res
    .status(401)
    .set("WWW-Authenticate", wwwAuthenticateInvalidTokenHeader(protectedResourceMetadataUrl(config)))
    .json({
      jsonrpc: "2.0",
      error: { code: -32001, message: "invalid_token" },
      id: null,
    });
}
