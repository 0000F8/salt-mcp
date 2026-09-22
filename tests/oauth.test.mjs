// Unit tests for src/oauth.mjs: RFC 9728 Protected Resource Metadata shape,
// both well-known paths, the exact WWW-Authenticate framing, and bearer
// token parsing. See the K5 contract in
// design-fleet/runs/2026-09-17-distribution/LANES.md.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  loadOAuthConfig,
  buildProtectedResourceMetadata,
  protectedResourceMetadataPaths,
  protectedResourceMetadataUrl,
  wwwAuthenticateHeader,
  extractBearerToken,
} from "../src/oauth.mjs";

test("loadOAuthConfig defaults match the K5 contract exactly", () => {
  const config = loadOAuthConfig({});
  assert.equal(config.resource, "https://mcp.saltapp.ai/mcp");
  assert.equal(config.issuer, "https://saltapp.ai");
  assert.deepEqual(config.scopesSupported, ["chat", "money"]);
});

test("loadOAuthConfig honours env overrides for local/dev/test runs", () => {
  const config = loadOAuthConfig({ MCP_RESOURCE_URL: "http://localhost:5200/mcp", MCP_ISSUER: "http://localhost:3000" });
  assert.equal(config.resource, "http://localhost:5200/mcp");
  assert.equal(config.issuer, "http://localhost:3000");
});

test("buildProtectedResourceMetadata carries the exact RFC 9728 field names", () => {
  const metadata = buildProtectedResourceMetadata({
    resource: "https://mcp.saltapp.ai/mcp",
    issuer: "https://saltapp.ai",
    scopesSupported: ["chat", "money"],
  });
  assert.deepEqual(metadata, {
    resource: "https://mcp.saltapp.ai/mcp",
    authorization_servers: ["https://saltapp.ai"],
    scopes_supported: ["chat", "money"],
    bearer_methods_supported: ["header"],
  });
});

test("protectedResourceMetadataPaths returns the bare path and the path-suffixed variant for a resource with a path", () => {
  assert.deepEqual(protectedResourceMetadataPaths("/mcp"), [
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
  ]);
});

test("protectedResourceMetadataPaths returns just the bare path for a resource with no path component", () => {
  assert.deepEqual(protectedResourceMetadataPaths("/"), ["/.well-known/oauth-protected-resource"]);
  assert.deepEqual(protectedResourceMetadataPaths(""), ["/.well-known/oauth-protected-resource"]);
});

test("protectedResourceMetadataUrl builds the absolute, most-specific (suffixed) metadata URL", () => {
  const url = protectedResourceMetadataUrl({ resource: "https://mcp.saltapp.ai/mcp" });
  assert.equal(url, "https://mcp.saltapp.ai/.well-known/oauth-protected-resource/mcp");
});

test("wwwAuthenticateHeader is exactly `Bearer resource_metadata=\"<url>\"`", () => {
  const header = wwwAuthenticateHeader("https://mcp.saltapp.ai/.well-known/oauth-protected-resource/mcp");
  assert.equal(header, 'Bearer resource_metadata="https://mcp.saltapp.ai/.well-known/oauth-protected-resource/mcp"');
});

test("extractBearerToken parses a well-formed Authorization header", () => {
  assert.equal(extractBearerToken("Bearer sat_abc123"), "sat_abc123");
  assert.equal(extractBearerToken("bearer sat_abc123"), "sat_abc123", "scheme is case-insensitive");
});

test("extractBearerToken rejects anything malformed or absent", () => {
  assert.equal(extractBearerToken(undefined), null);
  assert.equal(extractBearerToken(""), null);
  assert.equal(extractBearerToken("Basic dXNlcjpwYXNz"), null);
  assert.equal(extractBearerToken("Bearer"), null, "no token at all");
  assert.equal(extractBearerToken("Bearer  "), null, "whitespace only");
  assert.equal(extractBearerToken("Bearer two tokens"), null, "must be exactly one token, no embedded spaces");
});
