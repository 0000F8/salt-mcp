// Every outbound request THIS MCP server makes to salt-api -- both the
// legacy header-auth path (salt-agent-sdk's client) and the OAuth/keyless
// path (salt-bearer-client.mjs) -- carries proof this call came from the
// real, deployed MCP task and the real end-user's IP, so salt-api's own
// edge defenses (rate limiting, geo, abuse detection) see the actual
// caller instead of "the MCP task's own IP, unauthenticated." Added for
// the 2026-09-19 availability review (N2): src/http.mjs wraps its
// outbound `fetch` with these on every request, built fresh per incoming
// HTTP request (the caller IP is per-request; the secret is not).
//
// `X-Salt-Edge` is the existing edge secret salt-api already trusts from
// other first-party callers (the coordinator wires EDGE_SECRET into this
// service's ECS task definition in Terraform -- this file only reads it).
// `CloudFront-Viewer-Address`/`X-Forwarded-For` are the two shapes
// salt-api's own CloudFront-fronted origin already reads a viewer IP from
// (see salt-api's own `CloudFront-Viewer-Country` origin request policy
// note in the workspace CLAUDE.md) -- relaying both means salt-api's
// existing per-viewer logic keeps working whether the request came
// through CloudFront directly or via this MCP task.
//
// When EDGE_SECRET is unset (local dev, no Terraform-provisioned secret),
// this sends NEITHER the secret NOR the IP headers -- salt-api never sees
// an edge claim it can't verify, and a local dev's own loopback address
// never gets relayed as if it were a real viewer.

import { callerIpFromRequest } from "./caller-ip.mjs";

/**
 * @param {import("express").Request} req
 * @param {NodeJS.ProcessEnv} env
 * @returns {Record<string, string>}
 */
export function buildEdgeHeaders(req, env = process.env) {
  const edgeSecret = env.EDGE_SECRET;
  if (!edgeSecret) return {};
  const headers = { "X-Salt-Edge": edgeSecret };
  const ip = callerIpFromRequest(req);
  if (ip) {
    headers["CloudFront-Viewer-Address"] = `${ip}:0`;
    headers["X-Forwarded-For"] = ip;
  }
  return headers;
}

/**
 * Wraps a fetch-compatible function so every call it makes carries
 * `extraHeaders` merged on top of whatever headers the caller already
 * set (the caller's own headers win on a name collision, though none of
 * these names should ever collide with one salt-bearer-client.mjs or
 * salt-agent-sdk's client sets). A no-op wrapper (returns `baseFetch`
 * unchanged) when there's nothing to add, so the local-dev "send
 * neither" case costs nothing extra per call.
 *
 * @param {typeof fetch} baseFetch
 * @param {Record<string, string>} extraHeaders
 */
export function withEdgeHeaders(baseFetch, extraHeaders) {
  if (!extraHeaders || Object.keys(extraHeaders).length === 0) return baseFetch;
  return (url, init = {}) => baseFetch(url, { ...init, headers: { ...extraHeaders, ...(init.headers || {}) } });
}
