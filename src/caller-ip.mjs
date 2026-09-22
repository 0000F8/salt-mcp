// Derives the real end-user IP address the way this ECS task actually sees
// it, and it is NOT the first entry of X-Forwarded-For.
//
// That was the original reading, on the assumption that this service sits
// behind CloudFront -> an ALB, so the header would arrive as
// `<original client>, <CloudFront>`. It does not. `mcp.saltapp.ai` is a
// plain ALB host rule with no CloudFront in front of it (salt-deploy
// infra/mcp.tf routes the hostname straight at the load balancer; a live
// check confirms responses from mcp.saltapp.ai carry none of the
// `via: ...cloudfront.net` / `x-amz-cf-*` headers that saltapp.ai's do).
//
// X-Forwarded-For is CLIENT-SUPPLIED and an ALB only ever APPENDS to it:
// if a caller sends `X-Forwarded-For: 1.2.3.4`, the task receives
// `1.2.3.4, <caller's real address>`. So the first entry is whatever the
// attacker wrote, and the LAST entry is the one address in the list that a
// piece of AWS infrastructure observed rather than accepted.
//
// This mattered twice over, because the value is used for two things
// (2026-09-19 availability review, N2): the CloudFront-Viewer-Address /
// X-Forwarded-For pair src/edge-headers.mjs relays onward to salt-api
// under the real EDGE_SECRET -- where EdgeClientIp rewrites the request's
// address to it, so a forged value became `request.remote_ip` for every
// per-IP rate limit and every IP written to an Event -- and the key
// src/rate-limiter.mjs buckets on, which rotating the header defeated
// outright. Found by the K5 security review, 2026-09-22.
//
// Read from the right, not the left. TRUSTED_PROXY_HOPS is the number of
// proxies between the real client and the ALB: 0 today, so the last entry
// is the client. Put CloudFront back in front and it becomes 1, because
// the ALB would then be appending CloudFront's address rather than the
// caller's. This is the same rule Express's `trust proxy` implements when
// given a hop COUNT, and the same reason it takes a count rather than a
// boolean.

const DEFAULT_TRUSTED_PROXY_HOPS = 0;

/**
 * @param {NodeJS.ProcessEnv} env
 * @returns {number}
 */
export function trustedProxyHops(env = process.env) {
  const raw = Number.parseInt(env.TRUSTED_PROXY_HOPS ?? "", 10);
  return Number.isInteger(raw) && raw >= 0 ? raw : DEFAULT_TRUSTED_PROXY_HOPS;
}

/**
 * @param {import("express").Request} req
 * @param {NodeJS.ProcessEnv} env
 * @returns {string | null}
 */
export function callerIpFromRequest(req, env = process.env) {
  const xff = typeof req.get === "function" ? req.get("X-Forwarded-For") : req.headers?.["x-forwarded-for"];
  if (xff) {
    const parts = String(xff)
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);
    // Count in from the right. A caller can make this list arbitrarily long,
    // so if the index it implies falls off the left-hand end, the list is
    // shorter than the topology we trust and NOTHING in it was observed by
    // our own infrastructure -- fall through to the socket rather than pick
    // the attacker's leftmost entry as a consolation prize.
    const index = parts.length - 1 - trustedProxyHops(env);
    if (index >= 0 && parts[index]) return parts[index];
  }
  // No X-Forwarded-For at all -- not behind the ALB (local dev, or a direct
  // test connection). The raw socket address is the only thing left that
  // wasn't supplied by the caller. Deliberately NOT req.ip: with Express's
  // `trust proxy` set, req.ip is itself derived from this same header.
  return req.socket?.remoteAddress || null;
}
