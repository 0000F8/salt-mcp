// Derives the real end-user IP address the way this ECS task actually
// sees it, sitting behind CloudFront -> an ALB. Every proxy in a chain
// APPENDS its own hop to X-Forwarded-For, so the header this task
// receives from the ALB is `<original client>, <CloudFront's own
// address>` (or, if CloudFront doesn't forward one, just the ALB's own
// view) -- the FIRST entry is always the original caller, never the last.
// "X-Forwarded-For from the ALB, first hop" is exactly this.
//
// Used for two things (2026-09-19 availability review, N2): the
// CloudFront-Viewer-Address/X-Forwarded-For pair src/edge-headers.mjs
// relays onward to salt-api, and the key src/rate-limiter.mjs buckets on.
// Both need the SAME notion of "who is this," so it lives here once.

/**
 * @param {import("express").Request} req
 * @returns {string | null}
 */
export function callerIpFromRequest(req) {
  const xff = typeof req.get === "function" ? req.get("X-Forwarded-For") : req.headers?.["x-forwarded-for"];
  if (xff) {
    const first = String(xff).split(",")[0]?.trim();
    if (first) return first;
  }
  // No X-Forwarded-For at all -- not behind the ALB (local dev, or a
  // direct test connection). Express's own req.ip (honours `trust proxy`
  // when set) or the raw socket address is the best available fallback.
  return req.ip || req.socket?.remoteAddress || null;
}
