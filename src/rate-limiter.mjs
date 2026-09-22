// A fixed-window, per-IP request limiter sitting in front of EVERYTHING
// else on /mcp -- including token validation itself. Added for the
// 2026-09-19 availability review (N2): before this, a flood of requests
// carrying random/garbage bearer tokens would each still cost a call to
// salt-api's GET /api/v1/oauth2/grant (rejected, but not free), so a
// large-enough flood could pressure salt-api even though every individual
// token was worthless. This stops that at the MCP server, before a
// garbage-token flood ever reaches token validation.
//
// Deliberately simple (one counter per IP per window, not a sliding-log
// or token-bucket) -- the goal is "stop an obvious flood from one
// address," not perfectly smooth rate shaping.

const DEFAULT_LIMIT = 60;
const DEFAULT_WINDOW_MS = 60_000;
// Bounds the bucket map's memory under sustained traffic from many
// distinct IPs: once it grows past this, the next check() call sweeps
// out any bucket whose window has already lapsed. Cheap in the common
// case (small map, sweep never triggers) and self-limiting even if an
// attacker deliberately spreads a flood across many source IPs.
const SWEEP_ABOVE_SIZE = 20_000;

/**
 * @param {{limit?: number, windowMs?: number, now?: () => number}} options
 */
export function createRateLimiter({ limit = DEFAULT_LIMIT, windowMs = DEFAULT_WINDOW_MS, now = Date.now } = {}) {
  const buckets = new Map(); // ip -> { count, resetAt }

  function sweepExpired(current) {
    for (const [ip, bucket] of buckets) {
      if (bucket.resetAt <= current) buckets.delete(ip);
    }
  }

  /**
   * @param {string} ip
   * @returns {{allowed: true} | {allowed: false, retryAfterSeconds: number}}
   */
  function check(ip) {
    const current = now();
    if (buckets.size > SWEEP_ABOVE_SIZE) sweepExpired(current);

    let bucket = buckets.get(ip);
    if (!bucket || current >= bucket.resetAt) {
      bucket = { count: 0, resetAt: current + windowMs };
      buckets.set(ip, bucket);
    }
    bucket.count += 1;
    if (bucket.count > limit) {
      const retryAfterSeconds = Math.max(1, Math.ceil((bucket.resetAt - current) / 1000));
      return { allowed: false, retryAfterSeconds };
    }
    return { allowed: true };
  }

  return { check };
}
