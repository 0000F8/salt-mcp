// One authenticated call at startup so a wrong SALT_API_KEY fails loudly
// here instead of as a 401 on the first tool call. GET
// /api/v1/agents/webhook_secret answers `{agent_id, ...}` for the key's own
// agent; only `agent_id` is read (the secret is never logged).
//
// Never blocks startup on a network failure: a laptop that is offline when
// the client launches the server should still get a working server once it
// reconnects.

const TIMEOUT_MS = 10_000;

/**
 * @returns {Promise<{status: "ok"|"unauthorized"|"unreachable"|"unexpected", agentId?: string, mismatch?: boolean, message: string}>}
 */
export async function checkCredentials({ host, apiKey, appId, fetchImpl, timeoutMs = TIMEOUT_MS }) {
  const doFetch = fetchImpl ?? fetch;
  const base = String(host || "").replace(/\/$/, "");
  let res;
  try {
    res = await doFetch(`${base}/api/v1/agents/webhook_secret`, {
      method: "GET",
      headers: { "api-key": apiKey },
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    return { status: "unreachable", message: `couldn't reach ${base} to check SALT_API_KEY (${err?.message || err}); continuing anyway.` };
  }
  if (res.status === 401 || res.status === 403) {
    return {
      status: "unauthorized",
      message: `SALT_API_KEY was rejected by ${base} (HTTP ${res.status}). Use the agent's api key (shown once when the agent is created) and check HOST.`,
    };
  }
  if (!res.ok) {
    return { status: "unexpected", message: `couldn't verify SALT_API_KEY: ${base} answered HTTP ${res.status}; continuing anyway.` };
  }
  let body;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  const agentId = body?.agent_id != null ? String(body.agent_id) : undefined;
  const mismatch = agentId !== undefined && String(appId ?? "") !== agentId;
  return {
    status: "ok",
    agentId,
    mismatch,
    message: mismatch ? `SALT_APP_ID is ${appId} but this API key belongs to agent ${agentId}; set SALT_APP_ID=${agentId}.` : "SALT_API_KEY accepted.",
  };
}
