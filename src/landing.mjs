// What a visitor sees at the root of the hosted server, and for any path that
// is not a route. Until now both were Express's default "Cannot GET /" page.
// An agent gets JSON (how to connect, where the discovery documents are); a
// browser gets one small styled page. Content negotiation decides: a caller
// that names text/html first (every browser) gets the page, everything else
// (curl, fetch, an MCP client, `*/*`) gets JSON.
//
// Both are unauthenticated and static -- nothing here touches salt-api, so an
// anonymous prober cannot spend this service's upstream budget.

import { protectedResourceMetadataUrl } from "./oauth.mjs";

const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function origin(config) {
  return new URL(config.resource).origin;
}

/** The machine-readable landing document. */
export function buildLanding(config) {
  const base = origin(config);
  return {
    name: "Salt MCP",
    description: "Hosted Model Context Protocol server for Salt (saltapp.ai): the Salt agent network as MCP tools.",
    mcp_url: config.resource,
    transport: "streamable-http",
    methods: { "/mcp": ["POST"] },
    auth: {
      type: "oauth2",
      authorization_server: config.issuer,
      protected_resource_metadata: protectedResourceMetadataUrl(config),
      scopes_supported: config.scopesSupported,
      note: "An OAuth-capable MCP client discovers everything from a 401 on /mcp. No manual key is needed.",
    },
    connect: {
      claude_code: `claude mcp add --transport http salt ${config.resource}`,
      generic: `Add a remote MCP server with url ${config.resource} (transport: streamable HTTP) and sign in when asked.`,
    },
    health_url: `${base}/health`,
    docs_url: "https://github.com/0000F8/salt-mcp#readme",
    agent_docs_url: "https://saltapp.ai/llms.txt",
  };
}

export function landingHtml(config) {
  const d = buildLanding(config);
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Salt MCP</title>
<style>
:root{color-scheme:dark light;--bg:#0b1220;--ink:#f1f5f9;--mut:#a3b1c6;--line:#24324d;--card:#111a2e;--acc:#6aa8ff;--accink:#0b1220}
@media (prefers-color-scheme:light){:root{--bg:#f8fafc;--ink:#0f172a;--mut:#51607a;--line:#d5dce8;--card:#fff;--acc:#2563eb;--accink:#fff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:19px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;padding:32px 20px}
main{max-width:640px;margin:0 auto}p.k{margin:0 0 12px;font:600 13px/1 ui-monospace,Menlo,monospace;letter-spacing:.18em;color:var(--mut);text-transform:uppercase}
h1{margin:0 0 12px;font-size:34px;line-height:1.15}p{margin:0 0 20px;color:var(--mut)}
code,pre{font:15px/1.5 ui-monospace,Menlo,monospace}pre{margin:0 0 20px;padding:14px 16px;background:var(--card);border:1px solid var(--line);overflow-x:auto;color:var(--ink)}
ol{padding-left:22px;margin:0 0 24px;color:var(--mut)}li{margin-bottom:8px}a{color:var(--acc)}
.btn{display:inline-block;padding:12px 22px;background:var(--acc);color:var(--accink);font-weight:600;text-decoration:none;border-radius:2px}
footer{margin-top:36px;font-size:15px;color:var(--mut)}
</style></head><body><main>
<p class="k">Salt MCP</p>
<h1>Give your AI client a Salt account.</h1>
<p>This is the hosted Model Context Protocol server for Salt. Connect an MCP client and it can find agents, message people, and move money with your approval.</p>
<pre>${escapeHtml(d.mcp_url)}</pre>
<ol>
<li>Add a remote MCP server in your client with the address above (streamable HTTP).</li>
<li>Sign in to Salt when your client asks. That is the whole setup.</li>
</ol>
<p><a class="btn" href="${escapeHtml(d.docs_url)}">Setup guides for each client</a></p>
<footer>Building an agent? Ask this page for JSON: <code>curl -H "Accept: application/json" ${escapeHtml(origin(config))}/</code> &middot; <a href="${escapeHtml(d.health_url)}">health</a> &middot; <a href="https://saltapp.ai">saltapp.ai</a></footer>
</main></body></html>`;
}

function notFoundHtml(config, path) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Not found | Salt MCP</title>
<style>
:root{color-scheme:dark light}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1220;color:#f1f5f9;font:19px/1.6 system-ui,-apple-system,sans-serif;padding:24px;text-align:center}
main{max-width:440px}p.c{margin:0 0 10px;font:600 13px/1 ui-monospace,monospace;letter-spacing:.18em;color:#a3b1c6}h1{margin:0 0 10px;font-size:30px;line-height:1.15}p{margin:0 0 20px;color:#a3b1c6}
code{font:15px ui-monospace,monospace;overflow-wrap:anywhere}a{display:inline-block;padding:12px 22px;background:#6aa8ff;color:#0b1220;font-weight:600;text-decoration:none}
@media (prefers-color-scheme:light){body{background:#f8fafc;color:#0f172a}p,p.c{color:#51607a}a{background:#2563eb;color:#fff}}
</style></head><body><main><p class="c">404</p><h1>Nothing here</h1>
<p><code>${escapeHtml(path)}</code> is not part of this server. The MCP endpoint is <code>/mcp</code>.</p>
<a href="/">How to connect</a></main></body></html>`;
}

/** GET / (and HEAD). */
export function landingHandler(config) {
  const doc = buildLanding(config);
  return (req, res) => {
    res.set("Cache-Control", "public, max-age=300").vary("Accept");
    if (req.accepts(["json", "html"]) === "html") return res.type("html").send(landingHtml(config));
    return res.status(200).json(doc);
  };
}

/** Last route: anything unmatched. */
export function notFoundHandler(config) {
  const base = origin(config);
  return (req, res) => {
    res.set("Cache-Control", "no-store").vary("Accept");
    if (req.method === "GET" && req.accepts(["json", "html"]) === "html") {
      return res.status(404).type("html").send(notFoundHtml(config, req.path));
    }
    return res.status(404).json({
      error: "not_found",
      code: "not_found",
      message: `No route ${req.method} ${req.path}. The MCP endpoint is POST ${new URL(config.resource).pathname}.`,
      docs_url: `${base}/`,
    });
  };
}
