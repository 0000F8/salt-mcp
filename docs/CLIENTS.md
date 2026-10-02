# Adding Salt to your MCP client

The full client-by-client matrix. The README's [Add Salt to your client](../README.md#add-salt-to-your-client)
section covers the eight most common clients and links here for everything
else — CLI coding agents, IDE plugins, self-hosted chat UIs, low-code
platforms, and agent SDKs.

Every entry connects to the same server, `https://mcp.saltapp.ai/mcp`
(Streamable HTTP). A client with genuine remote-MCP-with-OAuth support needs
**only that URL** — it discovers the flow itself from the 401's
`WWW-Authenticate` header, no client id/secret to register anywhere (see
"Connect over OAuth" in the main README). Where a client doesn't do that
dance yet, this page says so plainly instead of guessing.

Two things every entry below assumes:

- **Scopes**: at the consent screen you pick `chat` and/or `money` — same as
  every other client, nothing library-specific.
- **Headless/backend auth**: an SDK that only accepts a bearer token or
  static headers (no browser, so no interactive consent) has two real
  options against Salt: (1) a `sat_...` access token obtained once through
  any OAuth-capable client above, passed as `Authorization: Bearer <token>` —
  keyless catalog (14 tools with `chat`, 19 with `chat` + `money`), but the token expires and these libraries
  don't refresh it for you; or (2) Salt's **legacy header auth**
  (`X-Salt-Api-Key` + `X-Salt-App-Id`, naming a non-keyless agent identity
  you already control) — long-lived, but only serves `list_salt_agents`,
  `list_products`, and `create_product` (see "A note on custody" in the main
  README for why). Each SDK entry below shows the header field; which of the
  two you put in it is your call.

## IDE and editor plugins

**VS Code** (GitHub Copilot) — full remote OAuth.

[![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Salt_MCP-0098FF?style=for-the-badge&logo=visualstudiocode)](vscode:mcp/install?%7B%22name%22%3A%22salt%22%2C%22type%22%3A%22http%22%2C%22url%22%3A%22https%3A%2F%2Fmcp.saltapp.ai%2Fmcp%22%7D)

Or `mcp.json`:
```json
{ "servers": { "salt": { "type": "http", "url": "https://mcp.saltapp.ai/mcp" } } }
```
VS Code shows a "Manage Authentication" CodeLens on the entry; running it opens
the browser consent screen. Verified against
https://code.visualstudio.com/docs/copilot/customization/mcp-servers and the
`vscode:mcp/install` handler's own source
(`src/vs/workbench/contrib/mcp/browser/mcpWorkbenchService.ts` in
microsoft/vscode, which parses the query as `JSON.parse(decodeURIComponent(...))`
with `name` alongside `type`/`url` — the badge above matches that contract
byte for byte). Needs VS Code 1.102+; enable CodeLens under Text Editor
settings if the auth prompt doesn't appear.

**Visual Studio** (2022 17.14+, or 2026) — full remote OAuth. Create
`.mcp.json` (solution or user folder):
```json
{ "servers": { "salt": { "url": "https://mcp.saltapp.ai/mcp" } } }
```
A CodeLens reading "Authentication Required" appears on the entry; select it,
then authenticate in the browser. Switch Copilot Chat to Agent mode and
enable the server's tools from the tool picker.
Verified: https://learn.microsoft.com/en-us/visualstudio/ide/mcp-servers?view=vs-2022
("Visual Studio now supports authentication for remote servers by using any
OAuth provider, in accordance with the MCP authorization specification.")

**Cursor** — see "Connect over OAuth" and the "Cursor" section above; already
fully documented there, including the one-click badge.

**Zed** — full remote OAuth. Agent panel → open settings → MCP Servers → Add
Remote Server → name `salt`, url `https://mcp.saltapp.ai/mcp` (leave headers
blank), or edit `settings.json` directly:
```json
{ "context_servers": { "salt": { "url": "https://mcp.saltapp.ai/mcp" } } }
```
Verified: https://zed.dev/docs/ai/mcp — "When a remote MCP server has no
configured 'Authorization' header, Zed will prompt you to authenticate
yourself against the MCP server using the standard MCP OAuth flow."

**Windsurf** (Cascade, now under Cognition's Devin Desktop docs) — full
remote OAuth per its own docs. Cascade panel → Actions (`...`) → Open MCP
config file → add:
```json
{ "mcpServers": { "salt": { "serverUrl": "https://mcp.saltapp.ai/mcp" } } }
```
Verified: https://docs.devin.ai/desktop/cascade/mcp (redirected from
`docs.windsurf.com/windsurf/cascade/mcp`) — "Devin Desktop also supports
OAuth for each transport type." No settings-UI walkthrough of the consent
step is shown, JSON-file only.

**JetBrains AI Assistant** (IntelliJ/PyCharm/etc.) — remote transport
supported; **no auth field documented at all**, OAuth or otherwise. Settings
→ Tools → AI Assistant → Model Context Protocol (MCP) → add:
```json
{ "mcpServers": { "salt": { "url": "https://mcp.saltapp.ai/mcp" } } }
```
Verified: https://www.jetbrains.com/help/ai-assistant/mcp.html — its own
worked example is a bare URL with no `headers`/`Authorization` field and
never mentions OAuth. Whether the plugin does the browser flow under the
hood isn't confirmed either way by the docs.

**Continue** (continue.dev) — remote transport supported; **OAuth not
documented**. `config.yaml`:
```yaml
mcpServers:
  - name: salt
    type: streamable-http
    url: https://mcp.saltapp.ai/mcp
```
Verified: https://docs.continue.dev/customize/deep-dives/mcp — the only
credential pattern shown (`env: ${{ secrets.X }}`) is for local `command`
servers; no header/OAuth field appears on the `streamable-http`/`sse`
transport examples.

**Cline** (VS Code extension) — remote supported, **static-auth only, no
OAuth**. MCP Servers panel → Configure MCP Servers (or the settings JSON):
```json
{ "mcpServers": { "salt": { "type": "streamableHttp", "url": "https://mcp.saltapp.ai/mcp", "disabled": false } } }
```
Verified: https://docs.cline.bot/mcp/mcp-overview and
https://docs.cline.bot/enterprise-solutions/configuration/infrastructure-configuration/control-other-cline-features/mcp-server-controls
— only a static `headers` field is documented; no discovery/PKCE/DCR, no
bridge recommended.

**Roo Code** (Cline fork) — same gap. Roo panel → Edit Global MCP (or
`.roo/mcp.json`):
```json
{ "mcpServers": { "salt": { "type": "streamable-http", "url": "https://mcp.saltapp.ai/mcp" } } }
```
Note the hyphenated `"streamable-http"` vs Cline's `"streamableHttp"` — the
forks diverged on this string. Verified:
https://roocodeinc.github.io/Roo-Code/features/mcp/using-mcp-in-roo

## Desktop and web chat apps

**Claude Desktop, Claude Code, and claude.ai** — see "Connect over OAuth"
above; all three already fully documented there.

**ChatGPT** — Settings → Security and login → turn on Developer mode → Go to
ChatGPT Plugins → the "+" button → paste `https://mcp.saltapp.ai/mcp`. OAuth
is supported ("users in your workspace will get an OAuth flow to your
service"). Verified: https://developers.openai.com/api/docs/mcp . Custom
connectors need a paid workspace/Plus+ plan (per the main README's existing
note); the exact plan gate isn't spelled out on this specific doc page.

**Goose** (Block/Linux Foundation) — full remote OAuth via Dynamic Client
Registration. Desktop deeplink:
```
goose://extension?url=https%3A%2F%2Fmcp.saltapp.ai%2Fmcp&type=streamable_http&id=salt&name=Salt&description=Salt%20agent%20network
```
CLI: `goose configure` → Remote Extension (Streamable HTTP) → endpoint
`https://mcp.saltapp.ai/mcp`. Verified:
https://goose-docs.ai/docs/getting-started/using-extensions/ — "Remote
(streamable_http) extensions that require OAuth normally obtain a client ID
automatically, using Client ID Metadata Documents or Dynamic Client
Registration."

**Raycast** — full remote OAuth. Install MCP Server (or Manage MCP Servers →
Install New Server) → Transport: HTTP → URL `https://mcp.saltapp.ai/mcp` →
OAuth Type: **Dynamic** (Raycast's label for DCR + PKCE — must pick this over
"Static", which expects a pre-registered client). Verified:
https://manual.raycast.com/ai/model-context-protocol

**LibreChat** (self-hosted) — full remote OAuth, auto-discovery included.
`librechat.yaml`:
```yaml
mcpServers:
  salt:
    type: 'streamable-http'
    initTimeout: 150000
    url: 'https://mcp.saltapp.ai/mcp'
```
No `oauth:` block needed — omitting client id/secret triggers Dynamic Client
Registration. Verified: https://github.com/librechat-ai/docs (content/docs/features/mcp.mdx,
content/docs/configuration/librechat_yaml/object_structure/mcp_servers.mdx) —
the shipped Spotify/PayPal examples use this exact minimal shape, labeled
"uses OAuth Client Discovery." Use a generous `initTimeout` for the first
browser round trip.

**Open WebUI** (self-hosted) — full remote OAuth. Settings → Admin →
Integrations → External Tool Servers → Add Connection → Type: MCP
(Streamable HTTP) → URL `https://mcp.saltapp.ai/mcp` → Auth: **OAuth 2.1**
(not "OAuth 2.1 (Static)") → Register Client. Then per-chat: "+" →
Integrations → Tools → enable "salt" → complete the consent redirect.
Verified: https://github.com/open-webui/docs (features/extensibility/mcp.mdx,
tutorials/integrations/mcp-notion.mdx) — "OAuth 2.1: Uses Dynamic Client
Registration (DCR)." OAuth tools can't be set as always-on defaults on a
model; enable per-chat.

## CLI coding agents

**Claude Code** — see "Connect over OAuth" above.

**OpenAI Codex CLI**:
```
codex mcp add salt --url https://mcp.saltapp.ai/mcp
```
`codex mcp login salt` / `codex mcp logout salt` manage the OAuth session
explicitly. Verified against the CLI's own source (`codex-rs/cli/src/mcp_cmd.rs`,
`codex-rs/codex-mcp/src/mcp/auth.rs` in openai/codex) rather than a prose doc
page — Codex doesn't have one yet for this flag. Legacy SSE isn't supported,
only stdio + Streamable HTTP (which is what Salt runs).

**Gemini CLI**:
```
gemini mcp add --transport http salt https://mcp.saltapp.ai/mcp
```
Falls back to `/mcp auth salt` if the browser flow isn't triggered
automatically. Verified:
https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md
Defaults to project scope (`.gemini/settings.json`); pass `-s user` for
`~/.gemini/settings.json`.

**GitHub Copilot CLI** (terminal):
```
copilot mcp add --transport http salt https://mcp.saltapp.ai/mcp
```
or `/mcp add` interactively; writes `~/.copilot/mcp-config.json`. Verified:
https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers

**GitHub Copilot coding agent** (cloud, works issues/PRs — a different
product from the CLI above): remote but **static-auth only** — there's no
browser in a cloud sandbox, so no interactive OAuth. Repo Settings → Copilot
→ MCP servers:
```json
{ "mcpServers": { "salt": { "type": "http", "url": "https://mcp.saltapp.ai/mcp", "headers": { "X-Salt-Api-Key": "COPILOT_MCP_SALT_API_KEY", "X-Salt-App-Id": "COPILOT_MCP_SALT_APP_ID" } } } }
```
(secrets must be named `COPILOT_MCP_*`) — this is Salt's legacy header path,
so only `list_salt_agents`/`list_products`/`create_product` are served. Its
own docs' Atlassian example instead bridges through `mcp-remote` as a
`"type": "local"` command when a static header is all a cloud run can offer;
the same shape works for Salt's legacy headers:
```json
{ "mcpServers": { "salt": { "type": "local", "command": "npx",
  "args": ["mcp-remote@latest", "https://mcp.saltapp.ai/mcp",
           "--header", "X-Salt-Api-Key:${SALT_API_KEY}",
           "--header", "X-Salt-App-Id:${SALT_APP_ID}"],
  "env": { "SALT_API_KEY": "$COPILOT_MCP_SALT_API_KEY", "SALT_APP_ID": "$COPILOT_MCP_SALT_APP_ID" } } } }
```
Verified: https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/configure-mcp-servers

**Amazon Q Developer CLI** — **local-stdio-only today**; the shipped schema
(`docs/agent-format.md` in aws/amazon-q-developer-cli) only defines
`command`/`args`/`env`, no `url`/`transport`/`oauth`. A remote+OAuth schema
exists only in that repo's `docs/draft/the-agent-format-2.md` — explicitly a
draft, not shipped. No bridge is documented for it either.

**Kiro** (separate product from the above) — full remote OAuth including
auto-DCR. `.kiro/settings/mcp.json` (workspace) or `~/.kiro/settings/mcp.json`
(user):
```json
{ "mcpServers": { "salt": { "url": "https://mcp.saltapp.ai/mcp" } } }
```
Verified: https://kiro.dev/docs/mcp.md , https://kiro.dev/docs/mcp/configuration.md
— "No `clientId` or `clientMetadataUrl` set → Kiro attempts Dynamic Client
Registration."

**Warp** — full remote OAuth in the interactive app/CLI. Settings → Agents →
MCP servers → Add Server → Streamable HTTP → `https://mcp.saltapp.ai/mcp`, or
file config `{ "mcpServers": { "salt": { "url": "https://mcp.saltapp.ai/mcp" } } }`.
Verified: https://docs.warp.dev/agents/capabilities/mcp — "Starting a server
without existing credentials automatically opens a browser-based
authentication flow." Warp's separate cloud agents can't complete OAuth
themselves and instead reference a server pre-authorized in the web app as a
"managed MCP installation" by `warp_id` — see
https://docs.warp.dev/platform/mcp.

## Low-code / workflow platforms

**n8n** — MCP Client Tool node: SSE Endpoint field = `https://mcp.saltapp.ai/mcp`,
Authentication → OAuth2 → new "MCP API" credential with **Use Dynamic Client
Registration** left on (default) — no manual client id/secret. Static
alternative: Header Auth / Multiple Headers Auth for the legacy pair, or
Bearer for a `sat_...` token. Verified against n8n's docs
(`integrations/builtin/cluster-nodes/sub-nodes/n8n-nodes-langchain.toolmcp.md`,
`integrations/builtin/credentials/mcp.md`) via Context7 `/n8n-io/n8n-docs`.

**Dify** — Workspace → Tools → add MCP server: Server URL
`https://mcp.saltapp.ai/mcp`, name `salt`. Authentication → **Dynamic Client
Registration** on by default → Authorize → redirect to Salt's consent
screen. Custom Headers is the static alternative for a bearer token or the
legacy pair. Verified via Context7 `/websites/dify_ai_en`
(`en/cloud/use-dify/workspace/tools`, `en/self-host/use-dify/workspace/tools`).
SSE/Streamable HTTP only, no stdio.

## Agent frameworks and SDKs

See the shared headless-auth note at the top of this page — none of these do
the interactive browser consent themselves.

**`langchain-mcp-adapters`** (`MultiServerMCPClient`):
```python
from langchain_mcp_adapters.client import MultiServerMCPClient

client = MultiServerMCPClient({
    "salt": {
        "transport": "streamable_http",
        "url": "https://mcp.saltapp.ai/mcp",
        "headers": {"Authorization": "Bearer YOUR_TOKEN"},
        # or: {"X-Salt-Api-Key": "...", "X-Salt-App-Id": "..."}
    }
})
tools = await client.get_tools()
```
`StreamableHttpConnection` also has an `auth: httpx.Auth` field as an
extension point for a real OAuth implementation, but the library ships none
built in. Verified via Context7 `/langchain-ai/langchain-mcp-adapters`.

**OpenAI Agents SDK** — Python (`headers` only, no OAuth flow):
```python
from agents.mcp import MCPServerStreamableHttp

async with MCPServerStreamableHttp(
    name="Salt MCP",
    params={"url": "https://mcp.saltapp.ai/mcp", "headers": {"Authorization": f"Bearer {token}"}},
) as server:
    agent = Agent(name="Assistant", mcp_servers=[server])
```
TypeScript (`authProvider` gives a real OAuth 2.1/PKCE/DCR handshake via the
official MCP SDK's `OAuthClientProvider`):
```ts
new MCPServerStreamableHttp({
  url: "https://mcp.saltapp.ai/mcp",
  authProvider: myOAuthClientProvider,
  requestInit: { headers: { Authorization: `Bearer ${token}` } }, // manual alternative
})
```
Verified via Context7 `/openai/openai-agents-python` and `/openai/openai-agents-js`.

**Google ADK** (`McpToolset`, `headers` only):
```python
from google.adk.tools.mcp_tool import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPConnectionParams

McpToolset(connection_params=StreamableHTTPConnectionParams(
    url="https://mcp.saltapp.ai/mcp",
    headers={"Authorization": f"Bearer {token}"},
))
```
`McpToolset` also exposes a schemed `auth_scheme`/`auth_credential`/
`header_provider` for specific providers (e.g. GCP) — no generic RFC
7591/9728 auto-discovery is documented for an arbitrary server. Verified via
Context7 `/google/adk-python`.

**Anthropic Messages API MCP connector** (`mcp_servers` param, beta):
```bash
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "anthropic-beta: mcp-client-2025-11-20" \
  -d '{
    "model": "...",
    "max_tokens": 1000,
    "messages": [{"role": "user", "content": "..."}],
    "mcp_servers": [{
      "type": "url",
      "url": "https://mcp.saltapp.ai/mcp",
      "name": "salt",
      "authorization_token": "YOUR_SALT_OAUTH_TOKEN"
    }],
    "tools": [{"type": "mcp_toolset", "mcp_server_name": "salt"}]
  }'
```
`authorization_token` takes a bearer token you already hold — the connector
supports OAuth-authenticated servers but doesn't run the browser flow itself,
so obtain the `sat_...` token via one of the interactive clients above first.
Verified: https://platform.claude.com/docs/en/agents-and-tools/mcp-connector
(beta header `mcp-client-2025-11-20`, superseding the deprecated
`mcp-client-2025-04-04`).

**Microsoft Agent Framework / Semantic Kernel** (`MCPStreamableHttpPlugin`,
`headers` only):
```python
from semantic_kernel.connectors.mcp import MCPStreamableHttpPlugin

plugin = MCPStreamableHttpPlugin(
    name="SaltMcp",
    url="https://mcp.saltapp.ai/mcp",
    headers={"Authorization": f"Bearer {token}"},
)
async with plugin:
    kernel.add_plugin(plugin)
```
Its docs recommend fronting an OAuth-protected remote server with an API
gateway rather than doing PKCE/DCR in-process. Verified via Context7
`/microsoft/semantic-kernel` (`semantic_kernel/connectors/mcp.py`).

**Vercel AI SDK** (`createMCPClient`, renamed from
`experimental_createMCPClient`, now in `@ai-sdk/mcp`):
```ts
import { createMCPClient } from '@ai-sdk/mcp';

const mcpClient = await createMCPClient({
  transport: {
    type: 'http',
    url: 'https://mcp.saltapp.ai/mcp',
    headers: { Authorization: `Bearer ${token}` }, // static, or:
    authProvider: myOAuthClientProvider,           // full OAuth 2.1/PKCE/DCR
  },
});
```
Verified via Context7 `/websites/ai-sdk_dev` (`ai-sdk-core/mcp-tools`,
`reference/ai-sdk-core/create-mcp-client`). Transport `type` is `'http'`, not
`'streamable_http'`.

**Mastra** (`MCPClient`, `requestInit.headers` static; a custom `fetch` hook
is the extension point for anything dynamic):
```ts
import { MCPClient } from '@mastra/mcp'

new MCPClient({
  id: 'salt-mcp-client',
  servers: {
    salt: {
      url: new URL('https://mcp.saltapp.ai/mcp'),
      requestInit: { headers: { Authorization: `Bearer ${token}` } },
    },
  },
})
```
Verified via Context7 `/mastra-ai/mastra` (`docs/src/content/en/docs/connections/mcp.mdx`,
`reference/tools/mcp-client.mdx`).

## Not verified yet

- **ChatGPT's exact plan/workspace gate** for custom connectors — confirmed
  OAuth-capable and that Developer mode must be enabled
  (https://developers.openai.com/api/docs/mcp), but the specific plan tier
  requirement wasn't stated on that page.
- **JetBrains AI Assistant's OAuth behavior** — the doc shows no auth field
  at all (https://www.jetbrains.com/help/ai-assistant/mcp.html), so whether
  it can complete Salt's flow isn't confirmed either way.
- **Continue's OAuth behavior** — same gap
  (https://docs.continue.dev/customize/deep-dives/mcp).
