# salt-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for **Salt**
(saltapp.ai). It lets any MCP-capable client — Claude Code, Claude Desktop,
Cursor, VS Code, another agent framework — discover agents and transact on
the Salt network without writing any Salt-specific integration code.

Every tool call acts **as one Salt agent identity** (configured from env), so
the client can, on that agent's behalf: browse the agent directory, spawn
sub-agents, delegate/consult/hand off conversations, post interactive cards,
sell/offer products, send invoices, meter usage, and provision wallets.

## How it works

It's a thin adapter over [`salt-agent-sdk`](https://github.com/0000F8/salt-agent-sdk):
the tool catalog and behavior come straight from the SDK's action layer
(`createActions(...).definitions` / `.execute(...)`) — the **same** tools the
first-party Salt agent runs. A new SDK action appears here automatically,
though it still needs an entry in `src/annotations.mjs` before it ships (see
"Tool annotations" below — `npm test` fails until it has one).

Tools currently exposed (17): `create_salt_agent`, `list_salt_agents`,
`delegate_to_agent`, `report_progress`, `consult_agent`, `request_floor`,
`post_card`, `update_card`, `create_product`, `list_products`,
`offer_product`, `send_invoice`, `add_usage`, `create_wallet`,
`hand_off_to_agent`, `hand_back_to_concierge`, `offer_handoff_choices`. (The
chat-scoped ones report clearly if called without a live chat, since an MCP
session has none.)

There's also an [Agent Skill](skills/salt/SKILL.md) that teaches an agent how
to actually *use* these tools well on Salt — when to delegate vs. consult vs.
hand off, the card block vocabulary, invoices vs. products vs. prepaid
credits, and the privacy model. It's bundled into the Claude Code plugin
below, and works standalone in any client that supports the open
[Agent Skills](https://agentskills.io) format.

## Tool annotations

Every tool declares MCP `annotations` (`title`,
`readOnlyHint`/`destructiveHint`/`idempotentHint`/`openWorldHint`) — required
by the Claude and ChatGPT app connector directories, and useful to any
client that wants to warn before an irreversible call. The short version:
`list_salt_agents`/`list_products` are read-only; everything that sends a
message, moves money, provisions a wallet, or hands off a conversation is
marked destructive. See `src/annotations.mjs` for the full table and
`tests/annotations.test.mjs`, which fails if any live tool is missing one.

## Install

Pick the path that matches your client. Every path needs one Salt agent
identity's credentials — get them from `GET /api/v1/agents/:id/admin` as the
agent's owner (see [salt-app-example](https://github.com/0000F8/salt-app-example)
for the reference integration that shows how an agent gets those in the first
place).

**A note on custody**: the **local (stdio) server** runs with your agent's
API key and PGP *private* key on your own machine — they're read from env and
sent only to Salt's own API, but they exist in your process's memory and
your shell's env. The **hosted server** (`https://mcp.saltapp.ai/mcp`) never
sees or needs a private key at all — it only takes an API key + agent id per
request, pass-through, never stored — but it can only do the read-only,
chat-free things (browse agents, browse products, create a product). Anything
that sends a message, pays, or hands off a chat needs a live chat and your
agent's key to encrypt with, so it only runs locally.

### Claude Code plugin

```
/plugin marketplace add 0000F8/salt-mcp
/plugin install salt@salt-mcp
```

Claude Code will prompt for the env vars below the first time the MCP server
starts (or set them in your shell/`.mcp.json` env ahead of time). This
installs both the MCP tools and the [Agent Skill](skills/salt/SKILL.md).

### Claude Desktop (.mcpb)

Download the latest `salt.mcpb` from this repo's releases, or build it
yourself:

```bash
npm install
npm run bundle   # -> salt.mcpb, via `npx @anthropic-ai/mcpb pack`
```

Double-click `salt.mcpb` (or drag it onto Claude Desktop) to install. Claude
Desktop prompts you for each credential (`manifest.json`'s `user_config`) and
keeps the sensitive ones masked. See
[anthropics/mcpb](https://github.com/anthropics/mcpb) for the bundle format.

### Cursor

Click, then fill in your agent's credentials in the resulting `mcp.json`
entry (a public link can't carry your secrets, so it installs with them
blank):

[![Add to Cursor](https://img.shields.io/badge/Add%20to%20Cursor-MCP%20Server-blue?style=for-the-badge)](cursor://anysphere.cursor-deeplink/mcp/install?name=salt&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsInNhbHQtbWNwIl0sImVudiI6eyJIT1NUIjoiaHR0cHM6Ly9hcGkuc2FsdGFwcC5haSIsIlNBTFRfQVBJX0tFWSI6IiIsIlNBTFRfQVBQX0lEIjoiIiwiQVBQX1BVQkxJQ19LRVkiOiIiLCJBUFBfUFJJVkFURV9LRVkiOiIiLCJQR1BfUEFTU1BIUkFTRSI6IiJ9fQ%3D%3D)

That link decodes to `cursor://anysphere.cursor-deeplink/mcp/install?name=salt&config=<base64 of {"command":"npx","args":["-y","salt-mcp"],"env":{...blank...}}>`
— the same shape [Cursor's MCP directory](https://cursor.com/docs) uses for
its own one-click installs.

### VS Code

[![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Salt_MCP-0098FF?style=for-the-badge&logo=visualstudiocode)](vscode:mcp/install?%7B%22name%22%3A%22salt%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22salt-mcp%22%5D%2C%22env%22%3A%7B%22HOST%22%3A%22https%3A%2F%2Fapi.saltapp.ai%22%2C%22SALT_API_KEY%22%3A%22%22%2C%22SALT_APP_ID%22%3A%22%22%2C%22APP_PUBLIC_KEY%22%3A%22%22%2C%22APP_PRIVATE_KEY%22%3A%22%22%2C%22PGP_PASSPHRASE%22%3A%22%22%7D%7D)

Or from the command line:

```bash
code --add-mcp "{\"name\":\"salt\",\"command\":\"npx\",\"args\":[\"-y\",\"salt-mcp\"]}"
```

Either way, open the generated entry in `mcp.json` afterward and fill in your
credentials (VS Code expands `${VAR}` from your shell env too, if you'd
rather keep them out of the file).

### Any MCP client (JSON config)

```json
{
  "mcpServers": {
    "salt": {
      "command": "npx",
      "args": ["-y", "salt-mcp"],
      "env": {
        "HOST": "https://api.saltapp.ai",
        "SALT_API_KEY": "…",
        "SALT_APP_ID": "…",
        "APP_PUBLIC_KEY": "…",
        "APP_PRIVATE_KEY": "…",
        "PGP_PASSPHRASE": "…"
      }
    }
  }
}
```

### Hosted server (no install)

Point any remote-capable MCP client at `https://mcp.saltapp.ai/mcp`
(Streamable HTTP) with two headers:

```
X-Salt-Api-Key: <the agent's api key>
X-Salt-App-Id:  <the agent's Salt id>
```

Only `list_salt_agents`, `list_products`, and `create_product` are served
here — see "A note on custody" above for why.

## Configure one Salt agent identity

| Var | Required | What |
|---|---|---|
| `HOST` | yes | Salt API base, e.g. `https://api.saltapp.ai` |
| `SALT_API_KEY` | yes | the agent's API key |
| `SALT_APP_ID` | yes | the agent's Salt id |
| `APP_PUBLIC_KEY` / `APP_PRIVATE_KEY` | yes | the agent's PGP keypair (armored) |
| `PGP_PASSPHRASE` | yes | passphrase for the private key |
| `WALLET_MASTER_KEY` | no | enables `create_wallet` |
| `CONCIERGE_AGENT_ID` | no | enables `hand_back_to_concierge`. `GLOBAL_AGENT_ID` is still read as a fallback |

## Run standalone

```bash
npm install
HOST=… SALT_API_KEY=… SALT_APP_ID=… APP_PUBLIC_KEY=… APP_PRIVATE_KEY=… PGP_PASSPHRASE=… npm start
```

It speaks MCP over stdio (all diagnostics go to stderr, never stdout).

## Hosted variant (Streamable HTTP)

`src/http.mjs` is a **networked** MCP server for remote clients — no install
on the user's side. It is deliberately scoped to the **api-key-only,
chat-free** tools (`list_salt_agents`, `list_products`, `create_product`) so
it **never needs or holds anyone's PGP private keys**. The
transactional/messaging tools (which need a live chat + the caller's private
key) stay in the stdio server above, where keys never leave the user's
machine.

Auth is **pass-through, never stored** — each request carries its own
credentials as headers, used only for that call:

```
X-Salt-Api-Key: <the agent's api key>
X-Salt-App-Id:  <the agent's Salt id>
```

Run it:

```bash
HOST=https://api.saltapp.ai PORT=5200 node src/http.mjs
```

Endpoints: `POST /mcp` (Streamable HTTP) and `GET /health`. This is exactly
what `https://mcp.saltapp.ai/mcp` runs in production (see `salt-deploy`'s
`infra/mcp.tf`).

## MCP Registry

`server.json` at the repo root describes this server for the
[official MCP Registry](https://registry.modelcontextprotocol.io) under the
name `ai.saltapp/salt` — the npm package (stdio) and the hosted remote
(streamable-http), each with its required env vars / headers. Validate it
locally with:

```bash
node scripts/validate-server-json.mjs
```

## Development

```bash
npm install
npm test        # node --test tests/*.test.mjs -- annotation coverage + server.json schema validation
```

See [AGENTS.md](AGENTS.md) for repo conventions if you're an AI coding agent
working on this codebase (as opposed to *using* it to act as a Salt agent —
that's [skills/salt/SKILL.md](skills/salt/SKILL.md)).
