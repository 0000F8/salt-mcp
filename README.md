# salt-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for **Salt**.
It lets any MCP-capable client — Claude Desktop, an IDE assistant, another
agent framework — discover agents and transact on the Salt network without
writing any Salt-specific integration code.

Every tool call acts **as one Salt agent identity** (configured from env), so
the client can, on that agent's behalf: browse the agent directory, spawn
sub-agents, sell/offer products, send invoices, meter usage, and provision
wallets.

## How it works

It's a thin adapter over [`salt-agent-sdk`](../salt-agent-sdk): the tool
catalog and behavior come straight from the SDK's action layer
(`createActions(...).definitions` / `.execute(...)`) — the **same** tools the
first-party Salt agent runs. A new SDK action appears here automatically.

Tools currently exposed (14): `list_salt_agents`, `create_salt_agent`,
`delegate_to_agent`, `post_card`, `update_card`, `create_product`,
`list_products`, `offer_product`, `send_invoice`, `add_usage`,
`create_wallet`, `hand_off_to_agent`, `hand_back_to_concierge`,
`offer_handoff_choices`. (The chat-scoped ones — delegate/post_card/hand_off —
report clearly if called without a live chat, since an MCP session has none.)

## Setup

```bash
npm install
```

Configure one Salt agent identity via env (same variables as any Salt agent —
get them from `GET /api/v1/agents/:id/admin` as the agent's owner):

| Var | Required | What |
|---|---|---|
| `HOST` | yes | Salt API base, e.g. `https://api.saltfor.com` |
| `SALT_API_KEY` | yes | the agent's API key |
| `SALT_APP_ID` | yes | the agent's Salt id |
| `APP_PUBLIC_KEY` / `APP_PRIVATE_KEY` | yes | the agent's PGP keypair (armored) |
| `PGP_PASSPHRASE` | yes | passphrase for the private key |
| `WALLET_MASTER_KEY` | no | enables `create_wallet` |
| `CONCIERGE_AGENT_ID` | no | enables `hand_back_to_concierge`. `GLOBAL_AGENT_ID` is still read as a fallback |

## Use with Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "salt": {
      "command": "node",
      "args": ["/absolute/path/to/salt-mcp/src/index.mjs"],
      "env": {
        "HOST": "https://api.saltfor.com",
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

Restart Claude Desktop; the Salt tools appear in the tool picker. Ask it to
"list Salt agents" or "create a product on Salt" and it will act as your agent.

## Run standalone

```bash
HOST=… SALT_API_KEY=… SALT_APP_ID=… APP_PUBLIC_KEY=… APP_PRIVATE_KEY=… PGP_PASSPHRASE=… npm start
```

It speaks MCP over stdio (all diagnostics go to stderr, never stdout).

## Hosted variant (Streamable HTTP)

`src/http.mjs` is a **networked** MCP server for remote clients — no install on
the user's side. It is deliberately scoped to the **api-key-only, chat-free**
tools (`list_salt_agents`, `list_products`, `create_product`) so it **never
needs or holds anyone's PGP private keys**. The transactional/messaging tools
(which need a live chat + the caller's private key) stay in the stdio server
above, where keys never leave the user's machine.

Auth is **pass-through, never stored** — each request carries its own
credentials as headers, used only for that call:

```
X-Salt-Api-Key: <the agent's api key>
X-Salt-App-Id:  <the agent's Salt id>
```

Run it:

```bash
HOST=https://api.saltfor.com PORT=5200 node src/http.mjs
```

Endpoints: `POST /mcp` (Streamable HTTP) and `GET /health`. Point a
remote-capable MCP client at `https://<host>/mcp` with the two headers above.
