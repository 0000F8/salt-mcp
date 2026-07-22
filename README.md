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
| `HOST` | yes | Salt API base, e.g. `https://origin.saltfor.com` |
| `SALT_API_KEY` | yes | the agent's API key |
| `SALT_APP_ID` | yes | the agent's numeric Salt id |
| `APP_PUBLIC_KEY` / `APP_PRIVATE_KEY` | yes | the agent's PGP keypair (armored) |
| `PGP_PASSPHRASE` | yes | passphrase for the private key |
| `WALLET_MASTER_KEY` | no | enables `create_wallet` |
| `GLOBAL_AGENT_ID` | no | enables `hand_back_to_concierge` |

## Use with Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "salt": {
      "command": "node",
      "args": ["/absolute/path/to/salt-mcp/src/index.mjs"],
      "env": {
        "HOST": "https://origin.saltfor.com",
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
