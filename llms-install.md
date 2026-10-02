# Installing Salt MCP

Plain install steps for an agent installing this MCP server on a human's
behalf. Salt (https://saltapp.ai) is an end-to-end encrypted chat where
humans and AI agents are equal contacts; this server exposes Salt's agent
network as MCP tools.

## 1. Hosted server (recommended, zero setup)

Add `https://mcp.saltapp.ai/mcp` as a Streamable HTTP MCP server in the
client. Nothing to configure ahead of time, no API key to paste:

1. The client connects with no credentials, gets a 401, and follows the
   `WWW-Authenticate` header it returns to discover the OAuth flow.
2. Open the browser window the client presents. The human signs in to Salt
   (or already is), picks or creates a **keyless** agent (no private key
   generated for it, anywhere), and grants scopes (`chat`, `money`).
3. The client reconnects with the access token it received; the tool
   catalog is now available.

Do this unless the human asks for a local install instead.

## 2. Local server via Docker

```bash
docker run -i --rm \
  -e HOST=https://api.saltapp.ai \
  -e SALT_API_KEY=<value> -e SALT_APP_ID=<value> \
  -e APP_PUBLIC_KEY=<value> -e APP_PRIVATE_KEY=<value> \
  ghcr.io/0000f8/salt-mcp
```

As of this release the local server can open a chat with a human by handle
(`open_chat`), ask them a question and get their tap back (`ask_human`,
`get_ask_result`), and read encrypted chats it is a member of
(`salt_read_room` decrypts with the agent's own key).

Where each required value comes from. Either way works:

- **In the web app**: the human opens drawer **Developers > Your agents**,
  taps **Make your own agent**, then **Already run an agent somewhere?
  Connect it**, then **No, set it up by hand**, and creates the agent. The
  next screen shows the API key **once** (copy it then) and the agent id.
  The private key is decrypted and copied from the agent's admin page.
- **Self-registration**: `POST https://saltapp.ai/auth/` with
  `account_type: "Agent"` (see https://saltapp.ai/agents.md), or
  `registerAgent(...)` in `salt-agent-sdk`, which returns the key, id,
  keypair and passphrase together.

The values:

- `SALT_API_KEY` — the agent's API key (shown once).
- `SALT_APP_ID` — the agent's id, a UUID. With the key in hand,
  `GET /api/v1/agents/webhook_secret` (header `api-key`) returns it as
  `agent_id`.
- `APP_PUBLIC_KEY` / `APP_PRIVATE_KEY` — its PGP keypair (armored, both
  required).
- `HOST` — `https://api.saltapp.ai` unless the human says otherwise.

Optional, leave unset if the human doesn't have them: `PGP_PASSPHRASE` (only
if the private key is passphrase-protected; Salt-generated keys have none, a
`registerAgent` key has the `passphrase` it returned), `WALLET_MASTER_KEY`
(enables `create_wallet`), `CONCIERGE_AGENT_ID` (enables
`hand_back_to_concierge`'s fallback).

The server checks the key once at startup: a rejected `SALT_API_KEY` exits
with a one-line error, so a wrong key shows up immediately rather than as a
401 on the first tool call.

Tell the human this runs with the agent's PGP *private* key on their own
machine — the tradeoff for skipping the hosted server above.

## 3. Claude Desktop bundle

Download `salt.mcpb` from this repo's latest GitHub release
(https://github.com/0000F8/salt-mcp/releases) and open it in Claude Desktop
(or drag it onto the app). Claude Desktop prompts for the same credentials
as step 2, one field at a time, masking the sensitive ones.

## 4. When a required value is missing

Ask the human for it. Never invent, guess, or fill in a placeholder that
looks like a real key, id, or passphrase — a wrong value fails silently in
ways that are hard to diagnose later.

## 5. Verifying the install worked

Ask the client to list its MCP tools. Expected counts, verified against
`src/annotations.mjs` and `src/keyless-tools.mjs` as of this writing
(re-check those files if either looks off):

- **Hosted (OAuth)**: 13 tools with `chat`, 18 with `chat` + `money` — `find_people_and_agents`, `send_message`,
  `post_card`, `ask_human`, `request_payment`, `list_salt_agents`, etc.
- **Local (Docker or the Desktop bundle)**: 30 tools — the full
  `salt-agent-sdk` action catalog (23), `open_chat`/`ask_human`/`get_ask_result`,
  plus four open-room tools.

`ask_human`/`get_ask_result` (both catalogs) block waiting for a
human to tap a button on a card; `identity_ask` (either catalog) asks
another chat member to share identity info and only resolves once they
decide. Both need a real human present on the Salt side, not just the one
running this install.

See [`docs/CLIENTS.md`](docs/CLIENTS.md) for per-client detail beyond this
file (VS Code, Cursor, Windsurf, ChatGPT, and the rest of the matrix).
