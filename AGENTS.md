# AGENTS.md

Instructions for an AI coding agent working ON this repo (`salt-mcp` itself).
If you're looking for how to work AS a Salt agent using these tools, that's
[skills/salt/SKILL.md](skills/salt/SKILL.md), not this file.

## What this repo is

An MCP (Model Context Protocol) adapter for [Salt](https://saltapp.ai), an
end-to-end encrypted chat where humans and AI agents are equal contacts. It's
a thin layer over
[`salt-agent-sdk`](https://github.com/0000F8/salt-agent-sdk)'s action layer
and has almost no logic of its own: the tool catalog comes straight from
`salt-agent-sdk`'s `createActions(...).definitions`/`.execute(...)`. Two
runtime entry points:

- `src/index.mjs` — local, stdio, one env-configured Salt agent identity.
  Holds the agent's PGP private key; never leaves the user's machine. Exposes
  the full SDK-derived catalog plus the four open-room tools (`src/room-tools.mjs`).
- `src/http.mjs` — hosted, Streamable HTTP, per-request credentials. Runs in
  production at `https://mcp.saltapp.ai/mcp` (see `salt-deploy`'s
  `infra/mcp.tf` for the deployed path/health check). Speaks two auth models
  on the same endpoint: legacy `X-Salt-Api-Key`/`X-Salt-App-Id` headers (a
  small, chat-free, api-key-only slice — `HOSTED_TOOLS` in that file), and
  OAuth bearer tokens naming a **keyless** agent (no private key anywhere),
  which get the larger `src/keyless-tools.mjs` catalog instead.
- `src/annotations.mjs` — the one place MCP tool `annotations`
  (title/readOnlyHint/destructiveHint/idempotentHint/openWorldHint) are
  decided for every SDK-derived tool exposed by either server above.

Distribution surfaces live alongside the server, all in this one repo:
`server.json` (MCP Registry), `.claude-plugin/` + `.mcp.json` +
`skills/salt/` (Claude Code plugin — the plugin's root IS this repo's root),
`manifest.json` (Claude Desktop MCPB bundle, built to `salt.mcpb`),
`Dockerfile` (public GHCR image), and `llms-install.md` (agent-installer
instructions — see "Publishing" below).

## Commands

Run from the repo root.

```bash
npm install    # setup
npm test       # node --test tests/*.test.mjs -- the whole CI story here
npm run bundle # build the Claude Desktop bundle -> salt.mcpb (npx @anthropic-ai/mcpb pack)
```

There is no `lint` script and no ESLint/Prettier config in this repo —
verified against `package.json` and the repo root, don't invent one.

`npm test` runs two files:

- `tests/annotations.test.mjs` — builds the REAL action list from the
  installed `salt-agent-sdk` and fails if any tool is missing an entry in
  `src/annotations.mjs`, or if a read/list tool isn't `readOnlyHint: true`,
  or if a money/message/hand-off tool isn't `destructiveHint: true`. A new
  SDK action needs an annotation entry here before it can ship.
- `tests/server-json.test.mjs` — validates `server.json` against the
  vendored official schema (`schemas/server.schema.json`) and checks the
  specific shape (npm package env vars, hosted remote's required secret
  headers).

Run the whole suite before every commit (181 tests as of this writing, well
under a few seconds).

**`npm install` alone can fail** (`ETARGET: No matching version found for
salt-agent-sdk@...`) on a clean checkout: `salt-agent-sdk`'s npm registry
listing is stuck at an old `0.1.0` (see "Publishing" below — same situation
as this repo's own npm listing), well behind the sibling repo's real version.
If that happens, install the local sibling checkout instead:
`npm install ../salt-agent-sdk` — this rewrites `package.json`'s dependency
to a local reference. **Always restore the original semver range in
`package.json`/`package-lock.json` before committing** (`git checkout --
package.json package-lock.json` if you made no other change to them). Never
commit a `file:`-referenced dependency.

## Layout

- `src/index.mjs` / `src/http.mjs` — the two server entry points (above).
- `src/annotations.mjs` — MCP annotations for every SDK action; the gate a
  new SDK action must pass before it's exposed at all.
- `src/keyless-tools.mjs` — the hosted OAuth path's own, larger tool catalog
  (messaging, cards, `ask_human`, payments) for a keyless agent identity;
  paired with `src/salt-bearer-client.mjs` (the REST client for that path).
- `src/room-tools.mjs` — the four open-room tools (not SDK actions), shared
  verbatim by both servers.
- `skills/salt/SKILL.md` — the Agent Skill teaching an agent how to *use*
  these tools well (delegate vs. consult vs. hand off, card blocks, the
  privacy model). Not this file's concern.
- `docs/CLIENTS.md` — the full per-MCP-client install matrix.

## Rules that bite

- **ESM only** (`"type": "module"`). Files are `.mjs`.
- **stdio hygiene**: `src/index.mjs` and anything it imports must NEVER
  write to stdout — that's the MCP protocol channel. Use `console.error`
  (aliased as `log` in `index.mjs`) for diagnostics.
- **A new SDK action needs**, in this order: (1) an entry in
  `src/annotations.mjs`'s `TOOL_ANNOTATIONS` map, (2) if it's chat-free and
  api-key-only, a decision on whether it joins `HOSTED_TOOLS` in
  `src/http.mjs`, (3) `npm test` passing. This repo has already shipped this
  gap twice against real `salt-agent-sdk` releases (identity actions landing
  two, then three, tools ahead of this map) — `tests/annotations.test.mjs`
  is what catches it, never trust the README's own tool count (see below).
- **A card tool waits on its OWN card, never the shared outbox.** The
  socket-mode outbox (`GET /api/v1/agent/updates`) has exactly ONE
  forward-only cursor per agent; any `after=` passed to it permanently
  advances that agent's server-side ack, silently stranding another
  consumer's backlog. `ask_human`/`get_ask_result` (`src/keyless-tools.mjs`)
  used to drain that outbox and learned the hard way: they now poll
  `GET /api/v1/cards/:id` (that card's own interaction log) instead, which
  shares nothing with any other poller. If you add another tool that waits
  for a human's tap, follow that pattern, not the outbox.
- **A posted card's id doesn't come back as a top-level `id`.**
  `POST /api/v1/cards` responds referencing the chat MESSAGE it created —
  read `resource_id` (the card) and `id`/`message_id` (the message), never
  assume a bare `id` is the card's own id (`postCardTool`/`askHuman` in
  `src/keyless-tools.mjs` both do `result?.resource_id ?? result?.id`).
- **A chat's `encrypted` flag is nested under `session`**
  (`chat.session.encrypted`), not top-level — see `src/room-tools.mjs`'s
  `encrypted: session.encrypted !== false` and its header comment on why
  this tool never guesses.
- **An encrypted chat refuses a plaintext body outright.** Plain-text
  helpers (`salt_read_room` and friends) only work on genuinely open rooms;
  `sendMessage` in `src/keyless-tools.mjs` always PGP-encrypts to every
  member's public key first. Don't add a "just post plain text" shortcut
  that assumes a chat is open — check `session.encrypted` first.
- **Test fakes must model salt-api's ACTUAL controller response shape**,
  not this repo's assumption about it — the `resource_id`/`message_id` and
  `session.encrypted` gotchas above are exactly the kind of thing a fake
  that "looks reasonable" gets wrong. `tests/keyless-tools.test.mjs` and
  `tests/room-tools.test.mjs` are the reference for what a real response
  looks like.
- Every REST route this repo's tools call (`api/v1/cards`, `api/v1/chats`,
  `api/v1/messages`, `api/v1/agents`, `api/v1/search`,
  `api/v1/transfer_requests`, `api/v1/products`) must also be a routable
  entry on salt-api's `Oauth::MCP_ALLOWLIST` for the OAuth/keyless path to
  reach it — that allowlist is deny-by-default and every entry must be a
  real, currently-routable action (never exempted "for now"; salt-api's own
  CLAUDE.md and `oauth_mcp_allowlist_test.rb` say why). If you add a tool
  that calls a new salt-api route, that route needs an allowlist entry on
  the salt-api side before the OAuth path can use it.
- **`server.json`, `manifest.json`, `.claude-plugin/plugin.json`, and
  `package.json`'s own `version`** should move together at release time —
  they currently don't share a single source of truth, so a version bump
  touches all four by hand.
- **Never commit real Salt credentials.** Every example in this repo
  (README, tests) uses placeholder values.
- Test-only Salt accounts, anywhere they're created (not applicable in this
  repo's own tests, which never call the real Salt API), are named
  `SALT-…` / `salt-…@example.test`, matching the workspace-wide convention.

## Where the truth is

- `https://saltapp.ai/api/openapi.json` — salt-api's real, current route
  shapes; more current than any of this repo's own paraphrases.
- `https://saltapp.ai/agents.md` — the agent-facing manifest for Salt itself.
- `https://mcp.saltapp.ai/mcp` — the hosted server this repo's `src/http.mjs`
  runs in production.
- [`docs/CLIENTS.md`](docs/CLIENTS.md) — the full, client-by-client install
  matrix (this repo's own).

## Publishing

- **npm has a stale `salt-mcp@0.1.0`.** It is ancient and far behind this
  repo's current version — do not treat it as current, safe to install
  standalone, or a reference for docs. The Docker image and the `.mcpb`
  bundle (below) are built straight from this repo's checked-out source, not
  from that npm listing. The same staleness applies to the `salt-agent-sdk`
  dependency itself (see "Commands" above).
- `ghcr.io/0000f8/salt-mcp` — a public, multi-arch container built by
  `.github/workflows/image.yml` on every GitHub release.
- `salt.mcpb` — the Claude Desktop bundle, built with `npm run bundle`
  (`npx @anthropic-ai/mcpb pack . salt.mcpb`) and attached to GitHub
  releases; not committed (`*.mcpb` is gitignored, rebuilt on demand).
- `server.json` — describes this server for the official
  [MCP Registry](https://registry.modelcontextprotocol.io) under
  `ai.saltapp/salt`. Validate with `node scripts/validate-server-json.mjs`.

## PR / commit guidance

Keep `src/annotations.mjs` and `tests/annotations.test.mjs` in the same
commit as any change to the tool catalog they describe. Run `npm test`
before every commit — it's the whole CI story this repo has right now.
