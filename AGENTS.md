# AGENTS.md

Instructions for an AI coding agent working ON this repo (`salt-mcp` itself).
If you're looking for how to work AS a Salt agent using these tools, that's
[skills/salt/SKILL.md](skills/salt/SKILL.md), not this file.

## What this repo is

A thin MCP (Model Context Protocol) adapter over
[`salt-agent-sdk`](https://github.com/0000F8/salt-agent-sdk)'s action layer.
It has almost no logic of its own: the tool catalog comes straight from
`salt-agent-sdk`'s `createActions(...).definitions`/`.execute(...)`. Two
runtime entry points:

- `src/index.mjs` — local, stdio, one env-configured Salt agent identity.
  Holds the agent's PGP private key; never leaves the user's machine.
- `src/http.mjs` — hosted, Streamable HTTP, per-request credentials,
  deliberately scoped to a small set of chat-free, api-key-only tools (see
  `HOSTED_TOOLS` in that file). Runs in production at `https://mcp.saltapp.ai/mcp`
  (see `salt-deploy`'s `infra/mcp.tf` for the real deployed path/health check).
- `src/annotations.mjs` — the one place MCP tool `annotations`
  (title/readOnlyHint/destructiveHint/idempotentHint/openWorldHint) are
  decided for every tool in both servers above.

Distribution surfaces live alongside the server, all in this one repo:
`server.json` (MCP Registry), `.claude-plugin/` + `.mcp.json` +
`skills/salt/` (Claude Code plugin — the plugin's root IS this repo's root),
`manifest.json` (Claude Desktop MCPB bundle).

## Setup

```bash
npm install
```

This is a real npm package with a real published dependency
(`salt-agent-sdk`). If you need to test against an UNPUBLISHED local build of
the SDK (e.g. a new SDK version not on npm yet), use
`npm install ../salt-agent-sdk` temporarily — this rewrites `package.json`'s
dependency to a `file:` reference. **Always restore the semver range
(e.g. `^0.7.1`) before committing.** Never commit a `file:`-referenced
dependency.

## Test

```bash
npm test
```

Runs `node --test tests/*.test.mjs`:

- `tests/annotations.test.mjs` — builds the REAL action list from the
  installed `salt-agent-sdk` and fails if any tool is missing an entry in
  `src/annotations.mjs`, or if a read/list tool isn't `readOnlyHint: true`,
  or if a money/message/hand-off tool isn't `destructiveHint: true`. A new
  SDK action needs an annotation entry here before it can ship.
- `tests/server-json.test.mjs` — validates `server.json` against the
  vendored official schema (`schemas/server.schema.json`) and checks the
  specific shape (npm package env vars, hosted remote's required secret
  headers).

Run the whole suite before every commit; there's no faster feedback loop
than `npm test` here, and it's fast (well under a second).

## Conventions

- **ESM only** (`"type": "module"`). Files are `.mjs`.
- **stdio hygiene**: `src/index.mjs` and anything it imports must NEVER
  write to stdout — that's the MCP protocol channel. Use `console.error`
  (aliased as `log` in `index.mjs`) for diagnostics.
- **A new SDK action needs**, in this order: (1) an entry in
  `src/annotations.mjs`'s `TOOL_ANNOTATIONS` map, (2) if it's chat-free and
  api-key-only, a decision on whether it joins `HOSTED_TOOLS` in
  `src/http.mjs`, (3) `npm test` passing.
- **`server.json`, `manifest.json`, `.claude-plugin/plugin.json`, and
  `package.json`'s own `version`** should move together at release time —
  they currently don't share a single source of truth, so a version bump
  touches all four by hand.
- **Never commit real Salt credentials.** Every example in this repo
  (README, tests) uses placeholder values.
- Test-only Salt accounts, anywhere they're created (not applicable in this
  repo's own tests, which never call the real Salt API), are named
  `SALT-…` / `salt-…@example.test`, matching the workspace-wide convention.

## PR / commit guidance

Keep `src/annotations.mjs` and `tests/annotations.test.mjs` in the same
commit as any change to the tool catalog they describe. Run `npm test`
before every commit — it's the whole CI story this repo has right now.
