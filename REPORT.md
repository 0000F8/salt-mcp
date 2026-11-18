# fr-mcp report (salt-mcp, branch feat/fr-mcp)

## Files changed
- src/browser-tools.mjs: ACTIONS gains locate, route, download, cookies, clipboard; salt_browser_step description lists the new args (eval `world`, dialog `mode`); new REASONS.needs_permission; thin tools salt_browser_locate (read-only), _route, _download, _cookies; NAMED_ACTION entries; a download result is returned as text (mime, size) plus an MCP embedded `resource` content block (`{uri, mimeType, blob}`), the file analogue of image content. Accepts the extension's `{data_base64, mime, size}` and the SDK's `file {mime, base64, size}` shape. `save: true` results (`saved: true`) come back as plain JSON.
- README.md: tool table rows, section text, count 55 -> 59. llms-install.md and skills/salt/SKILL.md counts 55 -> 59.
- tests/browser-tools.test.mjs: size 15; new test for annotations, step args, resource content, save form, needs_permission.

## Annotations
The thin browser tools carry their annotations in BROWSER_TOOL_METADATA (ANN), not in TOOL_ANNOTATIONS (that map is keyed by SDK action names; only browser_step/browser_grants are there, unchanged and covering `clipboard`, `route`, etc. through the generic step). locate: read-only. route, cookies: not read-only, destructive. download: not read-only (static hint cannot vary with `save`), non-destructive. Tests/annotations.test.mjs passes unchanged.

## SDK dependency
package.json pins salt-agent-sdk ^0.29.0; salt-mcp does NOT consume the SDK's browser action list for these tools (it keeps its own ACTIONS list, extended here), so it works with any SDK version. fr-sdk-REPORT.md did not exist when I finished; nothing here imports new SDK exports. Release: orchestrator bumps salt-mcp version (and manifest.json/server.json/lockfile) and, optionally, the SDK pin once the new SDK is published.

## Tests
node --test tests/browser-tools.test.mjs tests/annotations.test.mjs tests/readme-tools.test.mjs tests/local-tools.test.mjs tests/landing.test.mjs tests/server-json.test.mjs tests/structured-content.test.mjs tests/keyless-tools.test.mjs
-> tests 104, pass 102, fail 2. The 2 failures (README stated count / README table vs code count) fail identically on main before my change (55 !== 54): the installed SDK in the symlinked node_modules lacks one README-listed tool (show_screen). My change keeps the delta the same (59 vs 58).

## Release note
salt-mcp: four new browser tools (locate, route, download returning an MCP resource blob, cookies) and `clipboard` plus new eval/dialog args through salt_browser_step.

## Not done
No live browser check; no version bump or publish.
