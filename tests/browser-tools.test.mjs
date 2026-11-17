// The browser tools (src/browser-tools.mjs): a mocked Salt, real openpgp sealing. The local server lists them, the
// keyless catalog never does, and a sealed result is opened with the agent's own key.

import { test } from "node:test";
import assert from "node:assert/strict";
import pkg from "salt-agent-sdk";
import { createLocalHandlers, buildLocalServer } from "../src/index.mjs";
import { createDecryptor } from "../src/local-decrypt.mjs";
import { BROWSER_TOOL_METADATA, BROWSER_TOOL_NAMES, runBrowserTool } from "../src/browser-tools.mjs";
import { TOOL_ANNOTATIONS } from "../src/annotations.mjs";
import { KEYLESS_TOOLS } from "../src/keyless-tools.mjs";
import { HOSTED_TOOLS } from "../src/http.mjs";
import { toolResult } from "../src/tool-result.mjs";

const { createSaltClient, createIdentityStore, createActions, generateKeypair, encryptFor } = pkg;

const HOST = "https://salt.test";
const API_KEY = "secret-agent-key";
const CLIENT = "33333333-3333-3333-3333-333333333333";
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

/** A fake salt-api: `routes` maps "METHOD /path" to a handler({body}) -> Response; the api-key header is required. */
function fakeSalt(routes) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url);
    const key = `${init.method || "GET"} ${u.pathname}`;
    assert.equal(init.headers["api-key"], API_KEY, `${key} must send the api-key header`);
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ key, body });
    const handler = routes[key];
    return handler ? handler({ body }) : json({ error: `no route ${key}` }, 404);
  };
  return { calls, fetchImpl };
}

async function setup() {
  const keys = await generateKeypair("pw");
  const decrypt = createDecryptor({ privateKey: keys.privateKey, passphrase: "pw" });
  const seal = (value) => encryptFor(JSON.stringify(value), [keys.publicKey]);
  return { keys, decrypt, seal };
}

const GRANT = { id: "g1", status: "active", browser_client_id: CLIENT, mode: "limited" };

test("listed in the local catalog with annotations; hidden from keyless and hosted catalogs", () => {
  const caller = { saltAppId: "1", username: "b", displayName: "B", apiKey: API_KEY, publicKey: "p", privateKey: "x" };
  const identities = createIdentityStore();
  identities.register(caller);
  const actions = createActions({ client: createSaltClient({ host: HOST }), identities, pgpPassphrase: "p", publicWebhookUrl: "", walletMasterKey: "u" });
  const handlers = createLocalHandlers({ actions, caller, host: HOST });
  const tools = handlers.listTools();
  assert.equal(BROWSER_TOOL_NAMES.size, 11);
  for (const name of BROWSER_TOOL_NAMES) {
    const t = tools.find((x) => x.name === name);
    assert.ok(t, `${name} missing from the local catalog`);
    for (const f of ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"]) assert.equal(typeof t.annotations[f], "boolean", `${name}.${f}`);
    if (name !== "salt_browser_grants") assert.match(t.description, /open.*read/i, `${name} should teach the loop`);
  }
  assert.equal(handlers.toolCount, tools.length);
  assert.ok(TOOL_ANNOTATIONS.browser_grants && TOOL_ANNOTATIONS.browser_step, "the SDK actions are annotated");
  assert.ok(!tools.some((t) => t.name === "browser_step" || t.name === "browser_grants"), "the SDK twins are listed once, as salt_browser_*");
  assert.ok(KEYLESS_TOOLS.every((t) => !BROWSER_TOOL_NAMES.has(t.name)), "keyless catalog must not list browser tools");
  assert.ok([...HOSTED_TOOLS].every((n) => !BROWSER_TOOL_NAMES.has(n)));
});

test("salt_browser_open posts a step with the only active grant's browser and returns the unsealed result", async () => {
  const { decrypt, seal } = await setup();
  const armor = await seal({ url: "https://example.test/", title: "Example" });
  const salt = fakeSalt({
    "GET /api/v1/browser/grants": () => json({ grants: [GRANT, { ...GRANT, id: "g2", status: "revoked", browser_client_id: "other" }] }),
    "POST /api/v1/browser/steps": () => json({ step: { id: "s1", status: "queued" } }, 201),
    "GET /api/v1/browser/steps/s1": () => json({ step: { id: "s1", status: "done", result: armor } }),
  });
  const out = await runBrowserTool("salt_browser_open", { url: "https://example.test/" }, { host: HOST, apiKey: API_KEY, decrypt, fetchImpl: salt.fetchImpl, waitMs: 0 });
  assert.equal(out.status, "done");
  assert.deepEqual(out.result, { url: "https://example.test/", title: "Example" });
  assert.match(out.notice, /strangers/);
  const post = salt.calls.find((c) => c.key === "POST /api/v1/browser/steps").body;
  assert.equal(post.action, "open");
  assert.deepEqual(post.args, { url: "https://example.test/" });
  assert.equal(post.browser_client_id, CLIENT);
  assert.match(post.step_id, /^[0-9a-f]{32}$/);
  assert.equal(JSON.stringify(out).includes("BEGIN PGP"), false, "armor is never returned");
});

test("a screenshot comes back as text plus MCP image content", async () => {
  const { decrypt, seal } = await setup();
  const armor = await seal({ data: Buffer.from("jpegbytes").toString("base64"), mime: "image/jpeg", url: "https://example.test/" });
  const salt = fakeSalt({ "POST /api/v1/browser/steps": () => json({ step: { id: "s2", status: "done", result: armor } }, 201) });
  const out = await runBrowserTool("salt_browser_screenshot", { browser_client_id: CLIENT, full_page: true }, { host: HOST, apiKey: API_KEY, decrypt, fetchImpl: salt.fetchImpl, waitMs: 0 });
  const mcp = toolResult(out);
  const image = mcp.content.find((c) => c.type === "image");
  assert.equal(image.mimeType, "image/jpeg");
  assert.equal(Buffer.from(image.data, "base64").toString(), "jpegbytes");
  assert.equal(mcp.content[0].type, "text");
  assert.doesNotMatch(mcp.content[0].text, /jpegbytes|anBlZ2J5dGVz/, "the picture is not duplicated into the text");
  assert.deepEqual(salt.calls[0].body.args, { full_page: true });
});

test("the generic step runs any action; a pending step is checked once and then by step_id on demand", async () => {
  const { decrypt, seal } = await setup();
  const armor = await seal({ found: true, waited_ms: 40, url: "https://example.test/" });
  let gets = 0;
  const salt = fakeSalt({
    "POST /api/v1/browser/steps": () => json({ step: { id: "s3", status: "queued" } }, 201),
    "GET /api/v1/browser/steps/s3": () => (++gets === 1 ? json({ step: { id: "s3", status: "sent" } }) : json({ step: { id: "s3", status: "done", result: armor } })),
  });
  const deps = { host: HOST, apiKey: API_KEY, decrypt, fetchImpl: salt.fetchImpl, waitMs: 0 };
  const first = await runBrowserTool("salt_browser_step", { action: "wait_for", args: { text: "Welcome" }, browser_client_id: CLIENT }, deps);
  assert.equal(first.status, "pending");
  assert.equal(gets, 1, "exactly one GET after the post, no timer loop");
  const second = await runBrowserTool("salt_browser_step", { step_id: "s3" }, deps);
  assert.equal(second.status, "done");
  assert.equal(second.result.found, true);
  assert.equal(salt.calls.filter((c) => c.key === "POST /api/v1/browser/steps").length, 1, "checking never posts again");
});

test("refusals, needs_human and conflicts come back as plain sentences", async () => {
  const { decrypt } = await setup();
  const run = (name, args, routes) => runBrowserTool(name, args, { host: HOST, apiKey: API_KEY, decrypt, fetchImpl: fakeSalt(routes).fetchImpl, waitMs: 0 });
  const post = (res) => ({ "POST /api/v1/browser/steps": () => res });

  const ro = await run("salt_browser_click", { ref: "e3", browser_client_id: CLIENT }, post(json({ step: { id: "a", status: "refused", reason: "read_only" } }, 201)));
  assert.equal(ro.status, "refused");
  assert.match(ro.message, /look-only/);

  const human = await run("salt_browser_click", { ref: "e3", browser_client_id: CLIENT }, post(json({ step: { id: "b", status: "needs_human", reason: "captcha" } }, 201)));
  assert.equal(human.status, "needs_human");
  assert.match(human.message, /CAPTCHA/);

  const paused = await run("salt_browser_read", { browser_client_id: CLIENT }, post(json({ error: "wait", code: "paused" }, 409)));
  assert.equal(paused.code, "paused");
  assert.match(paused.message, /Wait until they finish/);

  const slow = await run("salt_browser_read", { browser_client_id: CLIENT }, post(json({ code: "rate_limited" }, 429)));
  assert.match(slow.message, /slow down/);

  const gone = await run("salt_browser_read", { browser_client_id: CLIENT }, post(json({ error: "nope" }, 404)));
  assert.match(gone.message, /no access/);
});

test("no grants, several browsers and a bad url are clear errors; an unsealed result is not trusted", async () => {
  const { decrypt } = await setup();
  const deps = (routes) => ({ host: HOST, apiKey: API_KEY, decrypt, fetchImpl: fakeSalt(routes).fetchImpl, waitMs: 0 });
  await assert.rejects(runBrowserTool("salt_browser_read", {}, deps({ "GET /api/v1/browser/grants": () => json({ grants: [] }) })), /granted this agent a browser/);
  await assert.rejects(
    runBrowserTool("salt_browser_read", {}, deps({ "GET /api/v1/browser/grants": () => json({ grants: [GRANT, { ...GRANT, browser_client_id: "c2" }] }) })),
    /pass browser_client_id/
  );
  await assert.rejects(runBrowserTool("salt_browser_open", { url: "javascript:alert(1)", browser_client_id: CLIENT }, deps({})), /http/);
  await assert.rejects(runBrowserTool("salt_browser_step", { action: "teleport", browser_client_id: CLIENT }, deps({})), /action must be one of/);

  const plain = await runBrowserTool("salt_browser_read", { browser_client_id: CLIENT }, deps({ "POST /api/v1/browser/steps": () => json({ step: { id: "p", status: "done", result: "{\"title\":\"x\"}" } }, 201) }));
  assert.equal(plain.status, "failed");
  assert.match(plain.message, /wasn't sealed/);
});

test("salt_browser_grants lists active grants; a call over MCP returns the image as content", async () => {
  const { decrypt, seal } = await setup();
  const armor = await seal({ data: Buffer.from("px").toString("base64"), mime: "image/jpeg" });
  const salt = fakeSalt({
    "GET /api/v1/browser/grants": () => json({ grants: [GRANT, { ...GRANT, status: "paused" }] }),
    "POST /api/v1/browser/steps": () => json({ step: { id: "s9", status: "done", result: armor } }, 201),
  });
  const caller = { saltAppId: "1", username: "b", displayName: "B", apiKey: API_KEY, publicKey: "p", privateKey: "x" };
  const identities = createIdentityStore();
  identities.register(caller);
  const actions = createActions({ client: createSaltClient({ host: HOST }), identities, pgpPassphrase: "p", publicWebhookUrl: "", walletMasterKey: "u" });
  const handlers = createLocalHandlers({ actions, caller, host: HOST, decrypt, fetchImpl: salt.fetchImpl });
  const grants = await handlers.callTool("salt_browser_grants", {});
  assert.deepEqual(grants.grants, [GRANT]);
  const shot = await handlers.callTool("salt_browser_screenshot", {});
  assert.ok(toolResult(shot).content.some((c) => c.type === "image"));
  assert.ok(buildLocalServer(handlers), "the server builds with the browser tools in its catalog");
});

test("metadata: every named tool's required fields exist in its schema", () => {
  for (const m of BROWSER_TOOL_METADATA) for (const r of m.inputSchema.required || []) assert.ok(m.inputSchema.properties[r], `${m.name} requires ${r}`);
});
