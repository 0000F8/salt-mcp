// Unit tests for src/media-tools.mjs -- live and short-video tools shared by the local and hosted servers.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { videoSource, pinnedGet, createMediaTools, runMediaTool, toMediaMcpTools, MEDIA_TOOL_METADATA, MEDIA_TOOL_NAMES } from "../src/media-tools.mjs";

const CHAT = "11111111-1111-1111-1111-111111111111";
const LIVE = "Lq3f8aZkP2xVnR7tYb1HdA";
const MEDIA = "Mq3f8aZkP2xVnR7tYb1HdB";
const POST = "Vq3f8aZkP2xVnR7tYb1HdC";

function fakeRequest(routes) {
  const calls = [];
  return {
    calls,
    request: async (method, path, body) => {
      calls.push({ method, path, body });
      const handler = routes[`${method} ${path.split("?")[0]}`];
      if (!handler) throw new Error(`no mock route for ${method} ${path}`);
      return typeof handler === "function" ? handler({ path, body }) : handler;
    },
  };
}

// The video getter (pinned to the checked address in production) answers from the latest externalFetch in these tests.
let lastExternal;
/** A HEAD answers the GET's status and headers, with the content-length the body would have had. */
async function asHead(res, opts) {
  if (opts?.method !== "HEAD" || (res.status >= 300 && res.status < 400)) return res;
  const h = new Headers(res.headers);
  if (!h.has("content-length")) h.set("content-length", String((await res.clone().arrayBuffer()).byteLength));
  return new Response(null, { status: res.status, headers: h });
}
videoSource.get = async (url, _address, opts) => asHead(await lastExternal(url.toString(), {}), opts);

const publicLookup = async () => [{ address: "93.184.216.34" }];

/** Third-party hosts only: the video source, presigned part URLs, the transcript CDN. */
function externalFetch(handlers) {
  const calls = [];
  const fn = async (url, init = {}) => {
    calls.push({ url, init });
    const u = new URL(url);
    const h = handlers[u.hostname];
    if (!h) throw new Error(`no external route for ${u.hostname}`);
    return h(u, init, calls.length);
  };
  fn.calls = calls;
  lastExternal = fn;
  return fn;
}

/** Replaces the pinned video getter: handlers get (url, address) and the call is recorded. */
function stubVideoSource(handler) {
  const calls = [];
  videoSource.get = async (url, address, opts) => {
    if (opts?.method !== "HEAD") calls.push({ url: url.toString(), address });
    return asHead(await handler(url, address), opts);
  };
  return calls;
}

const bytesResponse = (bytes, type = "video/mp4", status = 200, headers = {}) =>
  new Response(new Uint8Array(bytes), { status, headers: { "content-type": type, ...headers } });

const UPLOAD_ROUTES = {
  "POST /api/v1/media": { media: { id: MEDIA, state: "uploading" }, upload: { upload_id: "u1", part_size: 4, parts: [{ n: 1, url: "https://s3.test/p1" }, { n: 2, url: "https://s3.test/p2" }] } },
  [`POST /api/v1/media/${MEDIA}/complete`]: { media: { id: MEDIA, state: "processing" } },
};

test("goLive always asks for an RTMP session, returns the publish block once, and warns that the key is a secret", async () => {
  const { request, calls } = fakeRequest({
    "POST /api/v1/live_sessions": { live_session: { id: LIVE, chat_id: CHAT, state: "connecting", source_type: "rtmp", record: true }, publish: { ingest_endpoint: "x.live-video.net", rtmps_url: "rtmps://x.live-video.net:443/app/", stream_key: "sk_secret" } },
  });
  const out = await createMediaTools({ request }).goLive({ chat_id: CHAT, title: "  hi  ", record: true });
  assert.deepEqual(calls[0].body, { chat_id: CHAT, source_type: "rtmp", title: "hi", record: true });
  assert.equal(out.publish.stream_key, "sk_secret");
  assert.match(out.warning, /secret/i);
  assert.equal(out.live_session.id, LIVE);
});

test("goLive passes the server's refusal through and refuses a malformed chat_id before calling", async () => {
  const { request, calls } = fakeRequest({
    "POST /api/v1/live_sessions": () => {
      throw new Error("Salt API POST /api/v1/live_sessions -> 409: You are already live.");
    },
  });
  const tools = createMediaTools({ request });
  await assert.rejects(() => tools.goLive({ chat_id: CHAT }), /409: You are already live/);
  await assert.rejects(() => tools.goLive({ chat_id: "../x" }), /plain Salt id/);
  assert.equal(calls.length, 1);
});

test("getLive reads by id, or the room's current session (null when nothing is live)", async () => {
  const { request, calls } = fakeRequest({
    [`GET /api/v1/live_sessions/${LIVE}`]: { live_session: { id: LIVE, state: "live", viewer_count: 3 } },
    [`GET /api/v1/chats/${CHAT}/live`]: { live_session: null },
  });
  const tools = createMediaTools({ request });
  assert.equal((await tools.getLive({ live_session_id: LIVE })).live_session.viewer_count, 3);
  assert.deepEqual(await tools.getLive({ chat_id: CHAT }), { live_session: null });
  assert.equal(calls.length, 2);
});

test("endLive posts to the end path", async () => {
  const { request, calls } = fakeRequest({ [`POST /api/v1/live_sessions/${LIVE}/end`]: { live_session: { id: LIVE, state: "ending" } } });
  assert.equal((await createMediaTools({ request }).endLive({ live_session_id: LIVE })).live_session.state, "ending");
  assert.equal(calls[0].path, `/api/v1/live_sessions/${LIVE}/end`);
});

test("uploadVideo from a url: downloads, PUTs each part without Salt credentials, completes", async () => {
  const { request, calls } = fakeRequest(UPLOAD_ROUTES);
  const ext = externalFetch({
    "clips.test": () => bytesResponse([1, 2, 3, 4, 5, 6]),
    "s3.test": (u) => new Response("", { status: 200, headers: { ETag: `"e-${u.pathname.slice(-1)}"` } }),
  });
  const out = await createMediaTools({ request, fetchImpl: ext, lookupImpl: publicLookup }).uploadVideo({ url: "https://clips.test/a.mp4" });
  assert.equal(out.media.state, "processing");
  assert.deepEqual(calls[0].body, { kind: "video", byte_size: 6, content_type: "video/mp4", filename: "a.mp4" });
  const puts = ext.calls.filter((c) => c.init.method === "PUT");
  assert.deepEqual(Array.from(puts[0].init.body), [1, 2, 3, 4]);
  assert.deepEqual(Array.from(puts[1].init.body), [5, 6]);
  assert.equal(puts[0].init.headers, undefined);
  assert.deepEqual(calls[1].body, { upload_id: "u1", parts: [{ n: 1, etag: '"e-1"' }, { n: 2, etag: '"e-2"' }] });
});

test("uploadVideo refuses http, private hosts, redirects into private hosts, oversize and non-video content", async () => {
  const { request, calls } = fakeRequest(UPLOAD_ROUTES);
  const lookup = async (host) => [{ address: host === "internal.test" ? "10.0.0.5" : "93.184.216.34" }];
  const ext = externalFetch({
    "clips.test": (u) => (u.pathname === "/redirect" ? new Response("", { status: 302, headers: { location: "https://internal.test/x.mp4" } }) : u.pathname === "/big" ? bytesResponse([1], "video/mp4", 200, { "content-length": String(101 * 1024 * 1024) }) : bytesResponse([1], "text/html")),
  });
  const tools = createMediaTools({ request, fetchImpl: ext, lookupImpl: lookup });
  await assert.rejects(() => tools.uploadVideo({ url: "http://clips.test/a.mp4" }), /https/);
  await assert.rejects(() => tools.uploadVideo({ url: "https://internal.test/a.mp4" }), /isn't allowed/);
  await assert.rejects(() => tools.uploadVideo({ url: "https://127.0.0.1/a.mp4" }), /isn't allowed/);
  await assert.rejects(() => tools.uploadVideo({ url: "https://[::1]/a.mp4" }), /isn't allowed/);
  await assert.rejects(() => tools.uploadVideo({ url: "https://clips.test/redirect" }), /isn't allowed/);
  await assert.rejects(() => tools.uploadVideo({ url: "https://clips.test/big" }), /over 100 MB/);
  await assert.rejects(() => tools.uploadVideo({ url: "https://clips.test/page" }), /video\/mp4, video\/quicktime or video\/webm/);
  assert.equal(calls.length, 0);
});

test("uploadVideo: path is refused on the hosted server and read on the local one; exactly one source is required", async () => {
  const dir = mkdtempSync(join(tmpdir(), "salt-media-"));
  const file = join(dir, "clip.mov");
  writeFileSync(file, Buffer.from([7, 7, 7]));
  const { request, calls } = fakeRequest({
    "POST /api/v1/media": { media: { id: MEDIA }, upload: { upload_id: "u1", part_size: 4, parts: [{ n: 1, url: "https://s3.test/p1" }] } },
    [`POST /api/v1/media/${MEDIA}/complete`]: { media: { id: MEDIA, state: "processing" } },
  });
  const ext = externalFetch({ "s3.test": () => new Response("", { status: 200, headers: { ETag: '"e"' } }) });
  await assert.rejects(() => createMediaTools({ request }).uploadVideo({ path: file }), /only available on the local server/);
  const local = createMediaTools({ request, allowPath: true, fetchImpl: ext });
  await local.uploadVideo({ path: file });
  assert.deepEqual(calls[0].body, { kind: "video", byte_size: 3, content_type: "video/quicktime", filename: "clip.mov" });
  await assert.rejects(() => local.uploadVideo({}), /exactly one of url or path/);
  await assert.rejects(() => local.uploadVideo({ url: "https://x.test/a.mp4", path: file }), /exactly one of url or path/);
});

test("uploadVideo retries a failed part and gives up without completing", async () => {
  const { request, calls } = fakeRequest({
    "POST /api/v1/media": { media: { id: MEDIA }, upload: { upload_id: "u1", part_size: 4, parts: [{ n: 1, url: "https://s3.test/p1" }] } },
    [`POST /api/v1/media/${MEDIA}/complete`]: { media: { id: MEDIA, state: "processing" } },
  });
  let n = 0;
  const flaky = externalFetch({
    "clips.test": () => bytesResponse([1]),
    "s3.test": () => (++n === 1 ? new Response("", { status: 500 }) : new Response("", { status: 200, headers: { ETag: '"e"' } })),
  });
  await createMediaTools({ request, fetchImpl: flaky, lookupImpl: publicLookup }).uploadVideo({ url: "https://clips.test/a.mp4" });
  assert.equal(n, 2);
  const broken = externalFetch({ "clips.test": () => bytesResponse([1]), "s3.test": () => new Response("", { status: 500 }) });
  const before = calls.length;
  await assert.rejects(() => createMediaTools({ request, fetchImpl: broken, lookupImpl: publicLookup }).uploadVideo({ url: "https://clips.test/a.mp4" }), /part upload -> 500/);
  assert.ok(!calls.slice(before).some((c) => c.path.endsWith("/complete")));
});

test("publishVideo posts a new asset, or publishes a draft; it needs exactly one of media_id and draft_id", async () => {
  const { request, calls } = fakeRequest({
    "POST /api/v1/video_posts": { video_post: { id: POST, status: "published", media: { id: MEDIA, state: "ready" } } },
    [`PATCH /api/v1/video_posts/${POST}`]: { video_post: { id: POST, status: "published" } },
  });
  const tools = createMediaTools({ request });
  assert.equal((await tools.publishVideo({ media_id: MEDIA, caption: "hi", chat_id: CHAT })).video_post.id, POST);
  assert.deepEqual(calls[0].body, { media_id: MEDIA, caption: "hi", chat_id: CHAT });
  await tools.publishVideo({ draft_id: POST, caption: "ok" });
  assert.deepEqual(calls[1], { method: "PATCH", path: `/api/v1/video_posts/${POST}`, body: { status: "published", caption: "ok" } });
  await assert.rejects(() => tools.publishVideo({}), /exactly one/);
  await assert.rejects(() => tools.publishVideo({ media_id: MEDIA, draft_id: POST }), /exactly one/);
});

test("myVideos and videoFeed build their queries and shape the answers", async () => {
  const { request, calls } = fakeRequest({
    "GET /api/v1/video_posts/mine": { video_posts: [{ id: POST, status: "draft", media: { id: MEDIA, state: "ready" } }] },
    "GET /api/v1/video/feed": { items: [{ id: POST, status: "published" }], live: [{ id: LIVE, state: "live" }], next_before_seq: 12 },
  });
  const tools = createMediaTools({ request });
  assert.equal((await tools.myVideos({ status: "draft" })).video_posts[0].status, "draft");
  assert.equal(calls[0].path, "/api/v1/video_posts/mine?status=draft");
  const feed = await tools.videoFeed({ scope: "room", chat_id: CHAT, before_seq: 40, limit: 10 });
  assert.equal(calls[1].path, `/api/v1/video/feed?scope=room&chat_id=${CHAT}&before_seq=40&limit=10`);
  assert.equal(feed.next_before_seq, 12);
  assert.equal(feed.live[0].id, LIVE);
  await assert.rejects(() => tools.videoFeed({ scope: "nope" }), /scope must be/);
  await assert.rejects(() => tools.myVideos({ status: "hidden" }), /status must be/);
});

test("getMedia returns the transcript text via the CDN cookies, truncates a long one, and skips it on request", async () => {
  const media = { id: MEDIA, state: "ready", transcript: { status: "ready", language: "en", text_url: "https://media.test/v/x/transcript.txt" } };
  const { request, calls } = fakeRequest({
    [`GET /api/v1/media/${MEDIA}`]: { media },
    [`POST /api/v1/media/${MEDIA}/playback`]: { expires_at: "t", cookies: { "CloudFront-Policy": "p", "CloudFront-Signature": "s" } },
  });
  const ext = externalFetch({ "media.test": () => new Response("a".repeat(25000), { status: 200 }) });
  const tools = createMediaTools({ request, fetchImpl: ext });
  const out = await tools.getMedia({ media_id: MEDIA });
  assert.equal(out.transcript.text.length, 20000);
  assert.equal(out.transcript.truncated, true);
  assert.equal(ext.calls[0].init.headers.Cookie, "CloudFront-Policy=p; CloudFront-Signature=s");
  const skipped = await tools.getMedia({ media_id: MEDIA, include_transcript: false });
  assert.equal(skipped.transcript.text, null);
  assert.equal(ext.calls.length, 1);
  assert.equal(calls.filter((c) => c.path.endsWith("/playback")).length, 1);
});

test("getMedia without a transcript answers just the media", async () => {
  const { request } = fakeRequest({ [`GET /api/v1/media/${MEDIA}`]: { media: { id: MEDIA, state: "processing" } } });
  assert.deepEqual(await createMediaTools({ request }).getMedia({ media_id: MEDIA }), {
    media: { id: MEDIA, state: "processing", playback: null, duration_ms: null, width: null, height: null, failed_reason: null, transcript_status: null },
  });
});

test("reportMedia picks the path by which id it is given", async () => {
  const { request, calls } = fakeRequest({ [`POST /api/v1/live_sessions/${LIVE}/reports`]: {}, [`POST /api/v1/video_posts/${POST}/reports`]: {} });
  const tools = createMediaTools({ request });
  assert.deepEqual(await tools.reportMedia({ live_session_id: LIVE, reason: "spam", note: " n " }), { reported: true });
  await tools.reportMedia({ video_post_id: POST, reason: "spam" });
  assert.deepEqual(calls[0].body, { reason: "spam", note: "n" });
  assert.equal(calls[1].path, `/api/v1/video_posts/${POST}/reports`);
  await assert.rejects(() => tools.reportMedia({ reason: "x" }), /exactly one/);
  await assert.rejects(() => tools.reportMedia({ video_post_id: POST }), /reason is required/);
});

test("ids that are not Salt media ids are refused before any request", async () => {
  const { request, calls } = fakeRequest({});
  const tools = createMediaTools({ request });
  await assert.rejects(() => tools.getMedia({ media_id: "../../x" }), /Salt media id/);
  await assert.rejects(() => tools.endLive({ live_session_id: "a b" }), /Salt media id/);
  assert.equal(calls.length, 0);
});

test("runMediaTool dispatches by name and refuses anything else", async () => {
  const { request } = fakeRequest({ [`GET /api/v1/chats/${CHAT}/live`]: { live_session: null } });
  assert.deepEqual(await runMediaTool("salt_get_live", { chat_id: CHAT }, { request }), { live_session: null });
  await assert.rejects(() => runMediaTool("salt_nope", {}, { request }), /not a media tool/);
});

test("metadata: nine tools, every one with a title, all four hints, schemas; reads are read-only, going live and posting are destructive", () => {
  assert.equal(MEDIA_TOOL_NAMES.size, 9);
  for (const meta of MEDIA_TOOL_METADATA) {
    assert.ok(meta.title, meta.name);
    for (const f of ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"]) assert.equal(typeof meta.annotations[f], "boolean", `${meta.name}.${f}`);
    assert.equal(typeof meta.inputSchema, "object");
    assert.equal(typeof meta.outputSchema, "object");
  }
  const by = Object.fromEntries(MEDIA_TOOL_METADATA.map((m) => [m.name, m.annotations]));
  for (const n of ["salt_get_live", "salt_my_videos", "salt_video_feed", "salt_get_media"]) assert.equal(by[n].readOnlyHint, true, n);
  for (const n of ["salt_go_live", "salt_end_live", "salt_publish_video"]) assert.equal(by[n].destructiveHint, true, n);
  assert.equal(by.salt_go_live.idempotentHint, false);
});

test("go live's description tells the model the key is shown once and must stay secret", () => {
  const meta = MEDIA_TOOL_METADATA.find((m) => m.name === "salt_go_live");
  assert.match(meta.description, /exactly once/);
  assert.match(meta.description, /secret/);
});

test("toMediaMcpTools: only the local variant offers a file path for upload", () => {
  const hosted = toMediaMcpTools().find((t) => t.name === "salt_upload_video");
  const local = toMediaMcpTools({ local: true }).find((t) => t.name === "salt_upload_video");
  assert.equal(hosted.inputSchema.properties.path, undefined);
  assert.deepEqual(hosted.inputSchema.required, ["url"]);
  assert.ok(local.inputSchema.properties.path);
  assert.deepEqual(local.inputSchema.required, []);
  assert.equal(hosted.annotations.title, hosted.title);
});

test("the video fetch connects to the address that was checked, even if DNS answers differently the second time", async () => {
  const { request } = fakeRequest({
    "POST /api/v1/media": { media: { id: MEDIA }, upload: { upload_id: "u1", part_size: 4, parts: [{ n: 1, url: "https://s3.test/p1" }] } },
    [`POST /api/v1/media/${MEDIA}/complete`]: { media: { id: MEDIA, state: "processing" } },
  });
  let lookups = 0;
  const rebinding = async () => [{ address: ++lookups === 1 ? "93.184.216.34" : "127.0.0.1" }];
  const seen = stubVideoSource((url) => (url.pathname === "/hop" ? new Response("", { status: 302, headers: { location: "https://other.test/a.mp4" } }) : bytesResponse([1])));
  const ext = externalFetch({ "s3.test": () => new Response("", { status: 200, headers: { ETag: '"e"' } }) });
  const tools = createMediaTools({ request, fetchImpl: ext, lookupImpl: rebinding });
  await tools.uploadVideo({ url: "https://clips.test/a.mp4", byte_size: 1, content_type: "video/mp4" });
  assert.deepEqual(seen, [{ url: "https://clips.test/a.mp4", address: "93.184.216.34" }]);
  assert.equal(lookups, 1);
  // The second DNS answer is loopback: a fresh lookup is refused outright, so nothing is fetched.
  await assert.rejects(() => tools.uploadVideo({ url: "https://clips.test/hop", byte_size: 1, content_type: "video/mp4" }), /isn't allowed/);
  assert.equal(seen.length, 1);
});

test("each redirect hop is resolved and pinned to its own checked address", async () => {
  const { request } = fakeRequest({
    "POST /api/v1/media": { media: { id: MEDIA }, upload: { upload_id: "u1", part_size: 4, parts: [{ n: 1, url: "https://s3.test/p1" }] } },
    [`POST /api/v1/media/${MEDIA}/complete`]: { media: { id: MEDIA, state: "processing" } },
  });
  const lookup = async (host) => [{ address: host === "clips.test" ? "93.184.216.34" : "93.184.216.35" }];
  const seen = stubVideoSource((url) => (url.hostname === "clips.test" ? new Response("", { status: 302, headers: { location: "https://cdn.test/a.mp4" } }) : bytesResponse([1])));
  const ext = externalFetch({ "s3.test": () => new Response("", { status: 200, headers: { ETag: '"e"' } }) });
  await createMediaTools({ request, fetchImpl: ext, lookupImpl: lookup }).uploadVideo({ url: "https://clips.test/a.mp4" });
  assert.deepEqual(seen.map((c) => c.address), ["93.184.216.34", "93.184.216.35"]);
});

// --- M5: URL checks, timeouts, API-first, generic errors ---

test("literal hosts in every non-public range are refused, including IPv4-mapped, IPv4-compatible and NAT64 IPv6", async () => {
  const { request, calls } = fakeRequest(UPLOAD_ROUTES);
  const seen = stubVideoSource(() => bytesResponse([1]));
  const tools = createMediaTools({ request, lookupImpl: publicLookup });
  const hosts = ["[::ffff:10.0.0.5]", "[::ffff:a00:5]", "[::ffff:127.0.0.1]", "[::10.0.0.5]", "[64:ff9b::a00:5]", "[64:ff9b::808:808]", "198.18.0.1", "198.19.255.255", "169.254.169.254", "[::ffff:169.254.169.254]", "100.64.0.1", "192.0.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "0.0.0.0", "[::]", "[fe80::1]", "[fc00::1]", "[ff02::1]", "[2001:db8::1]", "[2002:a00:5::]"];
  for (const h of hosts) {
    await assert.rejects(() => tools.uploadVideo({ url: `https://${h}/a.mp4`, byte_size: 1, content_type: "video/mp4" }), /isn't allowed/, h);
  }
  assert.equal(seen.length, 0);
  assert.equal(calls.length, 0);
});

test("public literals, including a mapped public IPv4, are still allowed", async () => {
  const { request } = fakeRequest(UPLOAD_ROUTES);
  const seen = stubVideoSource(() => bytesResponse([1, 2, 3, 4, 5, 6]));
  const ext = externalFetch({ "s3.test": (u) => new Response("", { status: 200, headers: { ETag: `"e-${u.pathname.slice(-1)}"` } }) });
  await createMediaTools({ request, fetchImpl: ext, lookupImpl: publicLookup }).uploadVideo({ url: "https://[::ffff:93.184.216.34]/a.mp4", byte_size: 6, content_type: "video/mp4" });
  assert.equal(seen[0].address, "::ffff:5db8:d822");
});

test("a resolved address that is mapped, NAT64 or 198.18 is refused, and so is a redirect to one", async () => {
  const { request } = fakeRequest(UPLOAD_ROUTES);
  const answers = { "mapped.test": "::ffff:a00:5", "nat.test": "64:ff9b::a00:5", "bench.test": "198.18.0.9", "clips.test": "93.184.216.34" };
  const seen = stubVideoSource((url) => (url.hostname === "clips.test" ? new Response("", { status: 302, headers: { location: "https://bench.test/x.mp4" } }) : bytesResponse([1])));
  const tools = createMediaTools({ request, lookupImpl: async (h) => [{ address: answers[h] }] });
  for (const host of ["mapped.test", "nat.test", "bench.test", "clips.test"]) {
    await assert.rejects(() => tools.uploadVideo({ url: `https://${host}/a.mp4`, byte_size: 1, content_type: "video/mp4" }), /isn't allowed/, host);
  }
  assert.deepEqual(seen.map((c) => c.url), ["https://clips.test/a.mp4"]);
});

test("a redirect to a private literal is refused", async () => {
  const { request } = fakeRequest(UPLOAD_ROUTES);
  stubVideoSource(() => new Response("", { status: 302, headers: { location: "https://[::ffff:10.0.0.5]/x.mp4" } }));
  await assert.rejects(() => createMediaTools({ request, lookupImpl: publicLookup }).uploadVideo({ url: "https://clips.test/a.mp4", byte_size: 1, content_type: "video/mp4" }), /isn't allowed/);
});

test("no fetch happens when the API refuses the upload", async () => {
  const { request, calls } = fakeRequest({
    "POST /api/v1/media": () => {
      throw new Error("Salt API POST /api/v1/media -> 403: Only creators can upload video.");
    },
  });
  const seen = [];
  videoSource.get = async (url, address, opts) => {
    seen.push({ url: url.toString(), method: opts?.method });
    return bytesResponse([1]);
  };
  const tools = createMediaTools({ request, lookupImpl: publicLookup });
  await assert.rejects(() => tools.uploadVideo({ url: "https://clips.test/a.mp4", byte_size: 1, content_type: "video/mp4" }), /403: Only creators/);
  assert.equal(seen.length, 0);
  assert.deepEqual(calls[0].body, { kind: "video", byte_size: 1, content_type: "video/mp4", filename: "a.mp4" });
});

test("without a declared size the source is asked by HEAD, and a missing or oversize Content-Length is refused before the API", async () => {
  const { request, calls } = fakeRequest(UPLOAD_ROUTES);
  const seen = [];
  videoSource.get = async (url, address, opts) => {
    seen.push(opts?.method);
    if (url.pathname === "/none") return new Response(null, { status: 200, headers: { "content-type": "video/mp4" } });
    return new Response(null, { status: 200, headers: { "content-type": "video/mp4", "content-length": String(200 * 1024 * 1024) } });
  };
  const tools = createMediaTools({ request, lookupImpl: publicLookup });
  await assert.rejects(() => tools.uploadVideo({ url: "https://clips.test/none" }), /size isn't known/);
  await assert.rejects(() => tools.uploadVideo({ url: "https://clips.test/huge" }), /over 100 MB/);
  assert.deepEqual(seen, ["HEAD", "HEAD"]);
  assert.equal(calls.length, 0);
});

test("a body that is not the declared size is refused", async () => {
  const { request } = fakeRequest(UPLOAD_ROUTES);
  stubVideoSource(() => bytesResponse([1, 2, 3]));
  await assert.rejects(() => createMediaTools({ request, lookupImpl: publicLookup }).uploadVideo({ url: "https://clips.test/a.mp4", byte_size: 6, content_type: "video/mp4" }), /size changed/);
});

test("errors from the fetched host never reach the caller", async () => {
  const { request } = fakeRequest(UPLOAD_ROUTES);
  const tools = createMediaTools({ request, lookupImpl: publicLookup });
  const args = { url: "https://clips.test/a.mp4", byte_size: 1, content_type: "video/mp4" };
  for (const failure of [() => new Response("nope", { status: 503 }), () => new Response("", { status: 404 }), () => { throw new Error("SSL routines:tls_process_server_certificate:certificate verify failed"); }, () => { throw new Error("getaddrinfo ENOTFOUND clips.test"); }]) {
    stubVideoSource(failure);
    await assert.rejects(() => tools.uploadVideo(args), (err) => err.message === "Couldn't download that video.");
  }
  await assert.rejects(() => createMediaTools({ request, lookupImpl: async () => { throw new Error("queryA ECONNREFUSED 10.1.2.3:53"); } }).uploadVideo(args), (err) => err.message === "Couldn't download that video.");
  await assert.rejects(() => tools.uploadVideo({ url: "https://10.0.0.5/a.mp4", byte_size: 1, content_type: "video/mp4" }), (err) => err.message === "That address isn't allowed.");
});

// A fake https.request: the request is an EventEmitter with destroy/setTimeout/end, the response streams on demand.
function fakeHttps(onRequest) {
  const record = { destroyed: null, timeoutMs: null, timeoutCb: null, options: null };
  const requestImpl = (url, options, cb) => {
    const req = new EventEmitter();
    record.options = options;
    req.setTimeout = (ms, fn) => { record.timeoutMs = ms; record.timeoutCb = fn; };
    req.destroy = (err) => { record.destroyed = err ?? true; if (err) setImmediate(() => req.emit("error", err)); };
    req.end = () => onRequest(cb, record);
    return req;
  };
  return { requestImpl, record };
}

test("the pinned GET sets a 30 s socket timeout and gives up when it fires", async () => {
  const { requestImpl, record } = fakeHttps(() => {});
  const p = pinnedGet(new URL("https://clips.test/a.mp4"), "93.184.216.34", { requestImpl });
  assert.equal(record.timeoutMs, 30000);
  record.timeoutCb();
  await assert.rejects(p, /timeout/);
  assert.ok(record.destroyed);
});

test("the whole download has a deadline", async () => {
  const { requestImpl, record } = fakeHttps(() => {});
  await assert.rejects(pinnedGet(new URL("https://clips.test/a.mp4"), "93.184.216.34", { requestImpl, deadline: Date.now() + 20 }), /deadline/);
  assert.ok(record.destroyed);
  const done = fakeHttps(() => {});
  await assert.rejects(pinnedGet(new URL("https://clips.test/a.mp4"), "93.184.216.34", { requestImpl: done.requestImpl, deadline: Date.now() - 1 }), /deadline/);
});

test("the pinned GET aborts as soon as the stream passes 100 MB, without reading the rest", async () => {
  let pushed = 0;
  const { requestImpl, record } = fakeHttps((cb) => {
    const res = new EventEmitter();
    res.statusCode = 200;
    res.headers = {};
    cb(res);
    const chunk = Buffer.alloc(10 * 1024 * 1024);
    for (let i = 0; i < 20 && !record.destroyed; i++) {
      pushed++;
      res.emit("data", chunk);
    }
  });
  await assert.rejects(pinnedGet(new URL("https://clips.test/a.mp4"), "93.184.216.34", { requestImpl }), (err) => err.message === "That video is over 100 MB.");
  assert.equal(pushed, 11);
});

test("the pinned GET connects to the checked address and sends HEAD without a body", async () => {
  const { requestImpl, record } = fakeHttps((cb) => {
    const res = new EventEmitter();
    res.statusCode = 200;
    res.headers = { "content-length": "7" };
    cb(res);
    res.emit("end");
  });
  const res = await pinnedGet(new URL("https://clips.test/a.mp4"), "93.184.216.34", { requestImpl, method: "HEAD" });
  assert.equal(record.options.method, "HEAD");
  assert.equal(res.headers.get("content-length"), "7");
  await new Promise((r) => record.options.lookup("clips.test", {}, (e, a) => { assert.equal(a, "93.184.216.34"); r(); }));
});
