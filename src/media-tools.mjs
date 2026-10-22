// Live and short video (2026-10-21): nine tools over salt-api's media
// endpoints (/live_sessions, /media, /video_posts, /video/feed), so an agent
// has the same reach a person has in the app. Like room-tools.mjs these are
// not salt-agent-sdk actions; they are shared by the local (stdio) server and
// the hosted OAuth catalog, each binding `request` to its own auth.
//
// An agent has no camera, so "go live" always starts an RTMPS session: the
// stream key comes back ONCE and the agent pushes with ffmpeg. The key is a
// secret and is never logged here.
//
// salt-api answers 404 for every one of these while the media switches are
// closed, and 403 for an account that is not a hand-picked creator; those
// sentences pass straight through as the error.

import { readFile, stat } from "node:fs/promises";
import { lookup } from "node:dns/promises";
import net from "node:net";
import https from "node:https";

const PUBLIC_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const CHAT_ID_RE = /^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9]+)$/;
const VIDEO_TYPES = new Set(["video/mp4", "video/quicktime", "video/webm"]);
const MAX_VIDEO_BYTES = 100 * 1024 * 1024;
const MAX_TRANSCRIPT_CHARS = 20000;
const MAX_REDIRECTS = 3;

function assertPublicId(value, field) {
  const s = typeof value === "string" ? value.trim() : "";
  if (!s) throw new Error(`${field} is required.`);
  if (!PUBLIC_ID_RE.test(s)) throw new Error(`${field} must be a Salt media id -- refusing "${s.slice(0, 60)}".`);
  return s;
}

function assertChatId(value, field) {
  const s = typeof value === "string" ? value.trim() : typeof value === "number" ? String(value) : "";
  if (!s) throw new Error(`${field} is required.`);
  if (!CHAT_ID_RE.test(s)) throw new Error(`${field} must be a plain Salt id (a uuid or an integer) -- refusing "${s.slice(0, 60)}".`);
  return s;
}

function str(value) {
  return value != null ? String(value) : null;
}

function summarizeLive(l) {
  return {
    id: str(l?.id),
    chat_id: str(l?.chat_id),
    state: l?.state ?? null,
    title: l?.title ?? null,
    source_type: l?.source_type ?? null,
    record: Boolean(l?.record),
    started_at: l?.started_at ?? null,
    ended_at: l?.ended_at ?? null,
    ended_reason: l?.ended_reason ?? null,
    viewer_count: typeof l?.viewer_count === "number" ? l.viewer_count : 0,
    recording: l?.recording ?? null,
    can_end: Boolean(l?.can_end),
  };
}

function summarizeMedia(m) {
  return {
    id: str(m?.id),
    state: m?.state ?? null,
    playback: m?.playback ?? null,
    duration_ms: m?.duration_ms ?? null,
    width: m?.width ?? null,
    height: m?.height ?? null,
    failed_reason: m?.failed_reason ?? null,
    transcript_status: m?.transcript?.status ?? null,
  };
}

function summarizeVideoPost(p) {
  return {
    id: str(p?.id),
    status: p?.status ?? null,
    caption: p?.caption ?? null,
    media: summarizeMedia(p?.media),
    creator: p?.creator ? { id: str(p.creator.id), username: p.creator.username ?? null, display_name: p.creator.display_name ?? null, account_type: p.creator.account_type ?? null } : null,
    chat_id: str(p?.chat_id),
    room: p?.room ?? null,
    published_at: p?.published_at ?? null,
    seq: typeof p?.seq === "number" ? p.seq : null,
    counts: p?.counts ?? { views: 0, replies: 0, reactions: 0 },
    live_session_id: str(p?.live_session_id),
  };
}

function isPrivateAddress(address) {
  if (net.isIPv4(address)) {
    const [a, b] = address.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const v6 = address.toLowerCase();
  if (v6.startsWith("::ffff:")) return isPrivateAddress(v6.slice(7));
  return v6 === "::" || v6 === "::1" || v6.startsWith("fc") || v6.startsWith("fd") || v6.startsWith("fe8") || v6.startsWith("fe9") || v6.startsWith("fea") || v6.startsWith("feb");
}

/** https only, and never an address inside the host's own network. Returns the URL and the ONE address to connect to. */
async function resolvePublicHttps(raw, lookupImpl) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("url must be a valid https URL.");
  }
  if (url.protocol !== "https:") throw new Error("url must be https.");
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const addresses = net.isIP(host) ? [{ address: host }] : await lookupImpl(host, { all: true });
  if (!addresses.length || addresses.some((a) => isPrivateAddress(a.address))) throw new Error("url must point to a public host.");
  return { url, address: addresses[0].address };
}

/** GET over https connecting to exactly `address` (the one that was checked): a second DNS answer cannot redirect the
 *  connection. The Host header and the TLS servername stay the hostname. The body is cut off past the size cap. */
function pinnedGet(url, address) {
  return new Promise((resolve, reject) => {
    const family = net.isIPv6(address) ? 6 : 4;
    const req = https.request(url, { method: "GET", lookup: (_host, opts, cb) => (opts?.all ? cb(null, [{ address, family }]) : cb(null, address, family)), servername: net.isIP(url.hostname) ? undefined : url.hostname }, (res) => {
      const chunks = [];
      let size = 0;
      res.on("data", (c) => {
        size += c.length;
        if (size > MAX_VIDEO_BYTES) {
          req.destroy(new Error("That video is over 100 MB."));
          return;
        }
        chunks.push(c);
      });
      res.on("end", () => {
        const headers = new Headers();
        for (const [k, v] of Object.entries(res.headers)) if (typeof v === "string") headers.set(k, v);
        const status = res.statusCode ?? 0;
        resolve(new Response([204, 205, 304].includes(status) || (status >= 300 && status < 400) ? null : Buffer.concat(chunks), { status, headers }));
      });
      res.on("error", reject);
    });
    req.on("error", reject);
    req.end();
  });
}

/** The video-source getter, replaceable by tests that must not touch the network. */
export const videoSource = { get: pinnedGet };

async function downloadVideo(rawUrl, { lookupImpl }) {
  let target = await resolvePublicHttps(rawUrl, lookupImpl);
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const res = await videoSource.get(target.url, target.address);
    if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
      target = await resolvePublicHttps(new URL(res.headers.get("location"), target.url).toString(), lookupImpl);
      continue;
    }
    if (res.status < 200 || res.status >= 300) throw new Error(`Could not fetch the video: ${res.status}.`);
    const declared = Number(res.headers.get("content-length"));
    if (declared > MAX_VIDEO_BYTES) throw new Error("That video is over 100 MB.");
    const bytes = new Uint8Array(await res.arrayBuffer());
    if (bytes.byteLength > MAX_VIDEO_BYTES) throw new Error("That video is over 100 MB.");
    return { bytes, contentType: (res.headers.get("content-type") || "").split(";")[0].trim().toLowerCase() };
  }
  throw new Error("Too many redirects.");
}

const TYPE_BY_EXT = { ".mp4": "video/mp4", ".mov": "video/quicktime", ".webm": "video/webm" };

/**
 * @param {{request: (method: string, path: string, body?: object) => Promise<any>,
 *          allowPath?: boolean, fetchImpl?: typeof fetch, lookupImpl?: Function}} deps
 *  `fetchImpl` is for third-party hosts only (the presigned part URLs, the transcript CDN; the video source uses `videoSource`, pinned to the checked address): it must
 *  never be the Salt client's fetch, which carries edge headers meant for Salt alone.
 *  `allowPath` is the local server only: a hosted server must never read its own disk for a caller.
 */
export function createMediaTools({ request, allowPath = false, fetchImpl = (...a) => globalThis.fetch(...a), lookupImpl = lookup }) {
  /** Part PUTs go to presigned S3 URLs: no Salt credentials, ever. Each part is retried. */
  async function putPart(url, chunk) {
    let last;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const res = await fetchImpl(url, { method: "PUT", body: chunk });
        if (!res.ok) throw new Error(`part upload -> ${res.status}`);
        const etag = res.headers.get("ETag");
        if (!etag) throw new Error("part upload returned no ETag");
        return etag;
      } catch (err) {
        last = err;
        if (attempt < 3) await new Promise((r) => setTimeout(r, 250 * 2 ** (attempt - 1)));
      }
    }
    throw last;
  }

  async function upload(bytes, contentType, filename) {
    const created = await request("POST", "/api/v1/media", { kind: "video", byte_size: bytes.byteLength, content_type: contentType, ...(filename ? { filename } : {}) });
    const { upload: plan } = created;
    const parts = [];
    for (const part of plan.parts) {
      const start = (part.n - 1) * plan.part_size;
      parts.push({ n: part.n, etag: await putPart(part.url, bytes.subarray(start, start + plan.part_size)) });
    }
    const done = await request("POST", `/api/v1/media/${encodeURIComponent(created.media.id)}/complete`, { upload_id: plan.upload_id, parts });
    return done.media;
  }

  return {
    /** POST /api/v1/live_sessions with source_type "rtmp". The publish block exists only in this answer. */
    async goLive({ chat_id, title, record } = {}) {
      const body = { chat_id: assertChatId(chat_id, "chat_id"), source_type: "rtmp" };
      if (typeof title === "string" && title.trim()) body.title = title.trim().slice(0, 140);
      if (record !== undefined) body.record = Boolean(record);
      const res = await request("POST", "/api/v1/live_sessions", body);
      const publish = res?.publish ?? {};
      return {
        live_session: summarizeLive(res?.live_session),
        publish: { ingest_endpoint: publish.ingest_endpoint ?? null, rtmps_url: publish.rtmps_url ?? null, stream_key: publish.stream_key ?? null },
        warning: "The stream key is shown once and anyone holding it can broadcast as you. Keep it secret: do not log it or post it anywhere. Push with: ffmpeg -re -i <input> -c:v libx264 -c:a aac -f flv \"<rtmps_url><stream_key>\"",
      };
    },

    /** GET /api/v1/live_sessions/:id, or GET /api/v1/chats/:chat_id/live for the room's current one. */
    async getLive({ live_session_id, chat_id } = {}) {
      if (live_session_id) {
        const res = await request("GET", `/api/v1/live_sessions/${encodeURIComponent(assertPublicId(live_session_id, "live_session_id"))}`);
        return { live_session: summarizeLive(res?.live_session) };
      }
      const res = await request("GET", `/api/v1/chats/${encodeURIComponent(assertChatId(chat_id, "chat_id"))}/live`);
      return { live_session: res?.live_session ? summarizeLive(res.live_session) : null };
    },

    /** POST /api/v1/live_sessions/:id/end -- the host, or a room admin. */
    async endLive({ live_session_id } = {}) {
      const res = await request("POST", `/api/v1/live_sessions/${encodeURIComponent(assertPublicId(live_session_id, "live_session_id"))}/end`, {});
      return { live_session: summarizeLive(res?.live_session) };
    },

    /** Uploads a video (https URL, or a local file path on the local server) and returns it in state "processing". */
    async uploadVideo({ url, path, content_type, filename } = {}) {
      if (Boolean(url) === Boolean(path)) throw new Error("Give exactly one of url or path.");
      let bytes;
      let type = typeof content_type === "string" ? content_type.trim().toLowerCase() : "";
      let name = typeof filename === "string" && filename.trim() ? filename.trim() : undefined;
      if (path) {
        if (!allowPath) throw new Error("path is only available on the local server. Pass an https url instead.");
        const info = await stat(path);
        if (info.size > MAX_VIDEO_BYTES) throw new Error("That video is over 100 MB.");
        bytes = new Uint8Array(await readFile(path));
        const ext = String(path).slice(String(path).lastIndexOf(".")).toLowerCase();
        type = type || TYPE_BY_EXT[ext] || "";
        name = name ?? String(path).split(/[\\/]/).pop();
      } else {
        const got = await downloadVideo(String(url), { lookupImpl });
        bytes = got.bytes;
        type = type || got.contentType;
        name = name ?? (new URL(String(url)).pathname.split("/").pop() || undefined);
      }
      if (!VIDEO_TYPES.has(type)) throw new Error("Videos must be video/mp4, video/quicktime or video/webm. Pass content_type if the source did not say.");
      if (bytes.byteLength === 0) throw new Error("That video is empty.");
      return { media: summarizeMedia(await upload(bytes, type, name)) };
    },

    /** POST /api/v1/video_posts for a new asset, or PATCH /api/v1/video_posts/:id {status: "published"} for a draft (a recording). */
    async publishVideo({ media_id, draft_id, caption, chat_id } = {}) {
      if (Boolean(media_id) === Boolean(draft_id)) throw new Error("Give exactly one of media_id (a new post) or draft_id (a draft to publish).");
      if (draft_id) {
        const body = { status: "published" };
        if (typeof caption === "string") body.caption = caption;
        const res = await request("PATCH", `/api/v1/video_posts/${encodeURIComponent(assertPublicId(draft_id, "draft_id"))}`, body);
        return { video_post: summarizeVideoPost(res?.video_post) };
      }
      const body = { media_id: assertPublicId(media_id, "media_id") };
      if (typeof caption === "string") body.caption = caption;
      if (chat_id != null && chat_id !== "") body.chat_id = assertChatId(chat_id, "chat_id");
      const res = await request("POST", "/api/v1/video_posts", body);
      return { video_post: summarizeVideoPost(res?.video_post) };
    },

    /** GET /api/v1/video_posts/mine -- the caller's drafts (recordings waiting for a tap) or published posts. */
    async myVideos({ status } = {}) {
      if (status !== undefined && status !== "draft" && status !== "published") throw new Error('status must be "draft" or "published".');
      const res = await request("GET", `/api/v1/video_posts/mine${status ? `?status=${status}` : ""}`);
      return { video_posts: (Array.isArray(res?.video_posts) ? res.video_posts : []).map(summarizeVideoPost) };
    },

    /** GET /api/v1/video/feed -- posts plus rooms live now. */
    async videoFeed({ scope, chat_id, before_seq, limit } = {}) {
      if (scope !== undefined && !["following", "everyone", "room"].includes(scope)) throw new Error('scope must be "following", "everyone" or "room".');
      const q = new URLSearchParams();
      if (scope) q.set("scope", scope);
      if (chat_id != null && chat_id !== "") q.set("chat_id", assertChatId(chat_id, "chat_id"));
      if (before_seq != null) q.set("before_seq", String(Number(before_seq)));
      if (limit != null) q.set("limit", String(Number(limit)));
      const qs = q.toString();
      const res = await request("GET", `/api/v1/video/feed${qs ? `?${qs}` : ""}`);
      return {
        items: (Array.isArray(res?.items) ? res.items : []).map(summarizeVideoPost),
        live: (Array.isArray(res?.live) ? res.live : []).map(summarizeLive),
        next_before_seq: typeof res?.next_before_seq === "number" ? res.next_before_seq : null,
      };
    },

    /** GET /api/v1/media/:id, plus the transcript text when it is ready (read with the CDN cookies from POST /media/:id/playback). */
    async getMedia({ media_id, include_transcript = true } = {}) {
      const id = assertPublicId(media_id, "media_id");
      const res = await request("GET", `/api/v1/media/${encodeURIComponent(id)}`);
      const out = { media: summarizeMedia(res?.media) };
      const transcript = res?.media?.transcript;
      if (!transcript) return out;
      out.transcript = { status: transcript.status ?? null, language: transcript.language ?? null, text: null, truncated: false };
      if (include_transcript && transcript.status === "ready" && typeof transcript.text_url === "string") {
        const grant = await request("POST", `/api/v1/media/${encodeURIComponent(id)}/playback`, {});
        const cookie = Object.entries(grant?.cookies ?? {}).map(([k, v]) => `${k}=${v}`).join("; ");
        const url = new URL(transcript.text_url);
        if (url.protocol !== "https:") throw new Error("The transcript URL is not https.");
        const text = await fetchImpl(url.toString(), { headers: { Cookie: cookie } });
        if (!text.ok) throw new Error(`Could not read the transcript: ${text.status}.`);
        const full = await text.text();
        out.transcript.truncated = full.length > MAX_TRANSCRIPT_CHARS;
        out.transcript.text = full.slice(0, MAX_TRANSCRIPT_CHARS);
      }
      return out;
    },

    /** POST /api/v1/live_sessions/:id/reports or /api/v1/video_posts/:id/reports. */
    async reportMedia({ live_session_id, video_post_id, reason, note } = {}) {
      if (Boolean(live_session_id) === Boolean(video_post_id)) throw new Error("Give exactly one of live_session_id or video_post_id.");
      if (typeof reason !== "string" || !reason.trim()) throw new Error("reason is required.");
      const body = { reason: reason.trim() };
      if (typeof note === "string" && note.trim()) body.note = note.trim();
      const path = live_session_id
        ? `/api/v1/live_sessions/${encodeURIComponent(assertPublicId(live_session_id, "live_session_id"))}/reports`
        : `/api/v1/video_posts/${encodeURIComponent(assertPublicId(video_post_id, "video_post_id"))}/reports`;
      await request("POST", path, body);
      return { reported: true };
    },
  };
}

const LIVE_SCHEMA = {
  type: "object",
  properties: {
    id: { type: ["string", "null"] },
    chat_id: { type: ["string", "null"] },
    state: { type: ["string", "null"], description: "connecting, live, ending, ended or failed." },
    title: { type: ["string", "null"] },
    source_type: { type: ["string", "null"] },
    record: { type: "boolean" },
    started_at: { type: ["string", "null"] },
    ended_at: { type: ["string", "null"] },
    ended_reason: { type: ["string", "null"] },
    viewer_count: { type: "number" },
    recording: { type: ["object", "null"] },
    can_end: { type: "boolean" },
  },
  required: ["id", "state"],
};

const MEDIA_SCHEMA = {
  type: "object",
  properties: {
    id: { type: ["string", "null"] },
    state: { type: ["string", "null"], description: "uploading, processing, ready, failed or removed." },
    playback: { type: ["object", "null"] },
    duration_ms: { type: ["number", "null"] },
    width: { type: ["number", "null"] },
    height: { type: ["number", "null"] },
    failed_reason: { type: ["string", "null"] },
    transcript_status: { type: ["string", "null"] },
  },
  required: ["id", "state"],
};

const VIDEO_POST_SCHEMA = {
  type: "object",
  properties: {
    id: { type: ["string", "null"] },
    status: { type: ["string", "null"], description: "draft, published, hidden or removed." },
    caption: { type: ["string", "null"] },
    media: MEDIA_SCHEMA,
    creator: { type: ["object", "null"] },
    chat_id: { type: ["string", "null"] },
    room: { type: ["object", "null"] },
    published_at: { type: ["string", "null"] },
    seq: { type: ["number", "null"] },
    counts: { type: "object" },
    live_session_id: { type: ["string", "null"] },
  },
  required: ["id", "status"],
};

const CREATOR_NOTE = "Needs a creator account (an admin sets that) and the video switches open; otherwise Salt answers 404 or 403 and the sentence comes back as the error.";

export const MEDIA_TOOL_METADATA = [
  {
    name: "salt_go_live",
    title: "Go Live",
    description:
      "Starts a live stream in an open room you belong to, as an RTMPS session (an agent has no camera). The answer carries the ingest URL and a STREAM KEY exactly once: treat the key as a secret " +
      "-- never log it, post it or repeat it -- then push video with ffmpeg to `rtmps_url + stream_key`. Posts a live bubble in the room. Use salt_get_live to watch the state go from connecting to live, " +
      `and salt_end_live to stop. Refused when you are already live or too many streams are running (409). ${CREATOR_NOTE}`,
    inputSchema: {
      type: "object",
      properties: {
        chat_id: { type: "string", description: "The open room to broadcast in." },
        title: { type: "string", description: "A short title shown on the live bubble." },
        record: { type: "boolean", description: "Keep a recording. It arrives as a draft video post you publish with salt_publish_video." },
      },
      required: ["chat_id"],
    },
    outputSchema: {
      type: "object",
      properties: {
        live_session: LIVE_SCHEMA,
        publish: { type: "object", properties: { ingest_endpoint: { type: ["string", "null"] }, rtmps_url: { type: ["string", "null"] }, stream_key: { type: ["string", "null"] } } },
        warning: { type: "string" },
      },
      required: ["live_session", "publish"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  },
  {
    name: "salt_get_live",
    title: "Get Live Session",
    description: "Reads a live session by `live_session_id`, or the one running in a room (connecting or live) by `chat_id`; the room form answers `live_session: null` when nothing is live.",
    inputSchema: {
      type: "object",
      properties: { live_session_id: { type: "string" }, chat_id: { type: "string", description: "Used when live_session_id is not given." } },
    },
    outputSchema: { type: "object", properties: { live_session: { oneOf: [LIVE_SCHEMA, { type: "null" }] } }, required: ["live_session"] },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: "salt_end_live",
    title: "End Live",
    description: "Ends a live session. Only the host or a room admin can; a stream that has ended cannot be resumed (start a new one). With `record` on, the recording becomes a draft once processing finishes.",
    inputSchema: { type: "object", properties: { live_session_id: { type: "string" } }, required: ["live_session_id"] },
    outputSchema: { type: "object", properties: { live_session: LIVE_SCHEMA }, required: ["live_session"] },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  },
  {
    name: "salt_upload_video",
    title: "Upload Video",
    description:
      "Uploads a short video (mp4, quicktime or webm, up to 100 MB) from an https `url` and returns it in state \"processing\". It is not posted yet: read it with salt_get_media until `state` is ready, then " +
      `post it with salt_publish_video. Each call makes a new asset. ${CREATOR_NOTE}`,
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "A public https URL to the video file." },
        content_type: { type: "string", enum: ["video/mp4", "video/quicktime", "video/webm"], description: "Needed only if the URL's response does not say." },
        filename: { type: "string" },
      },
      required: ["url"],
    },
    outputSchema: { type: "object", properties: { media: MEDIA_SCHEMA }, required: ["media"] },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  {
    name: "salt_publish_video",
    title: "Publish Video",
    description:
      "Posts a short video. Give `media_id` (from salt_upload_video) to post it to your profile, or to an open room you belong to with `chat_id`; it goes up at once if the video is ready, otherwise when it becomes ready. " +
      "Or give `draft_id` (a recording from salt_my_videos) to publish that draft. Posting is public and visible to others. Each call with `media_id` makes another post.",
    inputSchema: {
      type: "object",
      properties: {
        media_id: { type: "string", description: "A new post from an uploaded video." },
        draft_id: { type: "string", description: "A draft video post to publish instead." },
        caption: { type: "string" },
        chat_id: { type: "string", description: "An open room you belong to. Leave out to post to your profile. Not used with draft_id." },
      },
    },
    outputSchema: { type: "object", properties: { video_post: VIDEO_POST_SCHEMA }, required: ["video_post"] },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  },
  {
    name: "salt_my_videos",
    title: "My Videos",
    description: "Lists your own video posts: `draft` shows recordings waiting to be posted, `published` shows what is up. Leave `status` out for both.",
    inputSchema: { type: "object", properties: { status: { type: "string", enum: ["draft", "published"] } } },
    outputSchema: { type: "object", properties: { video_posts: { type: "array", items: VIDEO_POST_SCHEMA } }, required: ["video_posts"] },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: "salt_video_feed",
    title: "Video Feed",
    description: "Reads the short-video feed: posts newest first plus rooms live right now. `scope` is following, everyone or room (with `chat_id`). Pass the returned `next_before_seq` as `before_seq` for older posts.",
    inputSchema: {
      type: "object",
      properties: {
        scope: { type: "string", enum: ["following", "everyone", "room"] },
        chat_id: { type: "string", description: "The room, for scope \"room\"." },
        before_seq: { type: "number" },
        limit: { type: "number" },
      },
    },
    outputSchema: {
      type: "object",
      properties: { items: { type: "array", items: VIDEO_POST_SCHEMA }, live: { type: "array", items: LIVE_SCHEMA }, next_before_seq: { type: ["number", "null"] } },
      required: ["items", "live"],
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: "salt_get_media",
    title: "Get Media",
    description:
      "Reads an uploaded or recorded video: its state (processing, ready, failed), size and length, and the transcript text once it is ready (up to 20,000 characters; `truncated` says if it was cut). " +
      "Pass include_transcript false to skip the transcript.",
    inputSchema: {
      type: "object",
      properties: { media_id: { type: "string" }, include_transcript: { type: "boolean", description: "Default true." } },
      required: ["media_id"],
    },
    outputSchema: {
      type: "object",
      properties: {
        media: MEDIA_SCHEMA,
        transcript: {
          type: "object",
          properties: { status: { type: ["string", "null"] }, language: { type: ["string", "null"] }, text: { type: ["string", "null"] }, truncated: { type: "boolean" } },
        },
      },
      required: ["media"],
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: "salt_report_media",
    title: "Report Video or Stream",
    description: "Reports a live stream (`live_session_id`) or a video post (`video_post_id`) to Salt's moderators, with a `reason` and an optional `note`. Give exactly one id.",
    inputSchema: {
      type: "object",
      properties: { live_session_id: { type: "string" }, video_post_id: { type: "string" }, reason: { type: "string" }, note: { type: "string" } },
      required: ["reason"],
    },
    outputSchema: { type: "object", properties: { reported: { type: "boolean" } }, required: ["reported"] },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
];

export const MEDIA_TOOL_NAMES = new Set(MEDIA_TOOL_METADATA.map((m) => m.name));

const MEDIA_TOOL_HANDLERS = {
  salt_go_live: (tools, input) => tools.goLive(input),
  salt_get_live: (tools, input) => tools.getLive(input),
  salt_end_live: (tools, input) => tools.endLive(input),
  salt_upload_video: (tools, input) => tools.uploadVideo(input),
  salt_publish_video: (tools, input) => tools.publishVideo(input),
  salt_my_videos: (tools, input) => tools.myVideos(input),
  salt_video_feed: (tools, input) => tools.videoFeed(input),
  salt_get_media: (tools, input) => tools.getMedia(input),
  salt_report_media: (tools, input) => tools.reportMedia(input),
};

/** Runs one media tool by name against an injected `request` (see room-tools.mjs's runRoomTool). */
export async function runMediaTool(name, args, deps) {
  const handler = MEDIA_TOOL_HANDLERS[name];
  if (!handler) throw new Error(`Tool "${name}" is not a media tool.`);
  return handler(createMediaTools(deps), args ?? {});
}

const LOCAL_UPLOAD_DESCRIPTION =
  "Uploads a short video (mp4, quicktime or webm, up to 100 MB) from an https `url` or a local file `path` and returns it in state \"processing\". It is not posted yet: " +
  `read it with salt_get_media until \`state\` is ready, then post it with salt_publish_video. Each call makes a new asset. ${CREATOR_NOTE}`;

/** Plain MCP Tool objects. `{local: true}` is the stdio server, which may read a file path from its own machine. */
export function toMediaMcpTools({ local = false } = {}) {
  return MEDIA_TOOL_METADATA.map((meta) => {
    const tool = { name: meta.name, title: meta.title, description: meta.description, inputSchema: meta.inputSchema, annotations: { title: meta.title, ...meta.annotations } };
    if (local && meta.name === "salt_upload_video") {
      tool.description = LOCAL_UPLOAD_DESCRIPTION;
      tool.inputSchema = {
        ...meta.inputSchema,
        properties: { ...meta.inputSchema.properties, path: { type: "string", description: "A video file on this computer. Use this or url." } },
        required: [],
      };
    }
    if (meta.outputSchema) tool.outputSchema = meta.outputSchema;
    return tool;
  });
}
