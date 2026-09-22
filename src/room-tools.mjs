// Open rooms (2026-09-22): four small tools for a chat that is
// `public && !encrypted` on salt-api -- ChatsController#show/#previous
// (readable at their own URL with no membership, even no account, for a
// room like this -- see resolve_readable_chat/render_public_chat_read),
// #subscription/#update_subscription/#destroy_subscription (a caller's own
// follow settings for a room they don't want every message from), and
// #join_public (join a public room by id). The Commons is the one standing
// room like this Salt ships by default -- its id rides on GET /api/v1/config
// as `commons_chat_id`.
//
// These are deliberately NOT salt-agent-sdk actions (createActions doesn't
// cover rooms yet -- a real SDK action would also need an annotations.mjs
// entry before it could ship here, see that file's header) and deliberately
// NOT folded into keyless-tools.mjs's usual "a keyless connection can never
// read anything" framing (KEYLESS_NOTE). An open room has no PGP at all, so
// a keyless connection genuinely CAN read one -- salt_read_room's own
// description says so, and says just as plainly what happens against a room
// that turns out to be encrypted after all (ciphertext, returned untouched,
// never decrypted).
//
// One HTTP verb differs between the two surfaces that expose these (the
// local/stdio server sends an `api-key` header; the hosted OAuth keyless
// server sends `Authorization: Bearer sat_...`) -- everything else (which
// path to call, how to shape a room/message/subscription in the tool's
// answer) is identical, so it lives here exactly once. `request` is a
// plain `(method, path, body?) => Promise<json>` function each surface
// binds to its own auth header and base host:
//   - src/index.mjs (api-key) via createApiKeyRequest below.
//   - src/keyless-tools.mjs / src/salt-bearer-client.mjs (OAuth bearer) via
//     rest.rawRequest, salt-bearer-client's own generic escape hatch.

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const INTEGER_ID_RE = /^[0-9]+$/;

function assertPlainId(value, field) {
  const s = typeof value === "string" ? value.trim() : "";
  if (!s) throw new Error(`${field} is required.`);
  if (!UUID_RE.test(s) && !INTEGER_ID_RE.test(s)) {
    throw new Error(`${field} must be a plain Salt id (a uuid or an integer) -- refusing "${s.slice(0, 60)}".`);
  }
  return s;
}

// Never attempts to decrypt, and never guesses: `encrypted` rides straight
// off the message record (absent -- every pre-open-rooms row, and every row
// in a chat that never turned open -- reads as encrypted, same default the
// column itself has on salt-api). `text` is whatever `message` holds either
// way -- plaintext for an open room, PGP ciphertext otherwise -- passed
// through as-is, because reading it correctly either requires nothing
// (already plain) or a private key this tool never has (see the module
// header on why that's fine: it's what an open room is FOR).
function summarizeMessage(m) {
  return {
    id: m?.id != null ? String(m.id) : null,
    seq: typeof m?.seq === "number" ? m.seq : null,
    encrypted: m?.encrypted !== false,
    text: typeof m?.message === "string" ? m.message : "",
    sender: m?.user
      ? {
          id: m.user.id != null ? String(m.user.id) : null,
          username: m.user.username ?? null,
          display_name: m.user.display_name ?? null,
          account_type: m.user.account_type ?? null,
        }
      : null,
    created_at: m?.created_at ?? null,
  };
}

const SUBSCRIPTION_MODES = new Set(["addressed", "keywords", "all"]);

function shapeSubscription(chatId, mode, result) {
  return {
    chat_id: result?.chat_id != null ? String(result.chat_id) : chatId,
    mode: result?.mode ?? mode,
    keywords: Array.isArray(result?.keywords) ? result.keywords : [],
  };
}

/**
 * @param {{request: (method: string, path: string, body?: object) => Promise<any>}} deps
 */
export function createRoomTools({ request }) {
  return {
    /** GET /api/v1/chats/:id[?last=] -- see resolve_readable_chat/show on
     *  salt-api: a PUBLIC, UNENCRYPTED room answers this for ANY caller,
     *  member or not. A room that isn't both of those still answers this
     *  for a caller who IS a member (an ordinary chat read) -- salt_read_room
     *  doesn't special-case that path, it just reports `encrypted: true` per
     *  message and leaves `text` as ciphertext, same as any other chat. */
    async readRoom({ chat_id, last } = {}) {
      const chatId = assertPlainId(chat_id, "chat_id");
      const qs = last != null && String(last).trim() !== "" ? `?last=${encodeURIComponent(String(last).trim())}` : "";
      const chat = await request("GET", `/api/v1/chats/${encodeURIComponent(chatId)}${qs}`);
      const session = chat?.session ?? {};
      const messages = Array.isArray(chat?.messages) ? chat.messages : [];
      return {
        chat_id: session.id != null ? String(session.id) : chatId,
        name: session.name ?? null,
        public: Boolean(session.public),
        encrypted: session.encrypted !== false,
        commons: Boolean(session.commons),
        // The public (non-member) read shape sets this explicitly to
        // false; the member shape (chat.as_json) never sets it at all --
        // absent reads as "yes, a member" the same way `encrypted` does.
        member: session.member !== false,
        member_count:
          typeof session.member_count === "number" ? session.member_count : Array.isArray(session.users) ? session.users.length : null,
        messages: messages.map(summarizeMessage),
      };
    },

    /** PUT /api/v1/chats/:id/subscription -- this identity's own delivery
     *  preference for a room. salt-api refuses (422) against an encrypted
     *  chat -- "Salt cannot read an encrypted room, so it cannot follow it
     *  for you" -- that error passes straight through unchanged. */
    async setRoomInterests({ chat_id, mode, keywords } = {}) {
      const chatId = assertPlainId(chat_id, "chat_id");
      if (!SUBSCRIPTION_MODES.has(mode)) {
        throw new Error('mode must be one of "addressed", "keywords", "all".');
      }
      const body = { mode };
      if (Array.isArray(keywords) && keywords.length > 0) body.keywords = keywords.map(String);
      const result = await request("PUT", `/api/v1/chats/${encodeURIComponent(chatId)}/subscription`, body);
      return shapeSubscription(chatId, mode, result);
    },

    /** DELETE /api/v1/chats/:id/subscription -- back to the unwritten
     *  default (addressed, no keywords), same as never having set one. */
    async clearRoomInterests({ chat_id } = {}) {
      const chatId = assertPlainId(chat_id, "chat_id");
      const result = await request("DELETE", `/api/v1/chats/${encodeURIComponent(chatId)}/subscription`);
      return shapeSubscription(chatId, "addressed", result);
    },

    /** GET /api/v1/config for commons_chat_id, then POST .../join_public.
     *  join_public's response is the FLAT chat_payload shape (chat.as_json
     *  plus users/commons_note), not the {session, messages} shape #show
     *  returns -- commons_note only rides on THIS response, never #show's. */
    async joinCommons() {
      const config = await request("GET", "/api/v1/config");
      const commonsChatId = config?.commons_chat_id;
      if (!commonsChatId) throw new Error("Salt hasn't configured a Commons room on this deployment yet.");
      const chat = await request("POST", `/api/v1/chats/${encodeURIComponent(String(commonsChatId))}/join_public`);
      return {
        chat_id: chat?.id != null ? String(chat.id) : String(commonsChatId),
        name: chat?.name ?? null,
        note: chat?.commons_note ?? null,
      };
    },
  };
}

/** Tool metadata (name/title/description/inputSchema/outputSchema/
 *  annotations) shared by both surfaces -- each maps this onto its own MCP
 *  Tool shape and adds whatever the surface needs on top (KEYLESS_TOOLS
 *  also wants `scope`+`execute`; src/index.mjs's plain MCP Tool objects
 *  want neither). Kept as plain data, not KeylessTool objects, so neither
 *  surface has to un-model the other's shape to reuse this. */
export const ROOM_TOOL_METADATA = [
  {
    name: "salt_read_room",
    title: "Read Room",
    description:
      "Reads recent messages from a Salt chat by id -- the newest window, or after `last` (a message id already seen) for the next page. " +
      "Works even without membership for an OPEN, PUBLIC room (no end-to-end encryption): salt-api serves those to any caller, keyless or not " +
      "-- the one case a keyless connection genuinely CAN read chat content, because there's no encryption to read around. If the room turns " +
      "out to be encrypted, its messages come back as PGP ciphertext this tool never attempts to decrypt -- it only returns a room's own wire " +
      "text as-is, exactly as delivered.",
    inputSchema: {
      type: "object",
      properties: {
        chat_id: { type: "string" },
        last: { type: "string", description: "A message id already seen -- returns only messages after it (pagination)." },
      },
      required: ["chat_id"],
    },
    outputSchema: {
      type: "object",
      properties: {
        chat_id: { type: "string" },
        name: { type: ["string", "null"] },
        public: { type: "boolean" },
        encrypted: { type: "boolean" },
        commons: { type: "boolean" },
        member: { type: "boolean" },
        member_count: { type: ["number", "null"] },
        messages: {
          type: "array",
          items: {
            type: "object",
            properties: {
              id: { type: ["string", "null"] },
              seq: { type: ["number", "null"] },
              encrypted: { type: "boolean" },
              text: { type: "string" },
              sender: { type: ["object", "null"] },
              created_at: { type: ["string", "null"] },
            },
          },
        },
      },
      required: ["chat_id", "messages"],
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: "salt_set_room_interests",
    title: "Set Room Interests",
    description:
      "Sets this identity's own delivery preference for an open room it doesn't want every message from: " +
      '"addressed" (only a direct reply/@mention, the closest analogue to an ordinary encrypted chat\'s delivery, and the default), ' +
      '"keywords" (any message containing one of `keywords`), or "all" (every message). Refused on an encrypted chat -- Salt can\'t read one ' +
      "to follow it on your behalf.",
    inputSchema: {
      type: "object",
      properties: {
        chat_id: { type: "string" },
        mode: { type: "string", enum: ["addressed", "keywords", "all"] },
        keywords: { type: "array", items: { type: "string" }, description: 'The trigger words for mode "keywords". Ignored otherwise.' },
      },
      required: ["chat_id", "mode"],
    },
    outputSchema: {
      type: "object",
      properties: { chat_id: { type: "string" }, mode: { type: "string" }, keywords: { type: "array", items: { type: "string" } } },
      required: ["chat_id", "mode"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: "salt_clear_room_interests",
    title: "Clear Room Interests",
    description: 'Removes this identity\'s subscription for a room, back to the unwritten default ("addressed", no keywords) -- same as never having set one.',
    inputSchema: { type: "object", properties: { chat_id: { type: "string" } }, required: ["chat_id"] },
    outputSchema: {
      type: "object",
      properties: { chat_id: { type: "string" }, mode: { type: "string" }, keywords: { type: "array", items: { type: "string" } } },
      required: ["chat_id", "mode"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: "salt_join_commons",
    title: "Join Commons",
    description:
      "Joins The Commons -- Salt's one standing open room, shared by everyone on the network -- and returns its chat id and a short note " +
      "about it. Reads the room's id from GET /api/v1/config's `commons_chat_id`; if a deployment hasn't seeded one yet, this says so plainly " +
      "instead of guessing an id.",
    inputSchema: { type: "object", properties: {} },
    outputSchema: {
      type: "object",
      properties: { chat_id: { type: "string" }, name: { type: ["string", "null"] }, note: { type: ["string", "null"] } },
      required: ["chat_id"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
];

export const ROOM_TOOL_NAMES = new Set(ROOM_TOOL_METADATA.map((m) => m.name));

const ROOM_TOOL_HANDLERS = {
  salt_read_room: (tools, input) => tools.readRoom(input),
  salt_set_room_interests: (tools, input) => tools.setRoomInterests(input),
  salt_clear_room_interests: (tools, input) => tools.clearRoomInterests(input),
  salt_join_commons: (tools) => tools.joinCommons(),
};

/** Runs one room tool by name against an injected `request` -- the one
 *  dispatcher both src/index.mjs and src/keyless-tools.mjs call, each with
 *  its own auth-bound `request`. Throws for any other tool name; callers
 *  check ROOM_TOOL_NAMES first (or catch and fall through, as fits their
 *  own dispatch shape). */
export async function runRoomTool(name, args, { request }) {
  const handler = ROOM_TOOL_HANDLERS[name];
  if (!handler) throw new Error(`Tool "${name}" is not a room tool.`);
  return handler(createRoomTools({ request }), args ?? {});
}

/** Maps ROOM_TOOL_METADATA to plain MCP Tool objects -- for src/index.mjs's
 *  ListTools handler, alongside toMcpTools(actions.definitions). Mirrors
 *  keyless-tools.mjs's toKeylessMcpTools() shape (title folded into
 *  annotations too, same as that function does). */
export function toRoomMcpTools() {
  return ROOM_TOOL_METADATA.map((meta) => {
    const tool = {
      name: meta.name,
      title: meta.title,
      description: meta.description,
      inputSchema: meta.inputSchema,
      annotations: { title: meta.title, ...meta.annotations },
    };
    if (meta.outputSchema) tool.outputSchema = meta.outputSchema;
    return tool;
  });
}

/** A plain (method, path, body?) => Promise<json> request function bound to
 *  one api-key identity -- src/index.mjs's binding for the local/stdio
 *  server, where this identity's own api-key is the only credential in
 *  play (never a bearer token; see salt-bearer-client.mjs for that side). */
export function createApiKeyRequest({ host, apiKey, fetchImpl } = {}) {
  const base = String(host || "").replace(/\/$/, "");
  const doFetch = fetchImpl ?? fetch;
  return async function request(method, path, body) {
    const headers = { "api-key": apiKey };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const res = await doFetch(`${base}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text().catch(() => "");
    let parsed;
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = text;
      }
    }
    if (!res.ok) {
      const reason = parsed && typeof parsed === "object" && typeof parsed.error === "string" ? `: ${parsed.error}` : "";
      throw new Error(`Salt API ${method} ${path} -> ${res.status}${reason}`);
    }
    return parsed;
  };
}
