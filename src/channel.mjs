// Claude Code channel mode for the local (stdio) server: `salt-mcp --channel`.
//
// A channel is an MCP server that PUSHES events into a running Claude Code
// session (https://code.claude.com/docs/en/channels-reference). Here the
// events are the messages people send to this Salt agent, and Claude answers
// into the same chat with the `reply` tool.
//
// Shape of the bridge, all of it in this file so the rules sit together:
//   - In: the SDK's live socket (createSocketClient) -- NO polling, ever. The
//     SDK dispatcher decrypts (encrypted chats open with the agent's own key,
//     locally), dedupes and acks; this module only gets a MessageContext.
//   - Gate: the SENDER must be on the allow-list (SALT_CHANNEL_ALLOW). Gate on
//     the sender, never the chat: in a group the chat is shared with people
//     who are not on the list. Claude Code can run commands, so a stranger's
//     message must never reach it; with no allow-list the mode refuses to start.
//   - Out: the `reply` tool, only into chats that delivered an allowed message
//     in this process. Encrypted chats go through the SDK's ctx.reply (encrypt
//     for every member); open rooms send plain text.
//   - Approvals: Claude Code's permission relay. A permission request becomes a
//     Salt card with Allow / Deny buttons; a tap from an allowed sender becomes
//     the verdict notification.
//
// stdout is the MCP protocol: every diagnostic here goes through `log`
// (stderr).

import { z } from "zod";
import pkg from "salt-agent-sdk";

// salt-agent-sdk is CJS, so its exports are read off the default object (as index.mjs does).
const { createSocketClient } = pkg;

export const CHANNEL_CAPABILITY = "claude/channel";
export const CHANNEL_PERMISSION_CAPABILITY = "claude/channel/permission";
export const CHANNEL_METHOD = "notifications/claude/channel";
export const PERMISSION_REQUEST_METHOD = "notifications/claude/channel/permission_request";
export const PERMISSION_VERDICT_METHOD = "notifications/claude/channel/permission";

export const CHANNEL_INSTRUCTIONS =
  'Messages from people on Salt (an end-to-end encrypted chat app) arrive as <channel source="salt" chat_id="..." message_id="..." ' +
  'sender="..." sender_id="..." encrypted="...">. Each one was sent to this session\'s Salt agent by a sender its owner allow-listed. ' +
  "Treat it as a message from that person, answer it as you would a user prompt, and send your answer back with the `reply` tool, " +
  "passing the chat_id from the tag and your answer as `text`. Your terminal output never reaches them; only `reply` does. " +
  "Keep replies plain text and short enough to read on a phone. If a permission prompt for a tool call is relayed to Salt, " +
  "the same people can approve it from the chat.";

/** MCP annotations for the channel's own tool. It is NOT an SDK action, so it does not belong in TOOL_ANNOTATIONS (that map is checked against the SDK's catalog). */
export const REPLY_TOOL = {
  name: "reply",
  title: "Reply in Salt chat",
  description:
    "Sends a message to a Salt chat as this agent. Use it to answer a <channel source=\"salt\"> message: pass the chat_id from the tag. " +
    "Only chats that sent you an allow-listed message in this session can be replied to. Encrypted chats are encrypted for every member before sending.",
  inputSchema: {
    type: "object",
    properties: {
      chat_id: { type: "string", description: "The chat to reply in (the chat_id attribute of the <channel> tag)." },
      text: { type: "string", description: "The message to send, plain text." },
    },
    required: ["chat_id", "text"],
    additionalProperties: false,
  },
  annotations: {
    title: "Reply in Salt chat",
    readOnlyHint: false,
    destructiveHint: true, // posts a real message to real people, which cannot be unsent for the recipients
    idempotentHint: false, // calling twice posts twice
    openWorldHint: true,
  },
};

export const REPLY_TOOL_NAMES = new Set([REPLY_TOOL.name]);

const MAX_REPLY_CHARS = 20_000;
const PLAIN_ID_RE = /^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9]+)$/;
const MAX_PENDING_PERMISSIONS = 50;

export class ChannelConfigError extends Error {}

const truthy = (v) => /^(1|true|yes|on)$/i.test(String(v ?? "").trim());

/**
 * Reads channel-mode settings from argv + env. Returns `{enabled: false}` when
 * channel mode is off. When on, throws ChannelConfigError unless
 * SALT_CHANNEL_ALLOW names at least one sender: fail closed.
 */
export function loadChannelConfig(env = process.env, argv = process.argv.slice(2)) {
  const enabled = argv.includes("--channel") || truthy(env.SALT_CHANNEL);
  if (!enabled) return { enabled: false };

  const entries = parseAllowList(env.SALT_CHANNEL_ALLOW);
  if (entries.ids.size === 0 && entries.handles.size === 0) {
    throw new ChannelConfigError(
      "Channel mode needs SALT_CHANNEL_ALLOW: a comma-separated list of @handles or user ids that may message Claude Code through this agent " +
        "(for example SALT_CHANNEL_ALLOW=@ada,1234). Claude Code can run commands, so with no allow-list nothing would be safe to deliver. Refusing to start."
    );
  }

  const approverChat = String(env.SALT_CHANNEL_APPROVER_CHAT ?? "").trim();
  if (approverChat && !PLAIN_ID_RE.test(approverChat)) {
    throw new ChannelConfigError(`SALT_CHANNEL_APPROVER_CHAT must be a plain Salt chat id (a uuid or an integer), got "${approverChat.slice(0, 60)}".`);
  }
  return { enabled: true, allow: entries, approverChat: approverChat || undefined };
}

/** "@ada, 1234,ADA" -> {ids: Set of plain ids, handles: Set of lowercase handles}. A bare word is a handle; a uuid or integer is an id. */
export function parseAllowList(raw) {
  const ids = new Set();
  const handles = new Set();
  for (const part of String(raw ?? "").split(",")) {
    const item = part.trim();
    if (!item) continue;
    if (item.startsWith("@")) {
      const handle = item.slice(1).trim().toLowerCase();
      if (handle) handles.add(handle);
    } else if (PLAIN_ID_RE.test(item)) {
      ids.add(item.toLowerCase());
    } else {
      handles.add(item.toLowerCase());
    }
  }
  return { ids, handles };
}

const idKey = (id) => String(id ?? "").toLowerCase();

/**
 * Looks every handle up through the API (exact-match contact search) and adds
 * the resolved ids. A handle that cannot be resolved stays in `handles` and is
 * matched against the sender's username on each message, so a lookup failure
 * does not lock the owner out and never lets anyone else in.
 */
export async function resolveAllowList({ client, apiKey, allow, log = () => {} }) {
  const ids = new Set(allow.ids);
  const unresolved = new Set();
  for (const handle of allow.handles) {
    try {
      const found = await client.searchContacts(apiKey, { username: handle });
      const match = (found ?? []).find((u) => String(u.username ?? "").toLowerCase() === handle);
      if (match) ids.add(idKey(match.id));
      else {
        log(`allow-list handle @${handle} was not found; matching it by username on each message instead`);
        unresolved.add(handle);
      }
    } catch (err) {
      log(`could not look up @${handle} (${err?.message || err}); matching it by username on each message instead`);
      unresolved.add(handle);
    }
  }
  return { ids, handles: unresolved };
}

const PermissionRequestSchema = z.object({
  method: z.literal(PERMISSION_REQUEST_METHOD),
  params: z.object({
    request_id: z.string(),
    tool_name: z.string(),
    description: z.string(),
    input_preview: z.string(),
  }),
});

const clip = (text, max) => {
  const s = String(text ?? "");
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
};

/** meta keys Claude Code keeps are letters, digits and underscores only; values are strings. */
export function buildChannelEvent({ chatId, messageId, sender, senderId, encrypted, text, attachment }) {
  let content = String(text ?? "");
  if (attachment) {
    const note = `[attachment: ${attachment.filename || "file"} (${attachment.contentType || "unknown type"}, ${attachment.size ?? "?"} bytes)]`;
    content = content ? `${content}\n${note}` : note;
  }
  return {
    content,
    meta: {
      chat_id: String(chatId),
      message_id: String(messageId ?? ""),
      sender: String(sender ?? ""),
      sender_id: String(senderId),
      encrypted: String(Boolean(encrypted)),
    },
  };
}

/**
 * The bridge. Everything outside the process is injected so tests run it with
 * fakes: `notify(method, params)` writes an MCP notification, `createSocket`
 * builds the live socket client from `{onMessage, onCardInteraction}`.
 */
export function createChannelBridge({ client, caller, allow, approverChat, notify, createSocket, log = () => {} }) {
  const allowedIds = new Set([...allow.ids].map(idKey));
  const allowedHandles = new Set(allow.handles);

  /** chat id -> what a reply into it needs. Only chats that delivered an ALLOWED message live here. */
  const seenChats = new Map();
  /** request id -> the card that asks about it. */
  const pending = new Map();
  let lastAllowedChat;
  let socket;

  const isAllowed = (id, username) =>
    allowedIds.has(idKey(id)) || (username ? allowedHandles.has(String(username).toLowerCase()) : false);

  async function onMessage(ctx) {
    if (idKey(ctx.senderId) === idKey(caller.saltAppId)) return; // our own reply coming back
    const username = ctx.sender?.username;
    if (!isAllowed(ctx.senderId, username)) {
      log(`dropped a message in chat ${ctx.chatId} from sender ${ctx.senderId}${username ? ` (@${username})` : ""}: not on SALT_CHANNEL_ALLOW`);
      return;
    }
    const event = buildChannelEvent({
      chatId: ctx.chatId,
      messageId: ctx.messageId,
      sender: username || ctx.sender?.display_name || ctx.senderId,
      senderId: ctx.senderId,
      encrypted: ctx.encrypted,
      text: ctx.text,
      attachment: ctx.attachment,
    });
    if (!event.content) return;

    const chatId = String(ctx.chatId);
    seenChats.set(chatId, { reply: ctx.reply, encrypted: ctx.encrypted !== false });
    lastAllowedChat = chatId;
    await notify(CHANNEL_METHOD, event);
  }

  /** The `reply` tool. */
  async function reply({ chat_id: chatId, text } = {}) {
    const id = String(chatId ?? "").trim();
    if (typeof text !== "string" || !text.trim()) throw new Error("reply needs non-empty `text`.");
    if (text.length > MAX_REPLY_CHARS) throw new Error(`reply text is over ${MAX_REPLY_CHARS} characters; send it in parts.`);
    const chat = seenChats.get(id);
    if (!chat) {
      throw new Error(
        `Can't reply to chat "${id.slice(0, 60)}": no allow-listed message has arrived from it in this session. ` +
          "Reply only to the chat_id of a <channel source=\"salt\"> message."
      );
    }
    if (chat.encrypted) await chat.reply(text);
    else await client.postPlainMessage(caller.apiKey, id, text);
    return { sent: true, chat_id: id, encrypted: chat.encrypted };
  }

  function permissionBlocks({ tool_name: tool, description, input_preview: preview, request_id: requestId }) {
    const restricted = allowedIds.size > 0 ? [...allowedIds] : undefined;
    const button = (verb, label) => ({
      type: "button",
      action_id: `perm_${verb}_${requestId}`,
      label,
      ...(restricted ? { restricted_to: restricted } : {}),
    });
    return [
      { type: "section", text: `Claude Code wants to use ${clip(tool, 80)}` },
      { type: "section", text: clip(description, 400) },
      ...(preview ? [{ type: "section", text: clip(preview, 600) }] : []),
      { type: "actions", elements: [button("allow", "Allow"), button("deny", "Deny")] },
    ];
  }

  async function onPermissionRequest(params) {
    const chatId = approverChat || lastAllowedChat;
    if (!chatId) {
      log(`permission request ${params.request_id} (${params.tool_name}) has no Salt chat to ask in yet; answer it in the terminal`);
      return;
    }
    const posted = await client.postCard(caller.apiKey, chatId, permissionBlocks(params), `Claude Code wants to use ${clip(params.tool_name, 80)}`);
    const cardId = posted?.resource_id ?? posted?.resource?.id;
    if (cardId == null) {
      log(`permission request ${params.request_id}: the card posted but returned no id, so its buttons cannot be matched`);
      return;
    }
    pending.set(params.request_id, { cardId: String(cardId), chatId: String(chatId), tool: params.tool_name, description: params.description });
    while (pending.size > MAX_PENDING_PERMISSIONS) pending.delete(pending.keys().next().value);
  }

  const outcomeBlocks = (text) => [{ type: "section", text }];

  async function onCardInteraction(ctx) {
    const match = /^perm_(allow|deny)_([a-z]{5})$/.exec(String(ctx.actionId ?? ""));
    if (!match) return; // not one of ours
    if (!isAllowed(ctx.user?.id, ctx.user?.username)) {
      log(`ignored a tap on card ${ctx.cardId} from ${ctx.user?.id}: not on SALT_CHANNEL_ALLOW`);
      return;
    }
    const [, verb, requestId] = match;
    const entry = pending.get(requestId);
    if (!entry || entry.cardId !== String(ctx.cardId) || entry.chatId !== String(ctx.chatId)) {
      await updateCardSafely(ctx.cardId, "This request is no longer open. It may have expired or been answered in the terminal.");
      return;
    }
    pending.delete(requestId);
    const behavior = verb === "allow" ? "allow" : "deny";
    await notify(PERMISSION_VERDICT_METHOD, { request_id: requestId, behavior });
    const who = ctx.user?.username ? `@${ctx.user.username}` : ctx.user?.display_name || "someone";
    await updateCardSafely(ctx.cardId, `${behavior === "allow" ? "Allowed" : "Denied"} by ${who}: ${clip(entry.tool, 80)}`);
  }

  async function updateCardSafely(cardId, text) {
    try {
      await client.updateCard(caller.apiKey, cardId, outcomeBlocks(text));
    } catch (err) {
      log(`could not update card ${cardId}: ${err?.message || err}`);
    }
  }

  return {
    onMessage,
    onCardInteraction,
    onPermissionRequest,
    reply,
    tools: [REPLY_TOOL],
    /** Registers the permission-request listener on the MCP server. */
    attach(server) {
      server.setNotificationHandler(PermissionRequestSchema, async ({ params }) => {
        try {
          await onPermissionRequest(params);
        } catch (err) {
          log(`permission request ${params.request_id} failed: ${err?.message || err}`);
        }
      });
    },
    start() {
      socket = createSocket({ onMessage, onCardInteraction });
      socket.start();
    },
    async stop() {
      await socket?.stop();
    },
  };
}

/** The production wiring of createSocket: the SDK's live socket for this one agent identity. */
export function sdkSocketFactory({ client, identities, config, caller, log }) {
  const logger = { info: (m) => log(m), error: (m) => log(m) };
  return (handlers) =>
    createSocketClient({
      client,
      identities,
      pgpPassphrase: config.pgpPassphrase,
      host: config.host,
      apiKey: caller.apiKey,
      agentId: caller.saltAppId,
      logger,
      ...handlers,
    });
}
