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
//   - Gate: the SENDER's user id must be on the allow-list (SALT_CHANNEL_ALLOW).
//     Ids only, never usernames (a handle can be squatted by a self-registered
//     agent), and the sender, never the chat: in a group the chat is shared
//     with people who are not on the list. Claude Code can run commands, so a
//     stranger's message must never reach it. With no allow-list, or a handle
//     that does not resolve to an id, the mode refuses to start.
//   - Out: the `reply` tool, only into ENCRYPTED chats that delivered an allowed
//     message in this process AND whose every other member is allow-listed
//     (checked against the API on each reply), so an answer never reaches a
//     stranger. Open rooms are neither read nor written unless
//     SALT_CHANNEL_OPEN_ROOMS=1.
//   - Approvals: Claude Code's permission relay. A card's state is stored in
//     plaintext on Salt's server, so the card carries no tool input: the details
//     go as a normal encrypted message first, into an encrypted chat whose
//     members are all allow-listed, and the card only says "details above" with
//     Allow / Deny buttons. A tap from an allowed sender becomes the verdict.
//   - One process per agent (a lock file): the socket has a single cursor.
//
// stdout is the MCP protocol: every diagnostic here goes through `log`
// (stderr).

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { z } from "zod";
import pkg from "salt-agent-sdk";
import { buildGuard, sendWithFreshKeys } from "./send-guard.mjs";

// salt-agent-sdk is CJS, so its exports are read off the default object (as index.mjs does).
const { createSocketClient, encryptFor } = pkg;

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
    "Only chats that sent you an allow-listed message in this session can be replied to, and only while every other member of the chat is allow-listed too. " +
    "The message is encrypted for every member before sending.",
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
export const DEFAULT_AGENT_REPLIES = 20;

export class ChannelConfigError extends Error {}

const truthy = (v) => /^(1|true|yes|on)$/i.test(String(v ?? "").trim());

/**
 * Reads channel-mode settings from argv + env. Channel mode is switched on by
 * the `--channel` argument ONLY (an env var could be inherited by a server the
 * owner did not mean to turn into a channel). Returns `{enabled: false}` when
 * off. When on, throws ChannelConfigError unless SALT_CHANNEL_ALLOW names at
 * least one sender: fail closed.
 */
export function loadChannelConfig(env = process.env, argv = process.argv.slice(2)) {
  if (!argv.includes("--channel")) return { enabled: false };

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

  // The SDK stops delivering an agent sender's messages after this many in a person-free chat (default 2).
  // An allow-listed AGENT account needs more room than that, but it stays a ceiling: it is the runaway guard.
  const rawReplies = String(env.SALT_CHANNEL_AGENT_REPLIES ?? "").trim();
  const agentReplies = rawReplies === "" ? DEFAULT_AGENT_REPLIES : Number(rawReplies);
  if (!Number.isInteger(agentReplies) || agentReplies < 1) {
    throw new ChannelConfigError(`SALT_CHANNEL_AGENT_REPLIES must be a positive whole number, got "${rawReplies.slice(0, 40)}".`);
  }
  return { enabled: true, allow: entries, approverChat: approverChat || undefined, openRooms: truthy(env.SALT_CHANNEL_OPEN_ROOMS), agentReplies };
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
 * Turns every allow-listed handle into a user id through the API (exact-match
 * contact search) and returns the Set of ids the gate uses. FAILS CLOSED: a
 * handle that is not found, or a lookup that errors, throws ChannelConfigError.
 * Usernames are never matched at message time: anyone can register an agent
 * under a handle nobody holds yet, so a name is not an identity.
 */
export async function resolveAllowList({ client, apiKey, allow }) {
  const ids = new Set([...allow.ids].map(idKey));
  for (const handle of allow.handles) {
    let found;
    try {
      found = await client.searchContacts(apiKey, { username: handle });
    } catch (err) {
      throw new ChannelConfigError(`Could not look up the allow-listed handle @${handle} (${err?.message || err}). Refusing to start: use its user id in SALT_CHANNEL_ALLOW, or retry when Salt is reachable.`);
    }
    const match = (found ?? []).find((u) => String(u.username ?? "").toLowerCase() === handle);
    if (!match) {
      throw new ChannelConfigError(`The allow-listed handle @${handle} does not resolve to a Salt user. Refusing to start: fix the handle, or use its user id in SALT_CHANNEL_ALLOW.`);
    }
    ids.add(idKey(match.id));
  }
  return ids;
}

/**
 * Why a chat must not receive anything from this channel, or null when it may:
 * it has to be end-to-end encrypted, and every member other than the agent
 * (observers included, they read too) has to be allow-listed. `chat` is the SDK's
 * getChat() answer, `{encrypted, users}`.
 */
export function unsafeChatReason({ chat, selfId, allowedIds }) {
  if (!chat || !Array.isArray(chat.users)) return "its members could not be read";
  if (chat.encrypted === false) return "it is an open room (not end-to-end encrypted)";
  const others = chat.users.filter((u) => idKey(u.id) !== idKey(selfId));
  if (others.length === 0) return "nobody else is in it";
  const stranger = others.find((u) => !allowedIds.has(idKey(u.id)));
  if (stranger) return `${stranger.username ? `@${stranger.username}` : `user ${stranger.id}`} is a member and is not on SALT_CHANNEL_ALLOW`;
  return null;
}

/** A chat id that may carry approval cards, or a ChannelConfigError saying why not. Used for SALT_CHANNEL_APPROVER_CHAT at startup. */
export async function verifyApproverChat({ client, apiKey, selfId, chatId, allowedIds }) {
  let chat;
  try {
    chat = await client.getChat(apiKey, chatId);
  } catch (err) {
    throw new ChannelConfigError(`SALT_CHANNEL_APPROVER_CHAT ${chatId} could not be read (${err?.message || err}). Refusing to start.`);
  }
  const reason = unsafeChatReason({ chat, selfId, allowedIds });
  if (reason) {
    throw new ChannelConfigError(
      `SALT_CHANNEL_APPROVER_CHAT ${chatId} cannot be used: ${reason}. It must be an encrypted chat whose other members are all on SALT_CHANNEL_ALLOW. Refusing to start.`
    );
  }
}

/**
 * Claims the single-process lock for one agent: the socket has ONE cursor per
 * agent, so two channel processes would each swallow part of the backlog. The
 * lock is a file holding the owner's pid under the temp dir; a pid that is no
 * longer running is a stale lock and is replaced. Returns a release function;
 * throws ChannelConfigError when a live process holds it.
 */
export function acquireChannelLock(agentId, { dir = os.tmpdir(), pid = process.pid, isAlive = pidIsAlive } = {}) {
  const file = path.join(dir, `salt-mcp-channel-${String(agentId).replace(/[^A-Za-z0-9_-]/g, "_")}.lock`);
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      fs.writeFileSync(file, String(pid), { flag: "wx", mode: 0o600 });
      return () => {
        try {
          if (fs.readFileSync(file, "utf8").trim() === String(pid)) fs.unlinkSync(file);
        } catch {
          // already gone
        }
      };
    } catch (err) {
      if (err?.code !== "EEXIST") throw err;
    }
    let holder = NaN;
    try {
      holder = Number.parseInt(fs.readFileSync(file, "utf8"), 10);
    } catch {
      continue; // vanished between the two calls: try to create it again
    }
    if (Number.isInteger(holder) && holder !== pid && isAlive(holder)) {
      throw new ChannelConfigError(
        `Another salt-mcp --channel (pid ${holder}) already holds agent ${agentId}'s socket, and an agent's socket has a single cursor: two readers would each lose part of the messages. ` +
          `Stop it first (if it is not running, delete ${file}).`
      );
    }
    try {
      fs.unlinkSync(file); // stale: its process is gone
    } catch {
      // someone else cleaned it first
    }
  }
  throw new ChannelConfigError(`Could not take the channel lock ${file}.`);
}

function pidIsAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err?.code === "EPERM";
  }
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

/** Meta values land inside the <channel ...> tag Claude reads: no quotes, angle brackets or line breaks, and short. */
const metaValue = (v) => clip(String(v ?? "").replace(/[<>"]/g, "").replace(/[\r\n\u2028\u2029]+/g, " "), 200);

/** meta keys Claude Code keeps are letters, digits and underscores only; values are sanitized strings. */
export function buildChannelEvent({ chatId, messageId, sender, senderId, encrypted, text, attachment }) {
  let content = String(text ?? "");
  if (attachment) {
    const note = `[attachment: ${metaValue(attachment.filename || "file")} (${metaValue(attachment.contentType || "unknown type")}, ${Number(attachment.size) || "?"} bytes)]`;
    content = content ? `${content}\n${note}` : note;
  }
  return {
    content,
    meta: {
      chat_id: metaValue(chatId),
      message_id: metaValue(messageId),
      sender: metaValue(sender),
      sender_id: metaValue(senderId),
      encrypted: String(Boolean(encrypted)),
    },
  };
}

/** Text that goes into card state or a card button: one line, bounded. */
const oneLine = (v, max) => clip(String(v ?? "").replace(/\s+/g, " ").trim(), max);

/**
 * The bridge. Everything outside the process is injected so tests run it with
 * fakes: `notify(method, params)` writes an MCP notification, `createSocket`
 * builds the live socket client from `{onMessage, onCardInteraction}`, `encrypt`
 * is the PGP encrypt step. `allowedIds` is the Set of allow-listed user ids
 * (resolveAllowList's answer).
 */
export function createChannelBridge({
  client,
  caller,
  allowedIds: allowedInput,
  approverChat,
  openRooms = false,
  notify,
  createSocket,
  encrypt = encryptFor,
  log = () => {},
}) {
  const allowedIds = new Set([...allowedInput].map(idKey));

  /** chat id -> whether it was encrypted when an ALLOWED message arrived from it. Only such chats can be replied to. */
  const seenChats = new Map();
  /** request id -> the card that asks about it. */
  const pending = new Map();
  let lastAllowedChat;
  let lastAllowedSender;
  let socket;

  const isAllowed = (id) => allowedIds.has(idKey(id));

  async function onMessage(ctx) {
    if (idKey(ctx.senderId) === idKey(caller.saltAppId)) return; // our own reply coming back
    if (!isAllowed(ctx.senderId)) {
      log(`dropped a message in chat ${ctx.chatId} from sender ${ctx.senderId}${ctx.sender?.username ? ` (@${ctx.sender.username})` : ""}: not on SALT_CHANNEL_ALLOW`);
      return;
    }
    const encrypted = ctx.encrypted !== false;
    if (!encrypted && !openRooms) {
      log(`dropped an open-room message in chat ${ctx.chatId}: open rooms are off (set SALT_CHANNEL_OPEN_ROOMS=1 to allow them)`);
      return;
    }
    const event = buildChannelEvent({
      chatId: ctx.chatId,
      messageId: ctx.messageId,
      sender: ctx.sender?.username || ctx.sender?.display_name || ctx.senderId,
      senderId: ctx.senderId,
      encrypted,
      text: ctx.text,
      attachment: ctx.attachment,
    });
    if (!event.content) return;

    const chatId = String(ctx.chatId);
    seenChats.set(chatId, { encrypted });
    lastAllowedChat = chatId;
    lastAllowedSender = String(ctx.senderId);
    await notify(CHANNEL_METHOD, event);
  }

  /** Encrypts for exactly the members just checked (never a separately fetched list) and posts. Errors propagate. */
  async function sendEncrypted(chatId, users, text) {
    // The send guard: fingerprints of the keys used. A stale_recipient_keys refusal re-encrypts once to the keys Salt returns.
    await sendWithFreshKeys(users, async (current) => {
      const recipientKeys = current.filter((u) => idKey(u.id) !== idKey(caller.saltAppId) && u.public_key).map((u) => u.public_key);
      if (recipientKeys.length === 0) throw new Error(`chat ${chatId} has no member public keys to encrypt for.`);
      const message = await encrypt(text, recipientKeys);
      const senderMessage = await encrypt(text, [caller.publicKey]);
      const guard = buildGuard(current, caller.saltAppId);
      // delegations, mentions, then the options (guard fields need a salt-agent-sdk with the key-reset release; older ones ignore them)
      return client.postMessage(caller.apiKey, chatId, message, senderMessage, undefined, undefined, guard.recipientFingerprints ? guard : undefined);
    });
  }

  /** A fresh member list for the chat, or a thrown reason it must not be used. */
  async function requireSafeChat(chatId) {
    const chat = await client.getChat(caller.apiKey, chatId);
    const reason = unsafeChatReason({ chat, selfId: caller.saltAppId, allowedIds });
    if (reason) throw new Error(`Won't send into chat ${chatId}: ${reason}.`);
    return chat;
  }

  /** The `reply` tool. */
  async function reply({ chat_id: chatId, text } = {}) {
    const id = String(chatId ?? "").trim();
    if (typeof text !== "string" || !text.trim()) throw new Error("reply needs non-empty `text`.");
    if (text.length > MAX_REPLY_CHARS) throw new Error(`reply text is over ${MAX_REPLY_CHARS} characters; send it in parts.`);
    const seen = seenChats.get(id);
    if (!seen) {
      throw new Error(
        `Can't reply to chat "${id.slice(0, 60)}": no allow-listed message has arrived from it in this session. ` +
          "Reply only to the chat_id of a <channel source=\"salt\"> message."
      );
    }
    const openRoomReply = async () => {
      if (!openRooms) throw new Error(`Won't send into chat ${id}: it is an open room, and open rooms are off (SALT_CHANNEL_OPEN_ROOMS=1 turns them on).`);
      await client.postPlainMessage(caller.apiKey, id, text);
      return { sent: true, chat_id: id, encrypted: false };
    };
    if (!seen.encrypted) return openRoomReply();

    const chat = await client.getChat(caller.apiKey, id);
    if (chat?.encrypted === false) return openRoomReply();
    const reason = unsafeChatReason({ chat, selfId: caller.saltAppId, allowedIds });
    if (reason) throw new Error(`Won't send into chat ${id}: ${reason}.`);
    await sendEncrypted(id, chat.users, text);
    return { sent: true, chat_id: id, encrypted: true };
  }

  /** The chat approvals go to, with its members, or undefined. Always an encrypted chat of allow-listed people only. */
  async function findApprover() {
    const candidates = approverChat ? [approverChat] : lastAllowedChat ? [lastAllowedChat] : [];
    for (const chatId of candidates) {
      try {
        return { chatId, chat: await requireSafeChat(chatId) };
      } catch (err) {
        log(`not asking for approvals in chat ${chatId}: ${err?.message || err}`);
      }
    }
    if (approverChat || !lastAllowedSender) return undefined;
    // The last message came from a chat strangers share (or an open room): ask the same person in their own 1:1 instead.
    try {
      const opened = await client.createOrGetChat(caller.apiKey, lastAllowedSender);
      const chatId = String(opened?.id ?? "");
      if (chatId) return { chatId, chat: await requireSafeChat(chatId) };
    } catch (err) {
      log(`could not use a 1:1 with ${lastAllowedSender} for approvals: ${err?.message || err}`);
    }
    return undefined;
  }

  async function onPermissionRequest(params) {
    const target = await findApprover();
    if (!target) {
      log(`permission request ${params.request_id} (${params.tool_name}) has no safe Salt chat to ask in; answer it in the terminal`);
      return;
    }
    const tool = oneLine(params.tool_name, 80);
    // The details are the sensitive part (commands, file contents): they travel as an ordinary
    // end-to-end encrypted message. The card's state is stored in plaintext on Salt's server.
    const details =
      `Claude Code wants to use ${tool}\n${clip(params.description, 600)}` +
      (params.input_preview ? `\n${clip(params.input_preview, 3000)}` : "") +
      "\nAllow or deny it with the buttons below.";
    await sendEncrypted(target.chatId, target.chat.users, details);

    // salt-api refuses a restricted_to id that is not a member of the chat, so it is built from the member list itself.
    const restricted = target.chat.users.filter((u) => idKey(u.id) !== idKey(caller.saltAppId) && isAllowed(u.id)).map((u) => u.id);
    const button = (verb, label) => ({ type: "button", action_id: `perm_${verb}_${params.request_id}`, label, restricted_to: restricted });
    const blocks = [
      { type: "section", text: `Claude wants to use ${tool} — details above` },
      { type: "actions", elements: [button("allow", "Allow"), button("deny", "Deny")] },
    ];
    const posted = await client.postCard(caller.apiKey, target.chatId, blocks, `Claude wants to use ${tool}`);
    const cardId = posted?.resource_id ?? posted?.resource?.id;
    if (cardId == null) {
      log(`permission request ${params.request_id}: the card posted but returned no id, so its buttons cannot be matched`);
      return;
    }
    pending.set(params.request_id, { cardId: String(cardId), chatId: String(target.chatId), tool });
    while (pending.size > MAX_PENDING_PERMISSIONS) pending.delete(pending.keys().next().value);
  }

  const outcomeBlocks = (text) => [{ type: "section", text }];

  async function onCardInteraction(ctx) {
    const match = /^perm_(allow|deny)_([a-z]{5})$/.exec(String(ctx.actionId ?? ""));
    if (!match) return; // not one of ours
    if (!isAllowed(ctx.user?.id)) {
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
    const who = ctx.user?.username ? `@${oneLine(ctx.user.username, 40)}` : oneLine(ctx.user?.display_name, 40) || "someone";
    await updateCardSafely(ctx.cardId, `${behavior === "allow" ? "Allowed" : "Denied"} by ${who}: ${entry.tool}`);
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
export function sdkSocketFactory({ client, identities, config, caller, log, maxAgentToAgentReplies = DEFAULT_AGENT_REPLIES, socketClient = createSocketClient }) {
  const logger = { info: (m) => log(m), error: (m) => log(m) };
  return (handlers) =>
    socketClient({
      client,
      identities,
      pgpPassphrase: config.pgpPassphrase,
      host: config.host,
      apiKey: caller.apiKey,
      agentId: caller.saltAppId,
      maxAgentToAgentReplies,
      logger,
      ...handlers,
    });
}
