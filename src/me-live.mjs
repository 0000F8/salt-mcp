// The live connection of `salt-mcp --as-me`: the owner's own Salt chats, received AS THEY ARRIVE over Salt's
// Action Cable socket instead of fetched on demand. NO POLLING: nothing here re-fetches on a timer.
//
//   - One socket per process, opened lazily (first live tool call, or at start when a watch list is given), with the
//     session's current token as the LAST Sec-WebSocket-Protocol entry (that is how salt-api's UserChannel
//     authenticates a linked device or a JWT), then `subscribe UserChannel`.
//   - Reconnects are event-driven on close (backoff 1 s doubling to 30 s with jitter). The one timer is a liveness
//     check on an OPEN socket: Action Cable pings every 3 s, and 15 s without one means the socket is dead.
//   - The cable never replays what it missed, so after every (re)connect each watched chat and each pending waiter's
//     chat is caught up once with `GET /api/v1/chats/:id?last=<newest id seen>`.
//   - A small ring per chat (last 50) dedupes by id; a re-broadcast of a known id is an edit or a tombstone and is
//     delivered only when the text or the deleted state changed.
//   - Frames flagged `observer` or carrying `request_state` are skipped unless the chat is explicitly watched.
//
// Everything outside the process is injected (the WebSocket class, timers, the session's `get`/`liveAuth`, the
// decoder), so tests run it with fakes and never touch the network.

const RING_SIZE = 50;
const SUBPROTOCOL = "actioncable-v1-json";
const FATAL_REASONS = new Set(["unauthorized", "device_unlinked", "invalid_request", "server_restart_never"]);

const messageTime = (m) => ((m.seq ?? null) !== null ? Number(m.seq) : Date.parse(m.created_at || 0) || 0);

/** A frame on the user stream is a chat message when it has no `type` and carries a chat and an id. */
export const isMessageFrame = (p) => p && typeof p === "object" && !("type" in p) && p.chat_id !== undefined && p.chat_id !== null && p.id !== undefined && p.id !== null;

/**
 * @param {{
 *   session: { get(path: string): Promise<any>, liveAuth(): Promise<{url: string, token: string}> },
 *   decode: (msg: any) => Promise<{mine: boolean, text: string, deleted: boolean, out: any} | null>,
 *   chatMeta: (chatId: string) => Promise<{name: string, newestId: string|null}>,
 *   notify?: (params: {content: string, meta: Record<string,string>}) => Promise<void>|void,
 *   WebSocketImpl?: typeof WebSocket, now?: () => number, random?: () => number,
 *   setTimeoutImpl?: typeof setTimeout, clearTimeoutImpl?: typeof clearTimeout,
 *   setIntervalImpl?: typeof setInterval, clearIntervalImpl?: typeof clearInterval,
 *   backoff?: {base: number, max: number}, pingTimeoutMs?: number, livenessCheckMs?: number, log?: (m: string) => void,
 * }} deps
 */
export function createLive({
  session, decode, decodeWork, chatMeta, notify,
  WebSocketImpl = globalThis.WebSocket, now = () => Date.now(), random = Math.random,
  setTimeoutImpl = setTimeout, clearTimeoutImpl = clearTimeout, setIntervalImpl = setInterval, clearIntervalImpl = clearInterval,
  backoff = { base: 1000, max: 30000 }, pingTimeoutMs = 15000, livenessCheckMs = 5000, log = () => {},
}) {
  let notifier = notify;
  let ws = null;
  let opening = null; // promise for the first confirmed subscription
  let connected = false;
  let stopped = false;
  let fatal = null;
  let since = null;
  let lastMessageAt = null;
  let lastPingAt = 0;
  let reconnects = 0;
  let attempts = 0;
  let retryTimer = null;
  let liveness = null;
  let queue = Promise.resolve();

  const rings = new Map(); // chat id -> [{id, mine, text, deleted, out}]
  const newest = new Map(); // chat id -> newest message id seen
  const watches = new Map(); // chat id -> {name}
  const names = new Map();
  const waiters = new Set(); // {chatId|null, from, resolve, reject, timer}
  let openWaiters = []; // [{resolve, reject}] waiting for the first confirmation

  const failNow = (error) => {
    fatal = error;
    stopped = true;
    connected = false;
    teardown();
    for (const w of waiters) {
      clearTimeoutImpl(w.timer);
      w.reject(error);
    }
    waiters.clear();
    for (const o of openWaiters) o.reject(error);
    openWaiters = [];
  };

  function teardown() {
    if (retryTimer) clearTimeoutImpl(retryTimer);
    retryTimer = null;
    if (liveness) clearIntervalImpl(liveness);
    liveness = null;
    const old = ws;
    ws = null;
    if (old) {
      old.onopen = old.onmessage = old.onclose = old.onerror = null;
      try {
        old.close();
      } catch {
        // already closed
      }
    }
  }

  // ---------- messages ----------

  const ringOf = (chatId) => {
    let r = rings.get(chatId);
    if (!r) rings.set(chatId, (r = []));
    return r;
  };

  /**
   * A message in a lane under a chat (coaching_for_chat_id): only its work reports matter (decodeWork returns null for
   * anything else), and they belong to the PARENT chat.
   */
  async function processLane(msg) {
    const parent = String(msg.coaching_for_chat_id);
    const watched = watches.has(parent);
    if ((msg.observer || msg.request_state) && !watched) return;
    if (!decodeWork) return;
    const ring = ringOf(`lane:${msg.chat_id}`);
    const id = String(msg.id);
    if (ring.some((e) => e.id === id)) return;
    const w = await decodeWork(msg);
    if (!w || w.mine) return;
    const entry = { id, mine: false, text: w.title, deleted: false, out: w.out };
    ring.push(entry);
    if (ring.length > RING_SIZE) ring.shift();
    for (const x of [...waiters]) {
      if (x.includeWork && (x.chatId === null || x.chatId === parent)) {
        x.entries.push(entry);
        if (!x.settle) x.settle = Promise.resolve().then(() => finish(x, false));
      }
    }
    if (watched) await push(parent, entry, w.out.status, "work");
    return entry;
  }

  async function process(msg) {
    if (msg.coaching_for_chat_id !== undefined && msg.coaching_for_chat_id !== null) return processLane(msg);
    const chatId = String(msg.chat_id);
    const watched = watches.has(chatId);
    if ((msg.observer || msg.request_state) && !watched) return;
    if (msg.event_type) return; // system events (joins, calls, cards) are not messages to wake for
    const decoded = await decode(msg);
    if (!decoded) return;
    const id = String(msg.id);
    const ring = ringOf(chatId);
    const known = ring.find((e) => e.id === id);
    if (known) {
      if (known.text === decoded.text && known.deleted === decoded.deleted) return;
      known.text = decoded.text;
      known.deleted = decoded.deleted;
      known.out = decoded.out;
      if (watched && !decoded.mine) await push(chatId, known, decoded.deleted ? "deleted" : "edited");
      return;
    }
    const entry = { id, mine: decoded.mine, text: decoded.text, deleted: decoded.deleted, out: decoded.out };
    ring.push(entry);
    if (ring.length > RING_SIZE) ring.shift();
    newest.set(chatId, id);
    lastMessageAt = new Date(now()).toISOString();
    for (const w of [...waiters]) {
      if ((w.chatId === null || w.chatId === chatId) && (w.from === "anyone" || !entry.mine)) {
        w.entries.push(entry);
        if (!w.settle) {
          // let a burst that arrives together (a catch-up) resolve as one result
          w.settle = Promise.resolve().then(() => finish(w, false));
        }
      }
    }
    if (watched && !entry.mine) await push(chatId, entry, "new");
    return entry;
  }

  /** Serialized so decoding never reorders messages and the ring dedupes reliably. */
  const ingest = (msg) => {
    const run = queue.then(() => process(msg)).catch((err) => log(`live: dropped a frame: ${err?.message || err}`));
    queue = run;
    return run;
  };

  async function push(chatId, entry, event, kind = "message") {
    if (!notifier) return;
    const from = entry.out?.from || {};
    try {
      await notifier({
        content: entry.out?.text ?? entry.text,
        meta: {
          chat_id: chatId,
          chat_name: String(watches.get(chatId)?.name ?? names.get(chatId) ?? ""),
          message_id: entry.id,
          sender: String(from.name ?? ""),
          sender_handle: String(from.handle ?? ""),
          sender_type: String(from.type ?? ""),
          time: String(entry.out?.time ?? ""),
          event,
          ...(kind === "work" ? { kind: "work", status: String(entry.out?.status ?? ""), title: String(entry.text ?? "") } : {}),
        },
      });
    } catch (err) {
      log(`live: channel notification failed: ${err?.message || err}`);
    }
  }

  function finish(w, timedOut) {
    if (!waiters.delete(w)) return;
    clearTimeoutImpl(w.timer);
    w.resolve(timedOut ? { messages: [], timed_out: true } : { messages: w.entries.map((e) => e.out), timed_out: false });
  }

  async function catchUp(chatId) {
    const last = newest.get(chatId);
    if (!last) return;
    let page;
    try {
      page = await session.get(`/api/v1/chats/${encodeURIComponent(chatId)}?last=${encodeURIComponent(last)}`);
    } catch (err) {
      log(`live: catch-up of chat ${chatId} failed: ${err?.message || err}`);
      return;
    }
    const batch = (Array.isArray(page?.messages) ? page.messages : []).map((m) => ({ ...m, chat_id: m.chat_id ?? chatId, id: m.id ?? m.message_id }));
    batch.sort((a, b) => messageTime(a) - messageTime(b));
    for (const m of batch) await ingest(m);
  }

  async function resumed() {
    const chats = new Set(watches.keys());
    let any = false;
    for (const w of waiters) {
      if (w.chatId) chats.add(w.chatId);
      else any = true;
    }
    if (any) for (const id of newest.keys()) chats.add(id);
    for (const id of chats) await catchUp(id);
  }

  // ---------- socket ----------

  const scheduleReconnect = () => {
    if (stopped || retryTimer) return;
    const delay = Math.min(backoff.max, backoff.base * 2 ** Math.min(attempts, 16)) * (0.75 + random() * 0.5);
    attempts += 1;
    retryTimer = setTimeoutImpl(() => {
      retryTimer = null;
      connect().catch((err) => {
        log(`live: reconnect failed: ${err?.message || err}`);
        scheduleReconnect();
      });
    }, delay);
    retryTimer.unref?.();
  };

  async function onLost() {
    const wasConnected = connected;
    connected = false;
    if (liveness) clearIntervalImpl(liveness);
    liveness = null;
    ws = null;
    if (stopped) return;
    if (!wasConnected) {
      // Closed before it ever subscribed: the token may be dead (a handshake 401 is just a close). Ask once with a normal call.
      try {
        await session.get("/api/v1/chats/unread");
      } catch (err) {
        if (err?.status === 401 || err?.kind === "link_pending" || err?.kind === "unlinked" || err?.kind === "sign_in") {
          failNow(new Error(`Salt closed the live connection: ${err.message}`));
          return;
        }
      }
    }
    scheduleReconnect();
  }

  async function connect() {
    if (stopped) return;
    const { url, token } = await session.liveAuth();
    const socket = new WebSocketImpl(url, [SUBPROTOCOL, token]);
    ws = socket;
    lastPingAt = now();
    socket.onmessage = (ev) => {
      if (ws !== socket) return;
      let frame;
      try {
        frame = JSON.parse(typeof ev.data === "string" ? ev.data : String(ev.data));
      } catch {
        return;
      }
      onFrame(socket, frame);
    };
    socket.onclose = () => {
      if (ws === socket) onLost();
    };
    socket.onerror = () => {}; // a close always follows
  }

  function onFrame(socket, frame) {
    if (frame.type === "welcome") {
      lastPingAt = now();
      socket.send(JSON.stringify({ command: "subscribe", identifier: JSON.stringify({ channel: "UserChannel" }) }));
    } else if (frame.type === "ping") {
      lastPingAt = now();
    } else if (frame.type === "confirm_subscription") {
      const first = since === null;
      connected = true;
      attempts = 0;
      lastPingAt = now();
      since = new Date(now()).toISOString();
      if (!first) reconnects += 1;
      if (!liveness) {
        liveness = setIntervalImpl(() => {
          if (connected && now() - lastPingAt > pingTimeoutMs) {
            log("live: no ping for 15 s; reconnecting");
            const dead = ws;
            connected = false;
            if (dead) {
              dead.onclose = null;
              try {
                dead.close();
              } catch {
                // gone already
              }
            }
            onLost();
          }
        }, livenessCheckMs);
        liveness.unref?.();
      }
      for (const o of openWaiters) o.resolve();
      openWaiters = [];
      resumed().catch((err) => log(`live: resume failed: ${err?.message || err}`));
    } else if (frame.type === "reject_subscription") {
      failNow(new Error("Salt refused the live subscription."));
    } else if (frame.type === "disconnect") {
      if (frame.reconnect === false || FATAL_REASONS.has(frame.reason)) {
        failNow(new Error(`Salt ended the live connection${frame.reason ? ` (${frame.reason})` : ""}. Relink or restart salt-mcp.`));
      }
      // reconnect:true: the close that follows reconnects
    } else if (frame.type === undefined && frame.message !== undefined) {
      if (isMessageFrame(frame.message)) ingest(frame.message);
    }
  }

  /** Opens the socket (once) and resolves when it is subscribed. Throws the plain error of a stopped connection. */
  function ensureOpen() {
    if (fatal) return Promise.reject(fatal);
    if (connected) return Promise.resolve();
    if (!opening) {
      opening = new Promise((resolve, reject) => {
        openWaiters.push({ resolve, reject });
      });
      opening.finally(() => {
        opening = null;
      }).catch(() => {});
      if (!ws && !retryTimer) {
        connect().catch((err) => {
          // could not even start (not linked yet, no password): the caller sees the plain reason; a later call tries again
          const o = openWaiters;
          openWaiters = [];
          for (const w of o) w.reject(err);
        });
      }
    }
    return opening;
  }

  // ---------- public ----------

  async function wait({ chat_id = null, after_message_id = null, timeout_s = 120, from = "others", include_work = false } = {}) {
    const chatId = chat_id === null ? null : String(chat_id);
    if (after_message_id !== null && !chatId) throw new Error("after_message_id needs a chat_id.");
    await ensureOpen();
    if (chatId) await seedChat(chatId);
    const ok = (e) => from === "anyone" || !e.mine;
    if (chatId && after_message_id !== null) {
      const after = String(after_message_id);
      const ring = ringOf(chatId);
      const idx = ring.findIndex((e) => e.id === after);
      let ready;
      if (idx >= 0) ready = ring.slice(idx + 1).filter(ok);
      else {
        const before = new Set(ring.map((e) => e.id));
        newest.set(chatId, after);
        await catchUp(chatId);
        ready = ringOf(chatId).filter((e) => !before.has(e.id) && ok(e));
      }
      if (ready.length) return { messages: ready.map((e) => e.out), timed_out: false };
    }
    return new Promise((resolve, reject) => {
      const w = { chatId, from, includeWork: include_work, resolve, reject, entries: [], settle: null, timer: null };
      w.timer = setTimeoutImpl(() => finish(w, true), Math.max(0, timeout_s) * 1000);
      waiters.add(w);
    });
  }

  /** Records the chat's newest id and name without delivering anything, so a later catch-up knows where to start. */
  async function seedChat(chatId) {
    if (names.has(chatId)) return names.get(chatId);
    const meta = await chatMeta(chatId);
    names.set(chatId, meta.name);
    if (meta.newestId && !newest.has(chatId)) newest.set(chatId, String(meta.newestId));
    return meta.name;
  }

  async function watch(chatId, on = true) {
    const id = String(chatId);
    if (on) {
      const name = await seedChat(id);
      watches.set(id, { name });
      await ensureOpen();
    } else {
      watches.delete(id);
    }
    return watchList();
  }

  const watchList = () => [...watches].map(([id, w]) => ({ chat_id: id, name: w.name }));

  return {
    wait,
    watch,
    watchList,
    ensureOpen,
    setNotifier(fn) {
      notifier = fn;
    },
    status: () => ({ connected, since, last_message_at: lastMessageAt, watching: watchList(), reconnects, ...(fatal ? { error: fatal.message } : {}) }),
    stop() {
      stopped = true;
      connected = false;
      teardown();
      for (const w of waiters) clearTimeoutImpl(w.timer);
      waiters.clear();
    },
  };
}
