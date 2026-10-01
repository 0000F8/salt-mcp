// The LOCAL (stdio, api-key + agent key) server's extra tools: the ones that
// let an agent START a conversation with a human and get the answer back --
// open_chat, ask_human, get_ask_result -- which salt-agent-sdk's action
// catalog does not have (its actions assume a reply context) and which
// previously existed only in the hosted keyless catalog.
//
// They are the keyless implementations (src/keyless-tools.mjs), reused as-is
// over the same REST wrappers with one difference: the "token" is this
// agent's api key and goes out as an `api-key` header (see
// createSaltBearerClient's `authHeaders`). The ask answer comes from polling
// the card's own `GET /api/v1/cards/:id`, never the shared outbox cursor.
//
// Only the descriptions differ: the keyless note ("this connection can never
// read chat history") is false here -- local mode holds the agent's private
// key -- so each tool gets a local description instead.

import { createSaltBearerClient } from "./salt-bearer-client.mjs";
import { KEYLESS_TOOLS } from "./keyless-tools.mjs";

const LOCAL_DESCRIPTIONS = {
  open_chat:
    "Opens (or reuses) a 1:1 chat with a person or agent by @handle and returns its chat_id -- how this agent starts a conversation. " +
    "Use the returned chat_id with ask_human, post_card or send messages.",
  ask_human:
    "Asks a human a question and returns their answer: posts a card with option buttons only the chosen chat member can tap, then waits " +
    "(up to ~50s) for the tap. Get chat_id from open_chat (the human's @handle) first. Returns {answer}, or {status: 'pending', ask_id} " +
    "to keep checking later with get_ask_result. The card reads \"Answered: ...\" afterwards.",
  get_ask_result: "Checks again for the answer to a pending ask_human call, using the ask_id it returned.",
};

export const LOCAL_TOOL_NAMES = new Set(Object.keys(LOCAL_DESCRIPTIONS));

const LOCAL_TOOLS = KEYLESS_TOOLS.filter((t) => LOCAL_TOOL_NAMES.has(t.name));

/** Plain MCP Tool objects for the three local tools (annotations come from the keyless entries, which tests/annotations.test.mjs covers). */
export function toLocalMcpTools() {
  return LOCAL_TOOLS.map((tool) => {
    const mcpTool = {
      name: tool.name,
      title: tool.title,
      description: LOCAL_DESCRIPTIONS[tool.name],
      inputSchema: tool.inputSchema,
      annotations: { title: tool.title, ...tool.annotations },
    };
    if (tool.outputSchema) mcpTool.outputSchema = tool.outputSchema;
    return mcpTool;
  });
}

/** A REST client bound to the api-key header, same method surface as the hosted bearer client. */
export function createLocalRest({ host, fetchImpl }) {
  return createSaltBearerClient({ host, fetchImpl, authHeaders: (apiKey) => ({ "api-key": apiKey }) });
}

/** Runs one local tool. `ctx` (signal, maxTotalMsOverride, minEmptyPollMsOverride) is server-side only, as in runKeylessTool. */
export async function runLocalTool(name, args, { rest, apiKey, signal, maxTotalMsOverride, minEmptyPollMsOverride }) {
  const tool = LOCAL_TOOLS.find((t) => t.name === name);
  if (!tool) throw new Error(`Tool "${name}" is not a local tool.`);
  return tool.execute(rest, apiKey, args ?? {}, { signal, maxTotalMsOverride, minEmptyPollMsOverride });
}
