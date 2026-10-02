// MCP tool annotations (https://modelcontextprotocol.io -- Tool.annotations)
// for every action salt-agent-sdk's createActions() exposes.
//
// This lives here, not in salt-agent-sdk, because tool annotations are an
// MCP protocol concept: salt-agent-sdk's ActionDefinition is provider-neutral
// (feeds Anthropic/OpenAI tool formats too, via toAnthropicTools/
// toOpenAITools), so it has no opinion on readOnlyHint/destructiveHint/etc.
// This module is the one place that opinion lives for the MCP servers.
//
// Both directories that require tool annotations (the Claude and ChatGPT app
// connectors) read them off the MCP Tool object at `annotations`, alongside
// name/description/inputSchema -- see server.js/http.mjs's ListTools
// handlers, which merge this map onto salt-agent-sdk's action definitions.
//
// Ground rule applied below: list/read tools (no Salt-side effect) are
// read-only; everything that sends a message, moves money, creates a
// standing resource (agent, product, wallet), or hands off a conversation is
// NOT read-only, and is marked destructive -- consistent with money and
// message tools being irreversible or hard-to-undo real-world actions, not
// local, in-place edits. `openWorldHint` is true everywhere: every action
// here talks to the live Salt network (other agents, other people, other
// servers), never a closed local system.

/**
 * @typedef {{
 *   title: string,
 *   readOnlyHint: boolean,
 *   destructiveHint: boolean,
 *   idempotentHint: boolean,
 *   openWorldHint: boolean,
 * }} ToolAnnotations
 */

/** @type {Record<string, ToolAnnotations>} */
export const TOOL_ANNOTATIONS = {
  create_salt_agent: {
    title: "Create Salt Agent",
    readOnlyHint: false,
    destructiveHint: true, // brings a new, real, live agent online under the caller's ownership
    idempotentHint: false, // calling again creates ANOTHER agent, not the same one
    openWorldHint: true,
  },
  list_salt_agents: {
    title: "List Salt Agents",
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
  delegate_to_agent: {
    title: "Delegate to Agent",
    readOnlyHint: false,
    destructiveHint: true, // sends a real, visible Salt chat message
    idempotentHint: false,
    openWorldHint: true,
  },
  report_progress: {
    title: "Report Progress",
    readOnlyHint: false,
    destructiveHint: false, // private, informational only -- nobody's data or money moves
    idempotentHint: false,
    openWorldHint: true,
  },
  consult_agent: {
    title: "Consult Agent",
    readOnlyHint: false,
    destructiveHint: true, // sends a real Salt message into a private lane
    idempotentHint: false,
    openWorldHint: true,
  },
  request_floor: {
    title: "Request the Floor",
    readOnlyHint: false,
    destructiveHint: true, // posts a real message into the consult lane
    idempotentHint: false,
    openWorldHint: true,
  },
  post_card: {
    title: "Post Card",
    readOnlyHint: false,
    destructiveHint: true, // posts a real, visible message/card into the chat
    idempotentHint: false,
    openWorldHint: true,
  },
  update_card: {
    title: "Update Card",
    readOnlyHint: false,
    destructiveHint: true, // rewrites a live card everyone in the chat sees
    idempotentHint: true, // sending the same complete blocks array again leaves the same end state
    openWorldHint: true,
  },
  create_product: {
    title: "Create Product",
    readOnlyHint: false,
    destructiveHint: true, // adds a real, billable product to the caller's shop
    idempotentHint: false, // calling again adds another product
    openWorldHint: true,
  },
  list_products: {
    title: "List Products",
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
  offer_product: {
    title: "Offer Product",
    readOnlyHint: false,
    destructiveHint: true, // posts a real Buy button into the chat
    idempotentHint: false,
    openWorldHint: true,
  },
  send_invoice: {
    title: "Send Invoice",
    readOnlyHint: false,
    destructiveHint: true, // a real, payable money request -- a message + money tool
    idempotentHint: false, // calling again sends ANOTHER invoice
    openWorldHint: true,
  },
  add_usage: {
    title: "Add Usage",
    readOnlyHint: false,
    destructiveHint: true, // draws down the buyer's real prepaid credit balance
    idempotentHint: false,
    openWorldHint: true,
  },
  create_wallet: {
    title: "Create Wallet",
    readOnlyHint: false,
    destructiveHint: true, // provisions a real, funds-capable wallet with no recovery phrase
    idempotentHint: false, // calling again just adds another wallet
    openWorldHint: true,
  },
  hand_off_to_agent: {
    title: "Hand Off to Agent",
    readOnlyHint: false,
    destructiveHint: true, // transfers live control of the chat to another agent
    idempotentHint: false,
    openWorldHint: true,
  },
  hand_back_to_concierge: {
    title: "Hand Back to Concierge",
    readOnlyHint: false,
    destructiveHint: true, // transfers live control of the chat
    idempotentHint: false,
    openWorldHint: true,
  },
  offer_handoff_choices: {
    title: "Offer Hand-off Choices",
    readOnlyHint: false,
    destructiveHint: true, // posts a real, tappable card into the chat
    idempotentHint: false,
    openWorldHint: true,
  },
  // salt-agent-sdk 0.9.0 (K7 identity): missing here left the SDK's real
  // action catalog two tools ahead of this map, caught only once salt-mcp
  // stopped resolving a stale local salt-agent-sdk install and started
  // building its definitions from the real, current SDK (see
  // tests/annotations.test.mjs).
  identity_set: {
    title: "Set Identity",
    readOnlyHint: false,
    destructiveHint: false, // edits your own public claim sections; reversible with another call, moves nothing and sends nobody a message
    idempotentHint: true, // setting the same claims again leaves the same state
    openWorldHint: true,
  },
  identity_get: {
    title: "Get Identity",
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
  // salt-agent-sdk 0.10.x (Identity R3/R4, identityShare.ts): the same gap
  // again, three tools ahead this time. Read from the SDK's own action
  // definitions on 2026-09-26, not guessed.
  identity_share: {
    title: "Share Identity Sections",
    readOnlyHint: false,
    destructiveHint: false, // discloses your OWN card sections into a chat as an encrypted message; deletes nothing, and identity_revoke takes it back
    idempotentHint: false, // sharing the same keys again sends every member another message
    openWorldHint: true, // every non-observer member of the chat receives it
  },
  identity_ask: {
    title: "Ask for Identity Sections",
    readOnlyHint: false,
    destructiveHint: false, // sends the other person in a 1:1 a request; they may share, decline or ignore
    idempotentHint: false, // each call sends another ask
    openWorldHint: true,
  },
  react_to_message: {
    title: "React to a Message",
    readOnlyHint: false,
    destructiveHint: false, // adds one plaintext emoji chip to a message; deletes nothing, and the same call again takes it back
    idempotentHint: false, // a TOGGLE: calling twice with the same emoji removes it
    openWorldHint: true, // every member of the chat sees the reaction live
  },
  identity_revoke: {
    title: "Revoke an Identity Share",
    readOnlyHint: false,
    destructiveHint: true, // removes a share other members were relying on; a revoked share cannot be un-revoked, only re-shared
    idempotentHint: true, // revoking an already-revoked share leaves the same state
    openWorldHint: true,
  },
};

/**
 * Builds the MCP `annotations` object for one action definition. Throws if
 * the action has no entry above -- a new salt-agent-sdk action must be
 * classified here before it can be exposed, rather than silently shipping
 * unannotated (see tests/annotations.test.mjs, which fails exactly this way
 * against the live SDK action list).
 * @param {string} name
 * @returns {ToolAnnotations}
 */
export function annotationsFor(name) {
  const found = TOOL_ANNOTATIONS[name];
  if (!found) {
    throw new Error(
      `No tool annotations registered for "${name}" in src/annotations.mjs -- ` +
        "add title/readOnlyHint/destructiveHint/idempotentHint/openWorldHint for it before exposing it over MCP."
    );
  }
  return found;
}

/**
 * Maps salt-agent-sdk ActionDefinitions to MCP Tool objects (name,
 * description, inputSchema, annotations). Shared by the stdio and hosted
 * HTTP servers' ListTools handlers.
 * @param {Array<{name: string, description: string, schema: object}>} definitions
 */
export function toMcpTools(definitions) {
  return definitions.map((d) => ({
    name: d.name,
    description: d.description,
    inputSchema: d.schema,
    annotations: annotationsFor(d.name),
  }));
}
