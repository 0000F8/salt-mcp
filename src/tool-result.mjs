// One place that shapes a tool's return value into an MCP CallToolResult.
// A tool that declares an `outputSchema` MUST answer with `structuredContent`
// (the official SDK client's callTool() throws -32600 otherwise), so every
// object result carries it beside the text copy older clients read.

/** @param {unknown} result what a tool handler returned (string or JSON value) */
export function toolResult(result) {
  const text = typeof result === "string" ? result : JSON.stringify(result ?? null, null, 2);
  const out = { content: [{ type: "text", text }] };
  if (result && typeof result === "object" && !Array.isArray(result)) out.structuredContent = result;
  return out;
}
