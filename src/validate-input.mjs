// Validates tool call arguments against a tool's own `inputSchema` before
// executing it. The low-level @modelcontextprotocol/sdk `Server` does NOT
// do this itself (it happily hands `CallToolRequest.params.arguments`
// straight to the handler, whatever shape it is) -- a 2026-09-18 security
// review flagged that gap directly. Same ajv setup
// scripts/validate-server-json.mjs already uses for server.json.

import Ajv from "ajv";
import addFormats from "ajv-formats";

const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);

// Compiled validators are cached by schema object identity -- every tool's
// inputSchema is a fixed, module-level object (src/keyless-tools.mjs), so
// this compiles each one exactly once per process, not once per call.
const compiled = new WeakMap();

/**
 * @param {object} schema a JSON Schema (a tool's inputSchema)
 * @param {unknown} data the arguments to validate
 * @returns {{valid: true} | {valid: false, message: string}}
 */
export function validateAgainstSchema(schema, data) {
  let validateFn = compiled.get(schema);
  if (!validateFn) {
    validateFn = ajv.compile(schema);
    compiled.set(schema, validateFn);
  }
  const valid = validateFn(data);
  if (valid) return { valid: true };
  const message = (validateFn.errors || [])
    .map((e) => `${e.instancePath || "(root)"} ${e.message}`.trim())
    .join("; ");
  return { valid: false, message: message || "arguments do not match the tool's input schema" };
}
