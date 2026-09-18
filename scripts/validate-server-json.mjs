#!/usr/bin/env node
// Validates server.json against the official MCP Registry server.schema.json
// (vendored at schemas/server.schema.json -- fetched from
// https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json,
// the schema the 2025-12-11 server.json format documents at
// https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/server-json/generic-server-json.md
// point at). Re-fetch the schema file if the registry ships a newer dated
// schema version and this repo's server.json needs to move to it.
//
// Usage: node scripts/validate-server-json.mjs [path/to/server.json]
// Exits non-zero with every validation error printed if invalid.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import Ajv from "ajv";
import addFormats from "ajv-formats";

const here = path.dirname(fileURLToPath(import.meta.url));
const schemaPath = path.join(here, "..", "schemas", "server.schema.json");
const serverJsonPath = path.resolve(process.argv[2] || path.join(here, "..", "server.json"));

export function loadSchema() {
  return JSON.parse(readFileSync(schemaPath, "utf8"));
}

export function validateServerJson(serverJson, schema = loadSchema()) {
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  const valid = validate(serverJson);
  return { valid, errors: validate.errors || [] };
}

function main() {
  const serverJson = JSON.parse(readFileSync(serverJsonPath, "utf8"));
  const { valid, errors } = validateServerJson(serverJson);
  if (valid) {
    console.log(`OK: ${serverJsonPath} is valid against ${path.relative(process.cwd(), schemaPath)}`);
    return;
  }
  console.error(`INVALID: ${serverJsonPath}`);
  for (const err of errors) {
    console.error(`  ${err.instancePath || "/"} ${err.message} ${JSON.stringify(err.params)}`);
  }
  process.exitCode = 1;
}

// Only run as a CLI when invoked directly (not when imported by the test).
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
