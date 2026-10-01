// Validates server.json against the vendored official MCP Registry schema
// (schemas/server.schema.json) and checks the specific shape this repo's
// server.json is supposed to have per the mcp-pack lane brief: the npm
// package (stdio) with its env vars, and the hosted streamable-http remote
// with its two required secret headers.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { validateServerJson, loadSchema } from "../scripts/validate-server-json.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const serverJsonPath = path.join(here, "..", "server.json");

function readServerJson() {
  return JSON.parse(readFileSync(serverJsonPath, "utf8"));
}

test("server.json validates against the official MCP Registry server.schema.json", () => {
  const serverJson = readServerJson();
  const schema = loadSchema();
  const { valid, errors } = validateServerJson(serverJson, schema);
  assert.equal(
    valid,
    true,
    "server.json failed schema validation:\n" + errors.map((e) => `  ${e.instancePath || "/"} ${e.message}`).join("\n")
  );
});

test("server.json name matches the MCP Registry namespace and package.json's mcpName", () => {
  const serverJson = readServerJson();
  const pkg = JSON.parse(readFileSync(path.join(here, "..", "package.json"), "utf8"));
  assert.equal(serverJson.name, "ai.saltapp/salt");
  assert.equal(pkg.mcpName, serverJson.name, "package.json's mcpName must match server.json's name exactly (registry ownership check)");
});

// The registry validates every package it is told about, and salt-mcp is not on npm
// yet (the owner's npm login gates it), so server.json is remotes-only until then.
// The day the npm block comes back, this test pins its shape; until then it pins
// that nothing claims a package that cannot be installed.
test("server.json claims no package until salt-mcp is actually on npm; when it does, it is a stdio npm entry with the documented env vars", () => {
  const serverJson = readServerJson();
  const npmPackage = (serverJson.packages || []).find((p) => p.registryType === "npm");
  if (!npmPackage) {
    // Until then the only package allowed beside the remote is the OCI image the
    // registry can verify by its io.modelcontextprotocol.server.name label.
    for (const p of serverJson.packages || []) {
      assert.equal(p.registryType, "oci", "only the OCI image may be listed while salt-mcp is not on npm");
      assert.match(p.identifier, /^ghcr\.io\/0000f8\/salt-mcp:v\d+\.\d+\.\d+$/, "OCI identifier is the canonical reference with the release tag (the registry rejects registryBaseUrl for OCI)");
      assert.equal(p.transport.type, "stdio");
      assert.equal(p.version, undefined, "the registry refuses a version field on OCI packages; the tag rides in the identifier");
    }
    assert.ok((serverJson.remotes || []).length > 0, "the entry must still name the hosted server");
    return;
  }
  assert.equal(npmPackage.identifier, "salt-mcp");
  assert.equal(npmPackage.transport.type, "stdio");
  assert.notEqual(npmPackage.version, "latest", "package version must be a specific version, not a range or 'latest'");

  const envByName = Object.fromEntries((npmPackage.environmentVariables || []).map((e) => [e.name, e]));
  const requiredSecrets = ["SALT_API_KEY", "APP_PRIVATE_KEY"];
  for (const name of requiredSecrets) {
    assert.ok(envByName[name], `missing environment variable ${name}`);
    assert.equal(envByName[name].isRequired, true, `${name} should be required`);
    assert.equal(envByName[name].isSecret, true, `${name} should be marked secret`);
  }
  assert.ok(envByName.HOST?.isRequired, "HOST should be required");
  assert.ok(envByName.SALT_APP_ID?.isRequired, "SALT_APP_ID should be required");
  assert.ok(envByName.APP_PUBLIC_KEY?.isRequired, "APP_PUBLIC_KEY should be required");
  // Optional ones stay optional.
  assert.equal(envByName.WALLET_MASTER_KEY?.isRequired, false);
  assert.equal(envByName.CONCIERGE_AGENT_ID?.isRequired, false);
});

test("server.json lists the hosted streamable-http remote with an OAuth bearer header and the legacy header pair, none required up front", () => {
  const serverJson = readServerJson();
  const remote = (serverJson.remotes || [])[0];
  assert.ok(remote, "expected a remote entry");
  assert.equal(remote.type, "streamable-http");
  assert.equal(remote.url, "https://mcp.saltapp.ai/mcp");

  const headerByName = Object.fromEntries((remote.headers || []).map((h) => [h.name, h]));

  // OAuth (K5 contract) is now the recommended path -- no header is
  // required up front, since a client that supports it discovers the
  // flow itself from this endpoint's 401 (RFC 9728). Nothing in
  // server.json can express "discovered automatically", so the
  // Authorization header is documented but not marked required.
  assert.ok(headerByName["Authorization"], "missing an Authorization header entry documenting the OAuth bearer flow");
  assert.equal(headerByName["Authorization"].isRequired, false);
  assert.equal(headerByName["Authorization"].isSecret, true);
  assert.match(headerByName["Authorization"].description, /OAuth/);

  // The legacy header pair keeps working unchanged (K5: "The legacy
  // X-Salt-Api-Key + X-Salt-App-Id header auth keeps working unchanged"),
  // but is no longer required now that OAuth is the default path.
  for (const name of ["X-Salt-Api-Key", "X-Salt-App-Id"]) {
    assert.ok(headerByName[name], `missing header ${name}`);
    assert.equal(headerByName[name].isRequired, false, `${name} should no longer be required now that OAuth is the default`);
    assert.equal(headerByName[name].isSecret, true, `${name} should be marked secret`);
    assert.match(headerByName[name].description, /LEGACY/);
  }
});

test("server.json's description fits the registry's 100-character limit", () => {
  const serverJson = readServerJson();
  assert.ok(serverJson.description.length <= 100, `description is ${serverJson.description.length} chars, limit is 100`);
});

test("server.json carries icons and a job-naming description of at most 100 characters; PGP_PASSPHRASE is optional", () => {
  const serverJson = readServerJson();
  assert.ok(serverJson.description.length <= 100, `description is ${serverJson.description.length} chars`);
  assert.doesNotMatch(serverJson.description, /\bpeople\b/i);
  const byType = Object.fromEntries((serverJson.icons || []).map((i) => [i.mimeType, i]));
  assert.equal(byType["image/png"]?.src, "https://saltapp.ai/logo512.png");
  assert.deepEqual(byType["image/png"]?.sizes, ["512x512"]);
  assert.equal(byType["image/svg+xml"]?.src, "https://saltapp.ai/favicon.svg");
  for (const pkg of serverJson.packages || []) {
    const pgp = (pkg.environmentVariables || []).find((e) => e.name === "PGP_PASSPHRASE");
    if (pgp) assert.equal(pgp.isRequired, false);
  }
});
