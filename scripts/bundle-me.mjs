#!/usr/bin/env node
// Builds salt-me.mcpb, the Claude Desktop bundle for `salt-mcp --as-me`. mcpb packs a directory whose manifest is
// named manifest.json, so the as-me manifest (manifest.as-me.json) is staged with src/, package.json, .mcpbignore
// and node_modules in a temp directory and packed from there. Run: npm run bundle:me

import { cpSync, copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const out = resolve(root, "salt-me.mcpb");
const stage = mkdtempSync(join(tmpdir(), "salt-me-bundle-"));
try {
  cpSync(join(root, "src"), join(stage, "src"), { recursive: true });
  cpSync(join(root, "node_modules"), join(stage, "node_modules"), { recursive: true });
  for (const f of ["package.json", ".mcpbignore"]) copyFileSync(join(root, f), join(stage, f));
  copyFileSync(join(root, "manifest.as-me.json"), join(stage, "manifest.json"));
  const r = spawnSync("npx", ["--yes", "@anthropic-ai/mcpb", "pack", stage, out], { stdio: "inherit" });
  process.exitCode = r.status ?? 1;
} finally {
  rmSync(stage, { recursive: true, force: true });
}
