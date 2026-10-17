// The "link this computer" setup of `salt-mcp --channel`: instead of pasting an agent's credentials into env vars,
// the computer makes a brand new Salt agent by scan. Contract: worktrees/SCAN_TO_LINK_CONTRACT.md (kind "agent").
//
//   when     link mode is the default for --channel when SALT_API_KEY is unset, or when --link is given. With
//            SALT_API_KEY set the env path is untouched.
//   begin    make the agent's own PGP keypair HERE (the SDK's generateKeypair, so the key decrypts exactly as the
//            SDK expects), POST /api/v1/device_links {kind:"agent", public_key, name:"Claude Code on <host>",
//            agent_name:"Claude Code"}, show a local QR page (link-store.mjs showLinkPage, deleted when the link ends) and poll
//            POST /device_links/:id/claim every 3 s until approved, denied, expired or claimed. The phone approves
//            with no key moving: this public key BECOMES the agent's, and its private key never leaves this
//            computer. Salt never holds it.
//   claim    200 {api_key, agent:{id,handle,name}, owner:{id,handle,name}} arrives once.
//   the keys the api key and the agent private key are one login-Keychain item (service "salt-mcp-channel", account
//            <host-slug>), written through `security -i` on STDIN. Everything else (ids, handles, the public key) is
//            in channel-link-<host-slug>.json next to the as-me link file (dir 0700, file 0600, excluded from Time
//            Machine). Off macOS the secrets fall back into that file and a line on stderr says so.
//   allow    the allow-list defaults to owner.id when SALT_CHANNEL_ALLOW is unset: only the person who scanned.
//   unlink   `salt-mcp --channel --unlink` removes the local state. Salt has no self-delete for an agent: delete
//            "Claude Code" in Salt (Developers) to cancel its api key.
//
// stdout is the MCP channel: everything here goes to stderr. No api key or private key is logged.

import { readFileSync, rmSync } from "node:fs";
import { hostname as osHostname } from "node:os";
import { join } from "node:path";
import pkg from "salt-agent-sdk";
import { createKeychain, defaultBaseDir, defaultOpen, defaultRunCommand, hostSlug, showLinkPage, writePrivateJson } from "./link-store.mjs";
import { LinkError, POLL_MS } from "./me-link.mjs";
import { DEFAULT_HOST } from "./me-session.mjs";
import { assertSafeHost } from "./me-cli.mjs";

const { generateKeypair } = pkg;

const KEYCHAIN_SERVICE = "salt-mcp-channel";
const REQUEST_TIMEOUT_MS = 30000;
const NAME_MAX = 60;
export const AGENT_NAME = "Claude Code";
/** The SDK's default key passphrase; the keypair is made with it so SDK decrypt/sign work unchanged. */
export const KEY_PASSPHRASE = "salt";

/** Link mode: --link always, else the default whenever no SALT_API_KEY is set. */
export const isChannelLinkMode = (argv, env = process.env) => argv.includes("--channel") && (argv.includes("--link") || !String(env.SALT_API_KEY ?? "").trim());

export function createChannelLink({
  host,
  fetchImpl,
  baseDir = defaultBaseDir(),
  hostname = osHostname(),
  openBrowser = defaultOpen,
  sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
  now = () => Date.now(),
  runCommand = defaultRunCommand,
  platform = process.platform,
  log = (m) => console.error("[salt-mcp]", m),
}) {
  const base = host.replace(/\/$/, "");
  const doFetch = fetchImpl ?? fetch;
  const slug = hostSlug(base);
  const file = join(baseDir, `channel-link-${slug}.json`);
  const onMac = platform === "darwin";
  const keychain = createKeychain({ runCommand, service: KEYCHAIN_SERVICE, account: slug });

  /** The stored link {host, agent, owner, public_key, api_key, private_key}, or null when there is none. */
  async function load() {
    let meta;
    try {
      meta = JSON.parse(readFileSync(file, "utf8"));
    } catch {
      return null;
    }
    if (meta?.v !== 1 || !meta.agent?.id || !meta.owner?.id || typeof meta.public_key !== "string") return null;
    let secrets = null;
    if (typeof meta.api_key === "string" && typeof meta.private_key === "string") secrets = meta;
    else if (meta.key_store === "keychain") {
      try {
        secrets = JSON.parse((await keychain.get()) ?? "null");
      } catch {
        secrets = null;
      }
    }
    if (typeof secrets?.api_key !== "string" || typeof secrets?.private_key !== "string") return null;
    return { host: base, agent: meta.agent, owner: meta.owner, public_key: meta.public_key, api_key: secrets.api_key, private_key: secrets.private_key };
  }

  async function store(link) {
    const { api_key, private_key, ...meta } = link;
    if (onMac) {
      await keychain.set(JSON.stringify({ api_key, private_key }));
      writePrivateJson(baseDir, file, { ...meta, key_store: "keychain" });
      await runCommand("/usr/bin/tmutil", ["addexclusion", file]).catch(() => {});
    } else {
      log("no macOS Keychain here: the agent's api key and private key are kept in the link file (readable by programs running as you)");
      writePrivateJson(baseDir, file, { ...meta, api_key, private_key, key_store: "file" });
    }
  }

  /** Removes the file and the Keychain item. Returns whether anything was there. */
  async function remove() {
    const had = Boolean(await load());
    rmSync(file, { force: true });
    if (onMac) await keychain.remove();
    return had;
  }

  /** Makes a new agent by scan and stores it; resolves the stored link. Waits for the phone (up to the link's expiry). */
  async function link() {
    const name = `Claude Code on ${hostname}`.slice(0, NAME_MAX);
    const { publicKey, privateKey, fingerprint } = await generateKeypair(KEY_PASSPHRASE);
    let res;
    try {
      res = await doFetch(`${base}/api/v1/device_links`, {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({ kind: "agent", public_key: publicKey, name, agent_name: AGENT_NAME }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch {
      throw new LinkError("Couldn't reach Salt. Check the connection and try again.", { kind: "network" });
    }
    if (res.status === 429) throw new LinkError("Salt is rate limiting new links. Wait a while and try again.", { status: 429, kind: "rate_limit" });
    if (res.status !== 201) throw new LinkError(`Salt answered the link request with ${res.status}.`, { status: res.status, kind: "link" });
    const made = await res.json();
    const expiresAt = Date.parse(made.expires_at) || now() + 15 * 60000;
    const page = await showLinkPage({ host: base, id: made.id, fp: fingerprint, name, openBrowser, log });
    if (page.opened) log("Scan the code in your browser with the Salt app on your phone (Menu, Devices, Link a computer) to make the agent.");
    try {
      for (;;) {
        let claim = null;
        try {
          claim = await doFetch(`${base}/api/v1/device_links/${encodeURIComponent(made.id)}/claim`, {
            method: "POST",
            headers: { Accept: "application/json", "Content-Type": "application/json" },
            body: JSON.stringify({ poll_secret: made.poll_secret }),
            signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
          });
        } catch {
          claim = null; // a network blip: try again until the link's own expiry
        }
        if (claim?.status === 200) {
          const body = await claim.json().catch(() => null);
          if (typeof body?.api_key !== "string" || !body.api_key || !body.agent?.id || !body.owner?.id) {
            throw new LinkError("Salt's answer to the link was incomplete. Nothing was saved; delete the new agent in Salt (Developers) and try again.", { kind: "link" });
          }
          const linked = { v: 1, host: base, agent: body.agent, owner: body.owner, public_key: publicKey, api_key: body.api_key, private_key: privateKey, linked_at: new Date(now()).toISOString() };
          await store(linked);
          return linked;
        }
        if (claim && (claim.status === 410 || claim.status === 404)) throw new LinkError("The link was denied, expired or already used. Run it again for a new code.", { status: claim.status, kind: "link" });
        if (now() >= expiresAt) throw new LinkError("The code ran out (they last 15 minutes). Run it again for a new one.", { kind: "link" });
        await sleep(POLL_MS);
      }
    } finally {
      page.cleanup();
    }
  }

  return { path: file, load, link, remove };
}

const shown = (v) => String(v ?? "").replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, "").slice(0, 80);

/**
 * The env that channel mode runs on in link mode: the process env plus the linked agent's identity (a copy, process.env
 * is untouched). Reuses a stored link or makes one by scan. SALT_CHANNEL_ALLOW defaults to the owner's id.
 */
export async function channelLinkEnv({ env = process.env, linkOptions = {} } = {}) {
  const host = (env.HOST || DEFAULT_HOST).replace(/\/$/, "");
  assertSafeHost(host, env);
  const client = createChannelLink({ host, ...linkOptions });
  const log = linkOptions.log ?? ((m) => console.error("[salt-mcp]", m));
  let linked = await client.load();
  if (linked) log(`Using the agent linked here: @${shown(linked.agent.handle)} (${shown(linked.agent.name)}), owned by @${shown(linked.owner.handle)}`);
  else {
    linked = await client.link();
    log(`Linked: agent @${shown(linked.agent.handle)} (${shown(linked.agent.name)}) now belongs to @${shown(linked.owner.handle)}`);
  }
  return {
    ...env,
    HOST: host,
    SALT_API_KEY: linked.api_key,
    SALT_APP_ID: String(linked.agent.id),
    APP_PUBLIC_KEY: linked.public_key,
    APP_PRIVATE_KEY: linked.private_key,
    PGP_PASSPHRASE: KEY_PASSPHRASE,
    SALT_USERNAME: linked.agent.handle || env.SALT_USERNAME,
    SALT_DISPLAY_NAME: linked.agent.name || env.SALT_DISPLAY_NAME,
    SALT_CHANNEL_ALLOW: String(env.SALT_CHANNEL_ALLOW ?? "").trim() ? env.SALT_CHANNEL_ALLOW : String(linked.owner.id),
  };
}

/** `salt-mcp --channel --unlink`: removes the local state and says how to cancel the agent in Salt. */
export async function runChannelUnlink({ env = process.env, linkOptions = {} } = {}) {
  const host = (env.HOST || DEFAULT_HOST).replace(/\/$/, "");
  assertSafeHost(host, env);
  const log = linkOptions.log ?? ((m) => console.error("[salt-mcp]", m));
  const had = await createChannelLink({ host, ...linkOptions }).remove();
  if (!had) return log("nothing to unlink: this computer has no channel link for " + host);
  log("unlinked: the agent's key and link file are deleted from this computer. Salt cannot delete an agent for you, so delete \"Claude Code\" in Salt (Developers) to cancel its api key.");
}
