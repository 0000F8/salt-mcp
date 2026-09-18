// Regression test for a real bug: src/index.mjs used to build createActions'
// options with `globalAgentId: config.globalAgentId`, but salt-agent-sdk's
// ActionsOptions only ever reads `conciergeAgentId` -- so
// hand_back_to_concierge's fallback destination silently did nothing in
// every salt-mcp deployment, no matter how correctly CONCIERGE_AGENT_ID (or
// its deprecated GLOBAL_AGENT_ID alias) was set in env.
//
// buildActionsOptions() is the pure function index.mjs uses to build that
// options object; this pins its shape directly against what
// salt-agent-sdk's createActions actually destructures, instead of relying
// on end-to-end behavior that needs a live chat and a live Salt API to
// observe.

import { test } from "node:test";
import assert from "node:assert/strict";
import { buildActionsOptions } from "../src/index.mjs";

test("buildActionsOptions passes the concierge id through as `conciergeAgentId`, not `globalAgentId`", () => {
  const config = {
    pgpPassphrase: "pw",
    publicWebhookUrl: "https://example.invalid/",
    walletMasterKey: "wmk",
    conciergeAgentId: "concierge-123",
    // A loaded SaltAgentConfig also carries a deprecated `globalAgentId`
    // (mirroring the same value) -- the bug was passing THIS one through
    // under a different key that createActions doesn't read at all.
    globalAgentId: "concierge-123",
  };
  const client = { marker: "fake-client" };
  const identities = { marker: "fake-identities" };

  const options = buildActionsOptions(config, { client, identities });

  assert.equal(options.conciergeAgentId, "concierge-123");
  assert.equal(options.client, client);
  assert.equal(options.identities, identities);
  assert.equal(options.pgpPassphrase, "pw");
  assert.equal(options.publicWebhookUrl, "https://example.invalid/");
  assert.equal(options.walletMasterKey, "wmk");
  assert.equal(
    "globalAgentId" in options,
    false,
    "options should never carry a globalAgentId key -- createActions doesn't read it, so its presence is a sign of the old bug"
  );
});

test("a missing conciergeAgentId passes through as undefined, not silently dropped or defaulted", () => {
  const options = buildActionsOptions(
    { pgpPassphrase: "pw", publicWebhookUrl: "https://example.invalid/" },
    { client: {}, identities: {} }
  );
  assert.equal(options.conciergeAgentId, undefined);
});
