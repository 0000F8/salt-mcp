// Unit tests for src/card-ui.mjs: the MCP Apps `ui://salt/card` resource
// renders valid, escaped HTML for every card block type salt-api's Card
// model validates (CARD_PROTOCOL_SPEC.md section 2 / app/models/card.rb).

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CARD_UI_RESOURCE_URI,
  CARD_UI_MIME_TYPE,
  escapeHtml,
  renderBlock,
  renderBlocksBody,
  renderCardAppHtml,
  cardToStructuredContent,
} from "../src/card-ui.mjs";

test("resource identity constants match the MCP Apps ui:// scheme and mcp-app profile mimeType", () => {
  assert.equal(CARD_UI_RESOURCE_URI, "ui://salt/card");
  assert.equal(CARD_UI_MIME_TYPE, "text/html;profile=mcp-app");
});

test("escapeHtml neutralizes every HTML-significant character", () => {
  assert.equal(escapeHtml(`<script>alert('x')</script> & "quoted"`), "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp; &quot;quoted&quot;");
  assert.equal(escapeHtml(null), "");
  assert.equal(escapeHtml(undefined), "");
});

test("renderBlock renders a section block's text and fields", () => {
  const html = renderBlock({ type: "section", text: "Hello", fields: [{ label: "Amount", value: "12.50" }] });
  assert.match(html, /salt-card-section/);
  assert.match(html, /Hello/);
  assert.match(html, /Amount/);
  assert.match(html, /12\.50/);
});

test("renderBlock escapes hostile section text instead of ever using it as markup", () => {
  const html = renderBlock({ type: "section", text: "<img src=x onerror=alert(1)>" });
  assert.doesNotMatch(html, /<img/);
  assert.match(html, /&lt;img/);
});

test("renderBlock renders an image block with escaped url/alt", () => {
  const html = renderBlock({ type: "image", url: "https://example.test/a.png", alt: "A \"cat\"" });
  assert.match(html, /<img src="https:\/\/example\.test\/a\.png"/);
  assert.match(html, /alt="A &quot;cat&quot;"/);
});

test("renderBlock renders a divider with no fields", () => {
  const html = renderBlock({ type: "divider" });
  assert.match(html, /salt-card-divider/);
});

test("renderBlock renders actions buttons as disabled/read-only with a note, never wired to a live tap", () => {
  const html = renderBlock({
    type: "actions",
    elements: [
      { type: "button", action_id: "yes", label: "Yes", style: "primary" },
      { type: "button", action_id: "no", label: "No", style: "danger", restricted_to: ["user-1"] },
    ],
  });
  assert.match(html, /disabled/);
  assert.match(html, /Yes/);
  assert.match(html, /No/);
  assert.match(html, /salt-card-button-primary/);
  assert.match(html, /salt-card-button-danger/);
  assert.match(html, /Open Salt to respond/);
  assert.match(html, /Restricted to one chat member/i, "a restricted_to button's title says so");
});

test("renderBlock ignores an unknown block type instead of rendering raw content", () => {
  assert.equal(renderBlock({ type: "iframe", src: "https://evil.test" }), "");
});

test("renderBlocksBody renders every block in order and skips unknown types", () => {
  const body = renderBlocksBody([
    { type: "section", text: "Q1" },
    { type: "unknown_type", text: "should not appear" },
    { type: "divider" },
    { type: "section", text: "Q2" },
  ]);
  assert.match(body, /Q1/);
  assert.match(body, /Q2/);
  assert.doesNotMatch(body, /should not appear/);
});

test("cardToStructuredContent shapes the CallToolResult structuredContent for a posted card", () => {
  const structured = cardToStructuredContent({ cardId: "card-1", messageId: "msg-1", blocks: [{ type: "divider" }], text: "hi" });
  assert.deepEqual(structured, { card_id: "card-1", message_id: "msg-1", blocks: [{ type: "divider" }], text: "hi" });
});

test("renderCardAppHtml produces one self-contained, well-formed HTML document with no external loads", () => {
  const html = renderCardAppHtml();
  assert.match(html, /^<!doctype html>/i);
  assert.match(html, /<html>/);
  assert.match(html, /<\/html>\s*$/);
  assert.match(html, /<style>/);
  assert.match(html, /<script>/);
  // No external stylesheet/script/font loads -- everything must be inline.
  assert.doesNotMatch(html, /<link[^>]+rel=["']stylesheet["']/i);
  assert.doesNotMatch(html, /src=["']https?:\/\//i);
  assert.doesNotMatch(html, /googleapis|googlefonts|cdn\./i);
  // Salt's look: IBM Plex fallback stack, brand blue, zero radius.
  assert.match(html, /IBM Plex Sans/);
  assert.match(html, /#2563EB/);
  assert.match(html, /border-radius: 0/);
});

test("renderCardAppHtml's script listens for postMessage and sends a ui/initialize handshake", () => {
  const html = renderCardAppHtml();
  assert.match(html, /addEventListener\("message"/);
  assert.match(html, /ui\/initialize/);
  assert.match(html, /window\.parent\.postMessage/);
});
