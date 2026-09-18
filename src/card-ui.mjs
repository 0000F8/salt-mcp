// Renders Salt's declarative card blocks (CARD_PROTOCOL_SPEC.md section 2,
// the same vocabulary salt-api's Card model validates: section, fields,
// image, divider, actions) as a self-contained MCP Apps UI resource --
// see github.com/modelcontextprotocol/ext-apps (SEP-1865).
//
// One static resource (`ui://salt/card`) is registered for BOTH post_card
// and update_card (src/keyless-tools.mjs); it carries no data of its own.
// Per-call card data reaches it at RUNTIME over the sandboxed-iframe
// postMessage channel the host sets up, not baked into the resource body --
// that's what lets one resource serve every card a caller ever posts or
// updates. See renderCardAppHtml's inline script for the listener.
//
// No external loads (fonts, scripts, images-as-network-fetches beyond a
// block's own declared `url`, which the host's sandbox governs): every
// style is inline, and the font stack falls back through the system's own
// faces rather than fetching Google Fonts (this resource has no <head>
// network access story of its own to rely on).
//
// Buttons render READ-ONLY with a note instead of calling back into a
// tool. Reasoning: a card's `actions` buttons (particularly `pay` and
// `restricted_to`-gated ones) require the TAPPING HUMAN's own Salt
// session/membership to authorize -- exactly the server-side re-check
// CARD_PROTOCOL_SPEC.md section 3.4 insists on. The MCP host rendering
// this iframe (Claude Desktop, ChatGPT, Cursor, ...) has no Salt session
// at all; it is not signed in as anyone. Wiring a tap to a real
// `tools/call` here would mean the KEYLESS AGENT (the only identity this
// server can act as) performing the tap, which is a different, wrong
// actor for a card meant to be answered by a specific chat member. So
// this stays intentionally inert, with a plain note pointing back to Salt
// itself, where the real member's own session can answer for real.

const IBM_PLEX_FALLBACK_STACK =
  '"IBM Plex Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif';
const BRAND_BLUE = "#2563EB";

export const CARD_UI_RESOURCE_URI = "ui://salt/card";
export const CARD_UI_MIME_TYPE = "text/html;profile=mcp-app";

/** HTML-escapes a string for safe interpolation into element content or attribute values. */
export function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderSection(block) {
  const parts = [];
  if (block.text) parts.push(`<p class="salt-card-text">${escapeHtml(block.text)}</p>`);
  if (Array.isArray(block.fields) && block.fields.length > 0) {
    const rows = block.fields
      .map(
        (f) =>
          `<div class="salt-card-field"><span class="salt-card-field-label">${escapeHtml(f.label)}</span><span class="salt-card-field-value">${escapeHtml(f.value)}</span></div>`
      )
      .join("");
    parts.push(`<div class="salt-card-fields">${rows}</div>`);
  }
  return `<div class="salt-card-block salt-card-section">${parts.join("")}</div>`;
}

function renderImage(block) {
  const alt = escapeHtml(block.alt || "");
  const url = escapeHtml(block.url || "");
  return `<div class="salt-card-block salt-card-image"><img src="${url}" alt="${alt}" /></div>`;
}

function renderDivider() {
  return `<div class="salt-card-block salt-card-divider"></div>`;
}

function renderActions(block) {
  const buttons = Array.isArray(block.elements) ? block.elements : [];
  const rendered = buttons
    .map((el) => {
      const style = el.style === "danger" ? "salt-card-button-danger" : el.style === "primary" ? "salt-card-button-primary" : "";
      const restricted = Array.isArray(el.restricted_to) && el.restricted_to.length > 0;
      const title = restricted ? "Restricted to one chat member -- open Salt to respond." : "Open Salt to respond.";
      return `<button type="button" class="salt-card-button ${style}" disabled title="${escapeHtml(title)}">${escapeHtml(el.label || "")}</button>`;
    })
    .join("");
  return `<div class="salt-card-block salt-card-actions">${rendered}</div><p class="salt-card-note">This card is interactive in Salt. Open the chat there to respond.</p>`;
}

/** Renders one validated block (see salt-api's Card model for the exact vocabulary). Unknown types render nothing -- the schema is the author's entire vocabulary. */
export function renderBlock(block) {
  if (!block || typeof block !== "object") return "";
  switch (block.type) {
    case "section":
      return renderSection(block);
    case "image":
      return renderImage(block);
    case "divider":
      return renderDivider();
    case "actions":
      return renderActions(block);
    default:
      return "";
  }
}

/** Renders an ordered array of blocks to one HTML fragment. */
export function renderBlocksBody(blocks) {
  return (Array.isArray(blocks) ? blocks : []).map(renderBlock).join("\n");
}

/**
 * Builds the CallToolResult's `structuredContent` for a posted/updated
 * card -- what the ui:// resource's runtime listener renders from (see
 * renderCardAppHtml's script), and also what a non-Apps host receives
 * directly as machine-readable structured content per the MCP tools spec.
 */
export function cardToStructuredContent({ cardId, messageId, blocks, text }) {
  return { card_id: cardId, message_id: messageId, blocks: Array.isArray(blocks) ? blocks : [], text: text || "" };
}

/**
 * The static, data-free HTML for the `ui://salt/card` resource. Shared by
 * post_card and update_card's `_meta.ui.resourceUri` -- one document,
 * fetched once per host session and re-driven for every card. The inline
 * script renders whatever the host hands it at runtime.
 *
 * The MCP Apps host-communication shape is new and still settling
 * (SEP-1865, github.com/modelcontextprotocol/ext-apps); this listens for
 * every reasonably-documented shape a host might use to deliver the tool
 * result (`ui/notifications/tool-result`'s `params.structuredContent`, a
 * bare `structuredContent`/`card` on the message, or the initial
 * `ui/initialize` response carrying it under `result`) rather than betting
 * on exactly one. See HANDOFF.md for the note to revisit this once host
 * behavior is verified against real clients.
 */
export function renderCardAppHtml() {
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 16px;
    font-family: ${IBM_PLEX_FALLBACK_STACK};
    color: #111318;
    background: #ffffff;
  }
  @media (prefers-color-scheme: dark) {
    body { color: #e7e9ee; background: #111318; }
    .salt-card-field-value, .salt-card-text { color: #e7e9ee; }
    .salt-card-divider { background: #2a2d36; }
    .salt-card-button { border-color: #3a3d47; color: #e7e9ee; }
  }
  .salt-card { max-width: 480px; }
  .salt-card-block { margin-bottom: 12px; }
  .salt-card-text { margin: 0; font-size: 15px; line-height: 1.45; white-space: pre-wrap; }
  .salt-card-fields { display: flex; flex-wrap: wrap; gap: 8px 16px; }
  .salt-card-field { display: flex; flex-direction: column; min-width: 96px; }
  .salt-card-field-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; opacity: 0.65; }
  .salt-card-field-value { font-size: 14px; font-weight: 600; }
  .salt-card-image img { max-width: 100%; border-radius: 0; display: block; }
  .salt-card-divider { height: 1px; background: #e2e4ea; border: 0; margin: 16px 0; }
  .salt-card-actions { display: flex; flex-wrap: wrap; gap: 8px; }
  .salt-card-button {
    font-family: inherit;
    font-size: 14px;
    font-weight: 600;
    padding: 8px 16px;
    border-radius: 0;
    border: 1px solid #c7cad3;
    background: transparent;
    color: #111318;
    cursor: not-allowed;
    opacity: 0.75;
  }
  .salt-card-button-primary { border-color: ${BRAND_BLUE}; color: ${BRAND_BLUE}; }
  .salt-card-button-danger { border-color: #b3261e; color: #b3261e; }
  .salt-card-note { font-size: 12px; opacity: 0.65; margin: 4px 0 0; }
  .salt-card-empty { font-size: 13px; opacity: 0.6; }
</style>
</head>
<body>
  <div id="salt-card-root" class="salt-card">
    <p class="salt-card-empty">Loading card&hellip;</p>
  </div>
  <script>
    (function () {
      "use strict";
      var root = document.getElementById("salt-card-root");

      function escapeHtml(value) {
        return String(value == null ? "" : value)
          .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
      }

      function renderBlock(block) {
        if (!block || typeof block !== "object") return "";
        if (block.type === "section") {
          var parts = [];
          if (block.text) parts.push('<p class="salt-card-text">' + escapeHtml(block.text) + "</p>");
          if (Array.isArray(block.fields) && block.fields.length) {
            var rows = block.fields.map(function (f) {
              return '<div class="salt-card-field"><span class="salt-card-field-label">' + escapeHtml(f.label) +
                '</span><span class="salt-card-field-value">' + escapeHtml(f.value) + "</span></div>";
            }).join("");
            parts.push('<div class="salt-card-fields">' + rows + "</div>");
          }
          return '<div class="salt-card-block salt-card-section">' + parts.join("") + "</div>";
        }
        if (block.type === "image") {
          return '<div class="salt-card-block salt-card-image"><img src="' + escapeHtml(block.url) +
            '" alt="' + escapeHtml(block.alt || "") + '" /></div>';
        }
        if (block.type === "divider") {
          return '<div class="salt-card-block salt-card-divider"></div>';
        }
        if (block.type === "actions") {
          var els = Array.isArray(block.elements) ? block.elements : [];
          var buttons = els.map(function (el) {
            var style = el.style === "danger" ? "salt-card-button-danger" : el.style === "primary" ? "salt-card-button-primary" : "";
            var restricted = Array.isArray(el.restricted_to) && el.restricted_to.length > 0;
            var title = restricted ? "Restricted to one chat member -- open Salt to respond." : "Open Salt to respond.";
            return '<button type="button" class="salt-card-button ' + style + '" disabled title="' + escapeHtml(title) + '">' +
              escapeHtml(el.label || "") + "</button>";
          }).join("");
          return '<div class="salt-card-block salt-card-actions">' + buttons + '</div>' +
            '<p class="salt-card-note">This card is interactive in Salt. Open the chat there to respond.</p>';
        }
        return "";
      }

      function render(card) {
        if (!card || !Array.isArray(card.blocks) || card.blocks.length === 0) {
          root.innerHTML = '<p class="salt-card-empty">Nothing to show yet.</p>';
          return;
        }
        root.innerHTML = card.blocks.map(renderBlock).join("\\n");
      }

      // Every reasonably-documented shape a host might use to deliver this
      // tool's result to the iframe (see the exported function's doc
      // comment for why this listens broadly rather than betting on one).
      function extractCard(data) {
        if (!data || typeof data !== "object") return null;
        var structured =
          (data.params && data.params.structuredContent) ||
          (data.result && data.result.structuredContent) ||
          data.structuredContent ||
          (data.params && data.params.card) ||
          data.card;
        return structured || null;
      }

      window.addEventListener("message", function (event) {
        // Only accept a message from the frame that actually embedded us.
        // A sandboxed iframe with no allow-same-origin has an opaque
        // origin, and so, typically, does its embedding parent -- so
        // event.origin is not a reliable check here (per the MCP Apps
        // messaging model). event.source IS reliable: postMessage always
        // sets it to the real sending window, regardless of origin, so
        // comparing it against window.parent rejects a message from any
        // OTHER frame (a malicious sibling, an ad, anything else sharing
        // this page) even though this document can't name its parent's
        // origin as a string. Flagged in a 2026-09-18 security review.
        if (event.source !== window.parent) return;
        var card = extractCard(event.data);
        if (card) render(card);
      });

      // Handshake -- announces this view is ready, per the MCP Apps
      // ui/initialize flow. Sent to "*" because a sandboxed iframe with an
      // opaque origin cannot address the parent by its real origin.
      try {
        window.parent.postMessage({ jsonrpc: "2.0", id: 1, method: "ui/initialize", params: {} }, "*");
      } catch (e) {
        // Not embedded in a host that speaks this protocol -- inert, not fatal.
      }
    })();
  </script>
</body>
</html>`;
}
