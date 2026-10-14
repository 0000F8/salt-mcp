// Wire-protocol markers in decrypted Salt messages, stripped the way the Salt
// website strips them before a person reads a message. A line-for-line port of
// salt-fe src/utilities/messages.jsx (stripWireMarkers, stripDisplayMarkers,
// stripMarkdown, previewText) and the marker modules it draws on
// (work.js, askContext.js, characterMarkers.js, identityMarkers.js). The
// markers are protocol between Salt's clients and agents, never words.
//
// If a marker changes there, change it here; tests/me-markers.test.mjs holds
// the cases copied from the web's own tests.

const DELEGATION_MARKER_RE = /^\[\[SALT-DELEGATION depth=\d+\]\]\n?/;
const MEDIATE_FINAL_MARKER_RE = /^\[\[SALT-MEDIATE-FINAL\]\]\n?/;
const PLUGIN_START_MARKER_RE = /^\[\[SALT-PLUGIN-START\]\]\n?/;
const HANDOFF_BRIEFING_MARKER_RE = /^\[\[SALT-HANDOFF-BRIEFING\]\]\n?/;
const SESSION_NOTE_MARKER_RE = /\n?\[\[SALT-SESSION-NOTE\]\][^\n]*$/;
const THINKING_MARKER_RE = /^\[\[SALT-THINKING\]\]([\s\S]*?)\[\[\/SALT-THINKING\]\]\n?/;
const PAGE_CONTEXT_MARKER_RE =
  /\[\[SALT-PAGE(?:\s+\w+="(?:[^"\\]|\\.)*")*\s*\]\](?:(?!\[\[\/?SALT-PAGE)[\s\S])*\[\[\/SALT-PAGE\]\]\n?/g;
const ORPHAN_PAGE_TOKEN_RE = /\[\[\/?SALT-PAGE[^\]]*\]\]\n?/g;
const ASK_CONTEXT_RE = /^\[\[SALT-CONTEXT[^\n]*(?:\n|$)/;
const WORK_MARKER_RE = /^\[\[SALT-WORK ([^\]\n]*)\]\]\n?/;
const WORK_CANCEL_RE = /^\[\[SALT-WORK-CANCEL id=([A-Za-z0-9_-]{1,64})\]\]\n?$/;
const CHARACTER_ASK_MARKER_RE = /^\[\[SALT-CHARACTER-ASK(?: mode=(?:draw|again|tweak|refine))?(?: for=me)?\]\][ \t]*\n?/;
const CHARACTER_CURRENT_RE = /\n?\[\[SALT-CHARACTER-CURRENT\]\][\s\S]*$/;
const CHARACTER_DRAWN_RE = /^\[\[SALT-CHARACTER-DRAWN for=me\]\][ \t]*\n?/;
const IDENTITY_MARKER_LINE_RE = /^\[\[SALT-IDENTITY-(SLICE|ASK|DECLINE|REVOKE) ([^\]\n]*)\]\]\n?/;

// A personal-drawing reply keeps only the sentence after its svg.
function stripCharacterDrawn(text) {
  if (typeof text !== "string" || !CHARACTER_DRAWN_RE.test(text)) return text;
  const body = text.replace(CHARACTER_DRAWN_RE, "");
  const start = body.indexOf("<svg");
  const end = body.lastIndexOf("</svg>");
  if (start < 0 || end < start) return "";
  return body.slice(end + 6).trim();
}

// An identity-marker message is only ever the marker: the whole body goes.
const stripIdentityMarkers = (text) => (IDENTITY_MARKER_LINE_RE.test(typeof text === "string" ? text : "") ? "" : typeof text === "string" ? text : "");

export const stripWireMarkers = (text) =>
  stripCharacterDrawn(text || "")
    .replace(ASK_CONTEXT_RE, "")
    .replace(WORK_MARKER_RE, "")
    .replace(WORK_CANCEL_RE, "")
    .replace(CHARACTER_ASK_MARKER_RE, "")
    .replace(CHARACTER_CURRENT_RE, "")
    .replace(DELEGATION_MARKER_RE, "")
    .replace(MEDIATE_FINAL_MARKER_RE, "")
    .replace(PLUGIN_START_MARKER_RE, "")
    .replace(PAGE_CONTEXT_MARKER_RE, "")
    .replace(ORPHAN_PAGE_TOKEN_RE, "");

export const stripDisplayMarkers = (text) =>
  stripIdentityMarkers(
    stripCharacterDrawn(text || "")
      .replace(ASK_CONTEXT_RE, "")
      .replace(WORK_MARKER_RE, "")
      .replace(WORK_CANCEL_RE, "")
      .replace(CHARACTER_ASK_MARKER_RE, "")
      .replace(CHARACTER_CURRENT_RE, "")
      .replace(HANDOFF_BRIEFING_MARKER_RE, "")
      .replace(THINKING_MARKER_RE, "")
      .replace(PLUGIN_START_MARKER_RE, "")
      .replace(PAGE_CONTEXT_MARKER_RE, "")
      .replace(ORPHAN_PAGE_TOKEN_RE, "")
  );

/**
 * What a reader (here, the owner's AI) should see for a decrypted message: every wire marker the website hides,
 * the hand-off briefing marker and its trailing session note, and the thinking block. Applied wire-first so a
 * delegation prefix does not shield a marker behind it.
 */
export function cleanMessageText(text) {
  return stripDisplayMarkers(stripWireMarkers(text)).replace(SESSION_NOTE_MARKER_RE, "").trim();
}

const MD_FENCE_RE = /```[^\n]*\n?/g;
const MD_IMAGE_RE = /!\[([^\]]*)\]\([^)]*\)/g;
const MD_LINK_RE = /\[([^\]]+)\]\([^)]*\)/g;
const MD_CODE_RE = /`([^`]*)`/g;
const MD_EMPHASIS_RE = /(\*{1,3}|_{1,3}|~~)(\S(?:[^\n]*?\S)?)\1/g;
const MD_LINE_LEAD_RE = /^[ \t]*(?:#{1,6}[ \t]+|>[ \t]?|(?:[-*+]|\d+[.)])[ \t]+)/gm;

export const stripMarkdown = (text) => {
  let out = (text || "").replace(MD_FENCE_RE, "").replace(MD_IMAGE_RE, "$1").replace(MD_LINK_RE, "$1").replace(MD_CODE_RE, "$1");
  out = out.replace(MD_EMPHASIS_RE, "$2").replace(MD_EMPHASIS_RE, "$2");
  return out.replace(MD_LINE_LEAD_RE, "").replace(/\s+/g, " ").trim();
};

/** One plain line for a chat-list preview. */
export const previewText = (text) => stripMarkdown(cleanMessageText(text));
