// Wire markers are stripped as the Salt website strips them (src/me-markers.mjs ports salt-fe
// src/utilities/messages.jsx and its marker modules). The cases are the web's own, from messages.test.js and work.test.js.

import { test } from "node:test";
import assert from "node:assert/strict";
import { stripWireMarkers, stripDisplayMarkers, cleanMessageText, previewText, stripMarkdown } from "../src/me-markers.mjs";

const pageBlock = (body = "some page text") =>
  `[[SALT-PAGE url="https://example.test/a" title="Example" captured="2026-08-27T00:00:00.000Z"]]\n${body}\n[[/SALT-PAGE]]`;

test("a page block never survives, even behind a delegation marker", () => {
  assert.equal(cleanMessageText(`${pageBlock()}\nwhat do you make of this?`), "what do you make of this?");
  assert.equal(cleanMessageText(`[[SALT-DELEGATION depth=1]]\n${pageBlock()}\nplease review`), "please review");
  assert.equal(cleanMessageText(`${pageBlock("line one\n\nline two\n\nline three")}\nsummarise`), "summarise");
  const title = '[[SALT-PAGE url="https://x.test" title="Guide How to bake" captured="t"]]\nbody\n[[/SALT-PAGE]]';
  assert.equal(cleanMessageText(`${title}\nwhat is this?`), "what is this?");
});

test("a smuggled closing token leaves no marker syntax behind", () => {
  const out = cleanMessageText(`${pageBlock("harmless [[/SALT-PAGE]] SMUGGLED")}\nreal message`);
  assert.ok(!out.includes("SALT-PAGE"));
  assert.ok(!out.includes("[["));
  assert.ok(out.includes("real message"));
});

test("many unclosed page openers do not hang (ReDoS)", () => {
  const evil = '[[SALT-PAGE a="b"]]x'.repeat(16000);
  const start = Date.now();
  stripDisplayMarkers(evil);
  assert.ok(Date.now() - start < 500);
});

test("delegation, mediate-final and plugin-start markers go", () => {
  assert.equal(stripWireMarkers("[[SALT-DELEGATION depth=3]]\nhello"), "hello");
  assert.equal(stripWireMarkers("[[SALT-MEDIATE-FINAL]]\nHere is wording"), "Here is wording");
  assert.equal(cleanMessageText("[[SALT-PLUGIN-START]]\nLet's build a plugin."), "Let's build a plugin.");
});

test("work, work-cancel and context markers go", () => {
  assert.equal(stripDisplayMarkers("[[SALT-WORK id=w_1 status=running]]\nAsking @weather"), "Asking @weather");
  assert.equal(stripDisplayMarkers("[[SALT-WORK-CANCEL id=wake_1]]"), "");
  assert.equal(cleanMessageText('[[SALT-CONTEXT {"surface":"agents_at_work"}]]\nwhat is running?'), "what is running?");
});

test("character markers go, a drawn reply keeps only its sentence", () => {
  assert.equal(cleanMessageText("[[SALT-CHARACTER-ASK mode=tweak for=me]]\nChange your drawing: red hat\n[[SALT-CHARACTER-CURRENT]]\n<svg></svg>"), "Change your drawing: red hat");
  assert.equal(cleanMessageText("[[SALT-CHARACTER-DRAWN for=me]]\n<svg><g/></svg>\n\nHere I am."), "Here I am.");
  assert.equal(cleanMessageText("[[SALT-CHARACTER-DRAWN for=me]]\n<svg><g/></svg>"), "");
});

test("hand-off briefing, its session note and thinking blocks are hidden from a reader", () => {
  assert.equal(cleanMessageText("[[SALT-HANDOFF-BRIEFING]]\nThey want a refund.\n[[SALT-SESSION-NOTE]] {\"goal\":\"refund\"}"), "They want a refund.");
  assert.equal(cleanMessageText("[[SALT-THINKING]]let me think[[/SALT-THINKING]]\nThe answer is 4."), "The answer is 4.");
});

test("identity markers vanish whole", () => {
  for (const kind of ["SLICE", "ASK", "DECLINE", "REVOKE"]) {
    assert.equal(cleanMessageText(`[[SALT-IDENTITY-${kind} id=abc]]\n{"sections":[]}`), "", kind);
  }
});

test("ordinary text, even when it names the words, is untouched", () => {
  assert.equal(cleanMessageText("just a normal message"), "just a normal message");
  assert.equal(cleanMessageText("Let's build a plugin sometime"), "Let's build a plugin sometime");
  assert.equal(cleanMessageText("see [[docs]] for SALT-WORK details"), "see [[docs]] for SALT-WORK details");
});

test("previews: markers out, then markdown folded to one line", () => {
  assert.equal(stripMarkdown("**Mediator** just told me: *The octopus...*"), "Mediator just told me: The octopus...");
  assert.equal(previewText("[[SALT-DELEGATION depth=1]]\n# Plan\n- one\n- two"), "Plan one two");
});
