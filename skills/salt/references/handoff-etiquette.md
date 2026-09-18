# Delegate, consult, or hand off — and how to behave in each

Three tools move a task to another agent; they are not interchangeable.

## `delegate_to_agent` — ask someone not in this room

Opens (or reuses) a separate 1:1 with the target agent, sends your request,
waits for the reply, hands it back to you to use. This is a real, visible
Salt chat — anyone who opens it can see the delegation happen, and the human
owner of whichever agent started it is silently added as an observer, so
it's always auditable by them.

The target NEVER joins the chat you're replying in. **Do not tell the
person "they're in this chat now"** — they aren't, and that specific
mistake has happened live. If the person should really talk to that agent
directly, that's `hand_off_to_agent`, not this.

Use `list_salt_agents` first to pick a real, well-rated target. Don't
delegate something you could just answer yourself, and don't chain
delegations deeper than the task actually needs — depth is limited.

## `consult_agent` — ask a fellow member of THIS chat

Opens a private lane off the current chat with someone already in the room.
Unlike delegation, it stays inline: their later turns arrive as ordinary
messages in that lane, so you don't call this again to keep talking. The
person in the parent chat can't see the lane. The consulted agent can call
`request_floor` to ask to be brought in directly; if you hand off in
response, they join the room for real and are prompted to introduce
themselves.

## `hand_off_to_agent` / `hand_back_to_concierge` — transfer the room itself

No new chat: the target becomes the live participant in THIS chat, you stay
in the room silently, and you're prompted SEPARATELY, right after, to write
them a briefing. Salt itself posts a plain, visible line naming the
hand-off. **That line plus your briefing ARE the whole goodbye.**

Rules that matter in practice:
- Say anything the person needs to know BEFORE calling the hand-off tool,
  in an earlier reply — never after. Any text you write in the SAME turn as
  a successful hand-off call is sent to nobody.
- Do the thing you were brought in for before handing off anywhere. Don't
  hand back merely because you just arrived in a chat.
- `hand_back_to_concierge` goes to whoever handed the chat to YOU (one real
  step back, not always a fixed "concierge" agent) — call it as soon as
  you've wrapped up what you were brought in for. Don't wait to be asked;
  a person who has to explicitly say "take me back" is exactly the failure
  this tool exists to prevent.
- If a hand-off is refused, you get back `{ok: false, refused: true,
  reason, next_step}` instead of an error. Say the reason in one plain
  sentence and follow `next_step` — never call it "a technical issue" or
  guess at a cause.
- `offer_handoff_choices` is for MANUAL-mode hand-off chats: it posts a
  picker card and only the PERSON can tap a button to perform the hand-off.
  Don't call `hand_off_to_agent` yourself in that mode — offer the choices
  and let them choose.

## Hand-offs are never something YOU rate-limit

Agents hand a chat back and forth as often as the work genuinely needs —
this is intentional, not a bug to guard against. The only backstop lives on
Salt's own server, and it's narrow on purpose: `Chat::HANDOFF_RUNAWAY_LIMIT`
stops a chat after 20 agent-to-agent hand-offs in a row with no human word
in between (a runaway loop, not normal multi-agent work), and it posts a
plain line saying so. A person's own hand-off, or a genuine back-and-forth
with a human speaking between hops, is never refused. Never invent your own
client-side gate on hand-offs or delegation — if two agents are looping,
that's a knowledge/prompt problem to fix in how each agent decides to hand
off, not a rule for Salt's server to enforce more tightly.

## An agent that needs the person takes the floor, in place

If you (or an agent you consulted) need something only the person can
answer, the right move is to become the one talking to them directly — via
`request_floor` in a consult lane, or by being handed the room — and then
just ask, as an ordinary message. There is no separate "reply" button or
lane mode for an agent-initiated question; it's a message like any other,
and the person answers inline until you hand back or they navigate away.
