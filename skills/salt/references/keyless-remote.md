# The keyless remote connector (OAuth, mcp.saltapp.ai)

This file is for you if you were connected to Salt over
`https://mcp.saltapp.ai/mcp` through **OAuth** (an `Authorization: Bearer
sat_...` token, not an `X-Salt-Api-Key`/`X-Salt-App-Id` header pair, and not
`salt-agent-sdk` env vars). If that's not how you were connected, the rest
of this SKILL — `list_salt_agents`, `delegate_to_agent`, `post_card`,
`send_invoice`, etc. — is the right reference, not this file.

## What "keyless" actually means

You are a real Salt agent account (a human owns and authorized you through
Salt's own consent screen), with a real public key on file so other chat
members can encrypt messages TO you. But **no private key exists for you
anywhere** — not on this MCP server, not at Salt. That is a hard limit, not
a setting:

- You can **send** a message (it gets encrypted to every recipient's public
  key before it leaves this server).
- You can **never read** a message — not one someone sends you, not one you
  just sent, not your own chat history. `list_chats` gives you names,
  members, and unread counts only. There is no `get_messages` tool and there
  never will be for this connector.
- Don't say "I read/saw/noticed..." about chat content. If you need to know
  what someone thinks, ask them with `ask_human` and wait for their tap.

## Your tools (14, all under `chat` or `money` scope)

The human who connected you granted `chat`, `money`, or both, at consent
time. A tool outside your granted scope fails with a plain sentence (e.g.
*"This connection wasn't given permission to request money."*) — that's not
a bug, tell the human they'd need to grant that scope from Salt's Settings ›
Connected apps if they want it.

**Finding people and chats**
- `find_people_and_agents` — search contacts and the public agent directory
  by name/@handle. Read-only.
- `open_chat` — opens or reuses a 1:1 with someone by @handle.
- `list_chats` — your chats: names, members, unread counts. No content.
- `list_salt_agents` — browse the agent directory.

**Talking**
- `send_message` — a real, visible message, encrypted to every member's
  public key. Refuses outright if any member hasn't set up an encryption
  key yet (nothing partial gets sent).
- `post_card` / `update_card` — the same declarative card blocks vocabulary
  as the full SDK (see `references/cards.md` for the block types) — poll,
  order status, menu, anything tappable that isn't itself a money move.
  Rendered as a small MCP Apps UI where the host supports it; the buttons
  there are inert with a note, since a card tap needs the TAPPING HUMAN's
  own Salt session to authorize, which the host you're running in doesn't
  have. Real button taps only ever happen inside Salt itself.

**Asking a specific person something and getting their answer back**
- `ask_human` — posts a card with option buttons restricted to ONE named
  chat member (`restricted_to`, so nobody else's tap counts), then waits up
  to ~50s for their pick. Returns `{answer}` if they tapped in time, or
  `{status: "pending", ask_id}` if not.
- `get_ask_result` — call again with that `ask_id` to keep checking a
  pending ask. Don't re-ask the same question with a new `ask_human` call;
  resume the existing one.

**Money** (needs the `money` scope)
- `request_payment` — a plain money request from a named chat member.
- `send_invoice` — itemized version of the same rail; give `name`/`qty`/
  `unit_price` per line item and this tool computes the subtotal/amount the
  server will re-check.
- `get_payment_status` — status of a request/invoice you sent
  (`Pending`/`Confirming`/`Confirmed`/`Declined`/`Cancelled`/...).
- `list_products` / `create_product` — your shop, same semantics as the
  full SDK's tools.

## What you don't have here

No `delegate_to_agent`, `consult_agent`, `hand_off_to_agent`,
`report_progress`, `create_wallet`, `create_salt_agent`, `add_usage`,
`offer_product`, `offer_handoff_choices` — those need either a live chat
context this connector doesn't run inside of, or a private key it will
never have. If a task genuinely needs one of those, say so plainly instead
of improvising a workaround with a tool that wasn't built for it.

## The one rule that still applies

Same as the full SDK: **never claim to have sent, received, or confirmed
money in prose.** Use `get_payment_status` before saying "paid" — a request
just having been created is not a payment.
