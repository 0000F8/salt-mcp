# Cards: the block vocabulary

`post_card` and `update_card` (see `CARD_PROTOCOL_SPEC.md` in the `salt`
workspace root for the full design rationale) take a `blocks` array built
from a small, server-validated vocabulary — the same one salt-fe's
`CardMessage.jsx` renders. Unknown fields are dropped; anything that doesn't
validate is refused, so a card is data, never code:

```
{ type: "section", text?: "markdown, <=2000 chars", fields?: [{label: "<=40", value: "<=160"}] (<=10) }
{ type: "divider" }
{ type: "image", url: "http(s), <=500 chars", alt?: string }
{
  type: "actions",
  elements: [ // 1-5 buttons
    {
      type: "button",
      action_id: "a-z0-9_- , <=40 chars, unique within the card",
      label: "<=40 chars",
      style?: "primary" | "danger",
      action_type?: "default" | "pay",
      pay?: { amount: "base units, as a string", currency: "..." }, // action_type: "pay" only
      restricted_to?: ["<user_id>", ...] // <=20, must be real members of this chat
    }
  ]
}
```

1-20 blocks per card.

## Two kinds of button, dispatched by TYPE not label

- `action_type: "pay"` — Salt itself turns the tap into a real
  `TransferRequest` on the normal payment rail. You never see or handle the
  money; you just describe the amount and currency. **Never** wire a
  payment to a button whose label merely LOOKS like a purchase ("Claim
  reward 🎁") without setting `action_type: "pay"` — the server dispatches
  strictly on the type field, so mislabeling doesn't create a shortcut and
  doesn't fool anyone either.
- Anything else (the default `action_type: "default"`, or omitted) comes
  back to you as a `card_interaction` webhook event. Answer it by calling
  `update_card` with the card's COMPLETE new `blocks` array (not a diff).

## `restricted_to`: default is open

Every member of the chat can tap every button unless you set
`restricted_to`. Set it on any button that shouldn't be that open — delete,
restart, admin actions, a purchase meant for one specific person. Everyone
still SEES the button; anyone not on the list sees it locked and the tap is
refused server-side, not just hidden client-side. Get the ids from the
chat's real member list (e.g. via the delegation/consult tools' member
lookups), never invent one.

## Worked examples

**A poll**, one section per option, a vote button each, updated in place on
every tap:

```json
{
  "text": "Poll: lunch spot",
  "blocks": [
    { "type": "section", "text": "**Lunch spot?** 4 votes so far" },
    { "type": "divider" },
    { "type": "section", "text": "Taco truck", "fields": [{"label": "Votes", "value": "2"}] },
    { "type": "actions", "elements": [{"type": "button", "action_id": "vote_taco", "label": "Vote"}] },
    { "type": "section", "text": "Ramen", "fields": [{"label": "Votes", "value": "2"}] },
    { "type": "actions", "elements": [{"type": "button", "action_id": "vote_ramen", "label": "Vote"}] }
  ]
}
```

On each `card_interaction`, increment your own vote tally and call
`update_card` with the fully re-rendered blocks.

**Order status**, no buttons at all — cards don't need interactivity to earn
their place over prose:

```json
{
  "blocks": [
    { "type": "section", "text": "**Order #4821**", "fields": [
      {"label": "Status", "value": "Preparing"},
      {"label": "ETA", "value": "12 min"}
    ]}
  ]
}
```

**A restricted purchase button** (only the person who asked can buy):

```json
{
  "blocks": [
    { "type": "section", "text": "**Premium plan** -- $9.99/mo" },
    { "type": "actions", "elements": [
      {
        "type": "button", "action_id": "buy_premium", "label": "Subscribe",
        "action_type": "pay", "pay": {"amount": "9990000", "currency": "USDC"},
        "restricted_to": ["482910"]
      }
    ]}
  ]
}
```

`offer_handoff_choices` builds a picker card the same way, under the hood —
you don't need to hand-build one yourself for that flow, just call the tool.
