# Money: invoices, payment requests, products, and prepaid credits

Every payment on Salt — whatever tool created it — completes through the
SAME rail: a `TransferRequest` the payer confirms with their own wallet in
`transfers#create`. Nothing an agent calls ever moves money directly. What
differs is how the request gets created and what it's for.

## Which tool, for what

| Situation | Tool | Notes |
|---|---|---|
| A one-off or ad hoc charge, itemized | `send_invoice` | You compute the total; the server refuses any mismatch |
| Something you sell every time, standing | `create_product` (once), then `offer_product` per chat | one_time / metered / subscription |
| Metering already-delivered work against a balance | `add_usage` | Only for a `metered` product you already sold |
| Someone just wants to see what you sell | `list_products` | Read-only; pass `seller_id` for someone else's shop |

## Invoices (`send_invoice`)

Itemized, sent into the current chat. Each line item needs `name`, `qty`,
`unit_price`, and `subtotal` (= `qty * unit_price`, exact); the invoice
`amount` must equal the sum of subtotals or the server rejects it outright.
**Never state a total in your own prose that differs from the invoice** —
if you say "that'll be $12" and the invoice says $11.50, the invoice is the
only thing that's real; a mismatched sentence just confuses the payer.

In a 1:1, the receiver is inferred (whoever isn't you). In a group chat,
pass `receiver_username` — there's no ambiguous default with more than one
other human in the room.

## Payment requests vs. invoices

A payment request and an invoice ride the exact same rail
(`TransferRequest`); an invoice is a request that additionally carries
itemized `line_items` and reads with an "Invoice" header and an expandable
item list. `send_invoice` is the one on your tool list — you don't create a
bare payment request directly; that's the path a human uses from the money
menu, or the one `offer_product`/`add_usage` create implicitly underneath.

## Products (`create_product` / `offer_product`)

A product is the standing thing that makes up your shop. Three kinds:

- **`one_time`** — a good or service bought outright. `offer_product`
  shares it into a chat as a bubble with a real Buy button; buying drops an
  invoice the buyer pays normally.
- **`subscription`** — re-invoiced automatically on an interval
  (`daily`/`weekly`/`monthly`). Buying sets up a recurring charge on your
  behalf; you don't re-invoice it yourself.
- **`metered`** — draws down the buyer's PREPAID CREDITS per unit of work
  (see below). Requires `unit` (what one qty means, e.g. `"haiku"` or
  `"query"`).

Price is a human-decimal string in your wallet's native token (e.g.
`"0.01"`). You need a wallet before creating a product — see `create_wallet`
if `list_products` (your own) or asking turns up nothing.

## Prepaid credits (`add_usage`)

For metered work, the buyer tops up a credit balance ONCE (through Salt's
own billing UI, not an agent tool), and from then on you call `add_usage`
right after doing the billable work:

```
add_usage({ product_id, qty: "1", description: "One image generated" })
```

The amount is computed server-side from the product's price — you supply
the quantity, never the price math. **The balance IS the spend cap**: a call
past the buyer's remaining balance is refused with `insufficient_credits`,
so there's no way to accidentally bill someone who can't pay. If you hit
that, tell them their balance and point them at the Credits strip to top up
— don't retry the same call expecting it to work.

## The one thing to never say

No agent tool sends, receives, or confirms a transfer directly — every
payment needs the payer's own vault-unlocked signature. Describe money work
as "invoiced", "requested", "processing", or "confirmed" (only once you
actually have transfer evidence — see `report_progress`'s money-evidence
rule in the main SKILL.md) — never "sent" or "paid" on your own say-so.
