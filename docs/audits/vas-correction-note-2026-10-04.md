# VAS Correction Note — 2026-10-04

Scope: audit + metadata facts only. No private data. No record contents, no
prices, no customer/vendor names, no attachments, no chatter text, no secrets.

This note corrects classification errors in the original VAS investigation report, using the audit (docs/audits/vas-tool-usage-2026-10-04.md) as evidence. It changes no broker behavior. It reproduces no user process report content. A failed attempt records `failed`; it does not by itself prove the model `unavailable` — see the legend below.

## Evidence-kind legend

- `enabled`: model/method passed exposure/policy checks at audit time (metadata
  fact). Does not assert a read succeeded.
- `not-enabled`: absent from sealed exposure (metadata fact). Changing it
  requires a new human `agent setup`, never a session grant.
- `denied`: broker policy denied the attempt by design (policy fact). Not an
  Odoo/ORM failure — and never by itself proof of underlying model absence.
- `failed`: an attempted call returned an error (execution fact). Requires
  error evidence to classify — and never by itself proof of underlying model
  absence (a transient failure is not server absence).
- `not-investigated`: never attempted; no execution evidence either way
  (audit-scope fact). MUST NOT be reported as `unavailable`.

## Corrections
| # | Claim | Prior (incorrect) reading | Corrected status | Evidence kind | Basis (meta/audit fact only) |
|---|---|---|---|---|---|
| 1 | `product.template.attribute.value` availability | read as unavailable / Odoo-side gap | `not-investigated`: meta-enabled, never attempted | `enabled` (exposure) + `not-investigated` (execution) | Model was meta-enabled; audit performed no read against it. Absence of attempt is not evidence of unavailability. |
| 2 | `product.template.attribute.line` availability | read as unavailable / Odoo-side gap | `not-investigated`: meta-enabled, never attempted | `enabled` (exposure) + `not-investigated` (execution) | Model was meta-enabled; audit performed no read against it. Absence of attempt is not evidence of unavailability. |
| 3 | `stock.rule` route-rule lookup outcome | read as Odoo failure / missing data | `denied`: designed policy denial, executed and refused by broker policy | `denied` | The lookup was attempted and refused by broker exposure/policy, not by Odoo. A denial proves routing, not ORM semantics. |

## Rules going forward

- Never report `not-investigated` as `unavailable`, and never treat `denied`
  or `failed` alone as proof of underlying model absence: a policy denial
  or a transient failure is not server absence.
- Never report `denied` as an Odoo/ORM failure. Denials are broker-policy
  outcomes; they prove nothing about the underlying model.
- Dispatch-recorder fakes prove routing/denial only. They are not evidence of
  Odoo ORM semantics (no live Odoo; synthetic fixtures only).
- Real tracking compatibility and production query cost remain unknown; do not
  certify either from this audit.
