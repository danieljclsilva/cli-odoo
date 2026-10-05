# Audit of VAS investigation tool usage

Date: 2026-10-04. Chat: **Investigate VAS logo request BoM**, `01a106c4-db4c-77f1-b099-eb16b096f195`.

## Scope and evidence

Read-only review of the referenced chat, its saved evidence and reports, and the current CLI source. No Odoo tool calls, production requests, credential reads, source edits, or runtime changes were made for this audit. Recommendations below are not implemented fixes.

Saved evidence: `/Users/komorinokage/odoo-agent-workspace/reports/new-logo-vas-2026-10-04/evidence.json`; accompanying `process-investigation.md` and `evidence-register.md`. Current source includes pre-existing uncommitted changes, so source findings describe this working tree, not necessarily a released binary. The compact chat exposes call arguments/status/duration; saved outputs supply additional evidence. It does not independently establish every server-side operation or inter-call timing.

The agent used 34 broker calls: meta 1, companies 1, catalog 1, search 12, read 3, count 2, evidence 7, workspace.list 2, workspace.mkdir 1, workspace.write 3, workspace.read 1. Four calls failed. No raw RPC, arbitrary method, admin, company override, shell, or write-to-Odoo call appears in the reviewed transcript. Workspace writes saved reports and evidence.

## Prioritized findings

### 1. Successful record payloads can expose bearer links — highest priority

The saved description of helpdesk ticket 2081 contains one nonempty, unredacted `access_token` query parameter. Token values are deliberately omitted from this audit; neither the link nor token was used. This establishes exposure of a token-shaped link, not its validity or permissions. Some chatter links were manually redacted, showing that agent-side cleanup was inconsistent.

The broker's response path marshals record values without a central payload sanitizer (`internal/agent/broker/transport.go:1455`). `redactErr` at line 1587 concerns error text and broker-held secrets; it does not sanitize successful business record text.

**Improve:** sanitize credential-bearing URL parameters and recognized secret-bearing content before returning records or saving automatic evidence, including HTML descriptions, chatter, and attachment metadata. Preserve useful business identifiers and replace removed values with explicit markers. Test alternate URL encodings and nested HTML/JSON, with legitimate text controls. Do not rely on the model to redact correctly. Binary attachment content needs a separately documented policy; a text sanitizer cannot establish that all downloaded files are secret-free.

### 2. Routing configuration lookup was blocked by a generic anchor list

`search(stock.rule, domain=[["route_id","in",[66,27]]], ...)` was denied immediately with `domain-denied`. This left the actual route rules unresolved. The field was an approved projection, but `route_id` is not a recognized bounded-domain anchor (`internal/agent/policy/bounded.go:33`). This is a designed policy denial, not evidence of an Odoo failure.

An earlier `count(helpdesk.ticket, domain=[["team_id","=",1891]])` was similarly denied. The agent recovered using a 31-day creation window and obtained count 61. That proves the selected cohort's count, not the complete team's historical population.

**Improve:** use reviewed, model-specific anchor rules for useful configuration relationships such as `stock.rule.route_id`, with existing limits and company scope. Return structured denial reasons and allowed query shapes. Keep team-wide historical scans bounded: accepting every many2one field would weaken the overload guard. A positive anchor alone is not a database query-cost guarantee.

### 3. Tracking retrieval failed with no actionable diagnosis

`evidence(helpdesk.ticket,1932,kind="tracking",limit=100)` failed after approximately 2.1 seconds with `linked evidence read failed`; chatter for that parent succeeded. There is insufficient evidence to distinguish permissions, a server fault, metadata incompatibility, or a transient failure. No diagnostic recovery was recorded.

`internal/agent/broker/evidence.go:354` replaces most upstream errors with the same message. Tracking involves message retrieval and then tracking-value retrieval, so identifying the failed phase matters.

**Improve:** provide a safe error classification, phase/model, request ID, retryability, and backoff hints. Keep credentials and sensitive upstream payloads out of errors; retain detailed diagnostics in human-accessible logs. Retry only classified transient errors within pacing limits. A real permitted Odoo verification is still needed to establish the cause and fix; this audit intentionally did not perform it.

### 4. Variant applicability was available but incorrectly reported unavailable

The report says applicable variant IDs could not be resolved because `product.template.attribute.value` was unavailable. Saved `meta` explicitly enables that model and its relevant relationship fields, along with `product.template.attribute.line`. The agent never attempted the corresponding read. 59 of 67 saved BoM lines contain applicability IDs.

This is an agent investigation/discovery gap, not a demonstrated broker permission blocker. The saved catalog was reduced to nine models and omitted these models, while the full saved policy metadata retained them.

**Improve:** tell agents to distinguish “not enabled,” “denied,” “failed,” and “not investigated.” Before declaring a model unavailable, consult focused policy metadata. Resolve explicit applicability IDs through bounded reads, then link attribute names/values and component variants. Include that check in investigation completion criteria. Correct the existing report's availability claim before using it as a complete BoM configuration analysis.

### 5. Base-product configuration was only partly investigated

The product reads omitted relevant readable fields visible in the saved catalog, including `parent_code`, `base_attrib`, `attribute_set_id`, and configuration indicators. Component variant and attribute relationships were not fully expanded. Consequently, naming and product derivation explanations are incomplete even where the current tool already exposes evidence.

Some related models, such as `product.attribute.set`, are not in the standard enabled list. Metadata discovery does not authorize executing those models or custom methods. Stored data and structural metadata also cannot prove the behavior of custom server code or automation.

**Improve:** give the investigation workflow a compact relationship checklist for ticket → product template → base/configuration fields → variants/attributes → BoM/applicability → routes/rules. Identify inaccessible relation targets explicitly for human review instead of silently skipping them or enabling arbitrary methods. Keep observed data separate from inferred naming conventions and unverified custom implementation behavior.

### 6. Tool schemas and instructions do not explain important constraints

The agent used `kind="messages"`, which was rejected; it corrected to `chatter`. The MCP evidence schema uses a plain string and its description does not enumerate the accepted kinds (`internal/agent/mcpadapter/mcpadapter.go:245`). Search domains are effectively untyped and the short search/count descriptions do not explain the bounded-domain rules. Initialization has no cross-tool usage instructions.

**Improve:** expose evidence-kind enums and numeric constraints; give concise examples of accepted domain shapes and denial recovery. Publish instructions on linked evidence, variant relationships, embedded untrusted content, completeness, and session renewal. Mirror these contracts in the OMP adapter. Do not broaden execution permissions just to make the model's guessed arguments work.

### 7. Large responses and lost response metadata impair efficient investigation

The ticket cohort's saved payload is about 393 KB; its HTML descriptions total roughly 352,000 characters. The agent fetched every description up front instead of first selecting a narrow cohort projection and then retrieving detailed text for selected cases. No response-size or pacing failure was recorded, but this increases context use and evidence duplication.

The MCP adapter discards the broker success envelope's `count` and returns only `result`; errors are reduced to text (`internal/agent/mcpadapter/mcpadapter.go:914`). Chatter/attachment lists lack the explicit paging hints used by tracking. Both MCP and OMP catalog tools accept no model selector even though the broker supports focused catalog requests.

**Improve:** expose focused catalog queries; encourage narrow projections followed by bounded detail reads. Preserve structured count, paging/completeness, scope, and classified error metadata consistently across adapters. Consider explicit opt-in HTML-to-text summaries while retaining safely redacted source evidence. Budget response bytes as well as request frequency. The recorded durations alone cannot prove server load or pacing compliance.

### 8. Evidence packaging needs stronger provenance and completion checks

The agent wrote three artifacts, read back the narrative report, and listed the directory. The evidence JSON and register were not independently validated/read back in the recorded tool flow. Manual repackaging reduced the catalog and required manual redaction. Attachment metadata was retrieved, but file contents were not downloaded or inspected, so artwork/content assertions remain unverified. Effective pricing was not established by the five template-specific pricelist rows; the report appropriately limits that conclusion.

**Improve:** offer optional broker-generated, redacted evidence bundles with request arguments, timestamps, policy/snapshot identity, response count, pagination status, error classifications, and file hashes. Validate JSON and cross-reference cited records before declaring completion. Include an explicit checklist for unexamined attachments, variant applicability, route rules, effective-price limitations, and custom-code unknowns. Do not convert a partial investigation into a stronger report merely by generating a bundle.

## Availability and security limits

The first turn reported no broker tools; the retry successfully used them. Availability was recovered for this investigation, but session/tool readiness remains a usability concern. A clear adapter readiness signal should distinguish missing tool exposure, unreachable broker, and expired session, with human renewal instructions. No automatic model-accessible admin grant should be introduced.

This chat stayed within the broker's exposed surface. That observation does not prove absence of custom Odoo read side effects, acceptable production query cost, or OS isolation. No live server verification or security boundary retest was performed. These conclusions should not be presented as unrestricted model safety.

## Suggested implementation order

1. Central successful-payload redaction and safe structured diagnostics.
2. Reviewed route-rule query anchors; explicit schemas, denial guidance, and focused catalog support.
3. Correct the agent's availability claim and improve relationship-completion guidance using permissions already available.
4. Structured result/pagination metadata and reproducible evidence packaging.

Acceptance should include malicious and legitimate text controls for redaction, policy-denial and accepted-query controls, actual permitted Odoo evidence for tracking/routing fixes, and an agent run that resolves applicability or reports a specific observed blocker. Avoid mocked Odoo behavior as proof of server semantics.
