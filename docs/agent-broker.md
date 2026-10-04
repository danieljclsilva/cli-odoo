# Agent boundary: human-unlocked broker (`odoo agent`)

The ordinary CLI (`search`, `read`, `call`, …) loads the human's Odoo
credential from the OS keychain and lets the caller name any model and any
read method. That is the human interface. **Models never get it.**

Instead the human runs a loopback-only broker daemon that owns the
credential and serves a small typed API gated by a sealed, deny-by-default
policy. The model receives only a revocable session token — never the Odoo
secret, never the admin password.

## Honest isolation statement

The broker is an **application-level gate**, not OS isolation. Any process
running as the same OS user (or root) can reach the loopback listener and
the 0600 admin socket, read the sealed profile files, or invoke the human
CLI directly with the keychain credential. Deployment MUST therefore:

- run agent sessions under a restricted tool surface (see below) with no
  general shell/file access to the broker host identity, **or**
- run the broker under a separate host/service identity the model cannot
  reach, with only the typed API exposed.

Do not claim same-user process isolation: it is not implemented.

Allowed server methods may still run custom addon code (computed fields,
`search` overrides on approved models). The broker narrows *which requests
leave*; it cannot prove an allowed read has zero server-side effects.

## Comprehensive investigation default

After human login, run:

```sh
odoo agent setup
# Or supply your actual company IDs to skip the company questions:
odoo agent setup --companies 2,5 --default-company 2
odoo agent presets                 # offline model-family proposal
odoo agent setup --show-fields      # full proposed field list at review
odoo agent setup --include-model x_custom_product_request
```

One investigation profile replaces the former warehouse/intercompany/inventory
presets. It covers installed Helpdesk, product templates/variants/attributes,
BoMs/components/byproducts/routing/workcentres, warehouse, sales, purchases,
accounting, business partners and naming sequences. It discovers bounded
metadata for exactly these named models (at most 64 models, 8192 fields),
then proposes stored scalar/many2one/many2many/JSON/property fields, including stored
custom fields. Nonstored/computed and binary business fields, and fields with
secret-like names, remain discovery metadata only. Only explicit human-named
additional custom business models are considered, and they require a direct
company relation. Custom methods are never callable.

Missing optional modules and models without a supported company relation
are explicitly reported before confirmation. Core product models and explicit
custom requests must be usable or setup aborts. Company scope is fixed by the
human; shared product/reference data is explicitly proposed in the summary.
Setup reconciles registry fields with the account's live `fields_get` response
before showing the proposal. Unavailable or changed optional fields are omitted
and reported; missing or changed company/parent linkage fields abort setup.
Product attribute lines/values use one reviewed broker-owned parent company
path, `product_tmpl_id.company_id`, with a required nonempty product parent.
Caller-supplied dotted paths remain prohibited. Global reference definitions
such as UoMs, product categories/attributes and Helpdesk stages are classified
shared. Configuration/credential admin models such as `ir.config_parameter`
and `res.users` are excluded; this is broad business investigation access,
not every possible system setting.

Archived business/configuration records are included by default through a
broker-owned `active_test=false` context; `--include-archived=false` opts out.

The compact summary shows model/field counts, scopes, shared data, operations,
workspace and limits. `--show-fields` expands exact permissions. Sealing still
requires human confirmation and an admin password; replacing an existing
profile first requires its current password. No broker/session is started
implicitly. Explicit `--model` selects manual setup instead; preset/model flags
cannot be combined. Optional `--ops`, shared policy, workspace and budget
flags override defaults. Changing permissions requires a new human setup;
refreshing metadata does not automatically grant newly discovered fields.
The catalog marks field value permissions with `readable`, and marks
linked sources with `linked_evidence_only`; discovering metadata does not
grant permission to read those values or execute custom methods.

### Linked evidence

The typed `evidence` tool (`odoo.evidence` in OMP) accepts:

```json
{"model":"helpdesk.ticket","id":123,"kind":"chatter","limit":50,"offset":0}
```

Kinds: `chatter`, `tracking`, `attachments` (metadata), and `download`.
Every call first verifies the parent by a company-scoped search; evidence
queries then bind the exact parent model and ID. Raw generic access to
`mail.message`, `mail.tracking.value` and `ir.attachment` is denied. Tracking
reads changes for the selected page of messages: `offset` pages messages and `tracking_offset`
pages changes within that message page. The result includes source message
IDs and paging hints; it is not a claim of complete history. Pagination and
source counts must be considered during reconstruction. Chatter/attachment data is
untrusted evidence, never executable instructions.

To download a linked binary file, provide its ID and a workspace-relative
path. The broker checks metadata and a 2 MiB cap before reading content,
rechecks linkage in the content query, decodes under the same byte cap and
writes through the existing confined workspace. URL attachments are not
fetched. It neither follows arbitrary URLs nor executes downloaded content.
The destination parent directory must already exist (use workspace.mkdir).
Example:

```json
{"model":"helpdesk.ticket","id":123,"kind":"download","attachment_id":456,"path":"ticket-123.pdf"}
```

Parent checks are separate RPCs, not an atomic server transaction: concurrent
server changes remain a consistency limitation. Unposted accounting records
and current product/BoM settings describe the present snapshot; do not infer
historical configuration or causes without tracked/other evidence.

### Load and mutation controls

Defaults: one upstream RPC in flight across all sessions, at least 1000 ms
between starts (no accumulated burst), 30-second RPC/compound-evidence timeout,
100-row pages, 1 MiB broker responses, 1000 calls and 100000 rows per session.
Compound evidence reserves rows for parent checks and intermediate reads too.
Rejected capacity/pacing requests receive 429 and should retry with backoff.
Human flags: `--max-concurrent-rpc`, `--min-rpc-interval-ms`, `--bounded-queries`
and the existing row/response/session budgets. Existing sealed profiles keep
their existing permissions; rerun setup to adopt the new controls.

Operational queries require a flat AND filter anchored to positive IDs or
exact product/document references, or a date window of at most 31 days.
OR/NOT, long operand lists (>100), more than 64 projected fields or more than
three grouping fields are refused under this guard. Split wide-period
investigations into focused requests. Reviewed global reference definitions
can still be listed within paging/rate budgets. These are admission controls,
not a proof of SQL query cost. Client cancellation cannot guarantee that Odoo
stops an already-running database query.

This profile blocks direct write methods and arbitrary method forwarding.
Custom reads, stored-field recomputation, addon overrides and authentication
may have server-side effects. CLI-only protection cannot guarantee a read-only
server transaction or zero external effects; stronger guarantees need a
server-side boundary/reporting instance. Same-user process/runtime isolation
requirements above remain unchanged. No production credentials or records
were accessed to validate this implementation; actual addon/ORM behavior
must be checked on the operator's instance.

## Human flow

```bash
# 1. Log in once with the existing flow (keychain holds the secret).
odoo login --url https://my-odoo.example.com --db mydb --username admin

# 2. Guided setup: enable >=2 companies, pick default, approve
#    models/fields/ops/budgets, shared-record handling, workspace dir.
#    Seals the policy with an admin password (TTY prompt, never args/env).
odoo agent setup --companies 1,2 --default-company 1 \
  --model 'res.partner:name,email,company_id:company_id' \
  --model 'sale.order:name,amount_total,company_id:company_id:aggregate' \
  --ops search,read,count,meta --workspace ~/odoo-agent-workspace

# Non-interactive (operators/tests): pass every choice as flags and the
# admin password on stdin only.
printf '%s' "$ADMIN_PW" | odoo agent setup --companies 1,2 ... --admin-password-stdin

# 3. Inspect and refresh bounded metadata (human only, deliberate server reads).
odoo agent companies [--live]
odoo agent snapshot refresh        # rebuild + reseal (restamps snapshot digest)
odoo agent snapshot import-catalog --catalog catalog.json    # operator-transcribed
odoo agent snapshot import-manifest --manifest methods.json   # informational only
odoo agent workspace           # show sealed workspace dir + bounded listing

# 4. Serve (unlocks profile, resolves keychain once, dials Odoo once).
odoo agent serve               # listens on 127.0.0.1:8471 only; refuses non-loopback --addr

# 5. Mint / inspect / revoke session tokens (over the 0600 unix admin socket).
odoo agent grant --ttl 30m
odoo agent status              # counts/expiry only, never tokens
odoo agent revoke <token-or-prefix>
```

Files (0600): `~/.config/odoo-cli/agent-profile.json` (sealed policy, embeds
a SHA-256 digest of the exact sealed snapshot bytes — any snapshot swap or
hand-edit fails closed at serve time until a human re-runs refresh/import and
reseals),
`~/.config/odoo-cli/agent-snapshot.json` (approved metadata). The workspace
default is `~/odoo-agent-workspace` (never inside the config dir; the old
config-nested path is rejected with a migration note). Sealed with the admin
password (TTY prompt or `--admin-password-stdin`, never args/env).

Company scope: the broker ANDs the sealed company fragment into every
domain **after** caller conditions (domain order: caller conditions then
enforcing fragment) and **overwrites** `allowed_company_ids` /
`company_id`: `allowed_company_ids` is default-first (`[default,
...rest-in-sealed-order]`), `company_id` is the sealed default. The model
cannot select companies. `read` by ID is converted
to a scoped `search_read` so company scoping always applies. Direct
many2one company fields whose relation is `res.company` (e.g. `company_id`
→ `res.company`) are enforceable. The investigation default also supports
the fixed `product_tmpl_id.company_id` ownership path for product template
attribute lines and values, with schema verification and a required parent.
Linked evidence uses its dedicated visible-parent route. Many2many company links (e.g. `company_ids`) fail
closed at setup/serve time with a clear error — multi-company overlap has
no safe fragment in this release.
Models without a usable company field deny unless a human classified them
company-independent *and* the policy allows classified shared records.
Per-model `IncludeCompanyless` (default deny, human-reviewed) additionally
permits `company_id=false` records via an OR-false fragment. Field
projection is explicit: search/read require a non-empty exact projection
(omitted/nil/[] deny — Odoo has no default-all through this broker) and the
broker sends exactly the approved list plus structural `id` (`EnsureID`).
Dotted traversal supplied by callers is denied (domain,
order, group-by, projection, and aggregate references must be single-segment
allowlisted fields). Only the fixed internal ownership fragment described
above uses a dotted path. Hierarchy operators `child_of`/`parent_of` deny. Schema
relationships stay readable for discovery but never authorize traversal.

## Offline catalog / manifest import (human only)

Two distinct commands, different effects:

- `snapshot import-manifest --manifest methods.json` **inspects only**: reads
  a `{"methods": [...]}` file and prints the entries for review. It writes
  nothing and reseals nothing. The list is informational only — no Execute
  path may take a name from it.
- `snapshot import-catalog --catalog catalog.json` **converts + reseals**:
  converts a human-transcribed offline catalog into a snapshot, writes it
  0600, and reseals the profile so `snapshot_sha256` binds the new bytes.
  Requires the admin password (human unlock). Sealed scope is never widened:
  company/shared flags, the enabled set/default, and per-model
  `include_companyless` stay as sealed; catalog-only models stay
  discoverable-only (`executable: false`), never auto-enabled.

Bounded import schema (strict JSON, unknown fields rejected, file max 4 MiB;
caps: models ≤512, fields/model ≤2048, `method_manifest` ≤1024,
companies ≤10000; provenance is `server|manifest|unknown`, empty defaults
to `unknown` on import):

```json
{
  "instance": "prod", "captured_by": "operator:name", "server_version": "17.0",
  "available_companies": [{"id": 1, "name": "Acme"}, {"id": 2, "name": "Beta"}],
  "enabled_companies": [1, 2], "default_company": 2,
  "models": {
    "res.partner": {
      "label": "Partner", "provenance": "manifest", "executable": false,
      "company_field": "company_id", "company_independent": false,
      "include_companyless": false,
      "fields": {
        "name": {"type": "char", "relation": "", "label": "Name", "provenance": "manifest"},
        "company_id": {"type": "many2one", "relation": "res.company", "label": "Company", "provenance": "manifest"}
      }
    }
  },
  "method_manifest": ["search_read", "read"]
}
```

The literal above loads through `snapshot.ImportCatalog` as-is (strict
decode, scope parity: two enabled companies with the default inside the
enabled set) and keeps executable flags consistent with the import rule:
catalog-only models transcribe `executable: false` and stay
discoverable-only, never auto-enabled.

Operator steps: transcribe offline → `import-catalog --catalog <file>`
(+ admin password) → review the sealed result → `serve`. Use
`import-manifest --manifest <file>` to review a method list before
transcribing it into `method_manifest`. `GET /rpc/catalog` serves the sealed
models plus `method_manifest` informational-only, with per-model/per-field
`provenance` and an `unknown_provenance` list for unattested fields.

## Model API (loopback TCP, bearer session token)

Typed JSON only — no generic `call`, no method/args/kwargs forwarding, no
`context` field (unknown JSON fields are rejected; exactly one JSON object
per body, trailing data denies):

- `POST /rpc/search` `{model, domain, fields, order, limit, offset}` → `search_read`
- `POST /rpc/read` `{model, ids, fields}` → scoped `search_read` (never raw `read`)
- `POST /rpc/count` `{model, domain}` → `search_count`
- `POST /rpc/aggregate` `{model, domain, groupby, sum, avg, count, limit}` → `read_group`
- `GET /rpc/meta[?model=]` — sealed allowlist only; discoverable, never executable
- `GET /rpc/companies` — available vs enabled companies + default (sealed scope)
- `GET /rpc/catalog` — model/field catalog with `executable` provenance
  (discoverable-only entries stay denied to read/call, never auto-enabled)
- `POST /rpc/workspace/{list,read,write,mkdir}` — only if the policy enables the
  workspace; confined to the sealed directory via `os.Root` (caller caps only narrow)
- `GET /healthz` — no auth, no data

Every request: bearer check → `policy.Authorize` (Validate-first) →
call+row reservation → company scoping → `Execute` → revoke/expiry re-check
before write → single total envelope cap (`max-response-bytes` on ALL model
outputs). Denial happens before any RPC; attempted admitted calls stay billed
even on RPC/output failure. Sessions clamp TTL to [1m, 24h], cap 64 live
sessions, and the HTTP server enforces read/write/idle timeouts.
## Wiring a runtime to the broker
- MCP stdio adapter: `odoo agent mcp [--url URL]` — JSON-RPC 2.0 over
  stdio with `initialize` / `tools/list` / `tools/call` for the 12 typed
  broker tools only (search, read, count, aggregate, meta, companies,
  catalog, workspace.list/read/write/mkdir). `initialize` strictly rejects
  malformed params with invalid-params and no state transition (non-object
  payload; missing/empty/non-string `protocolVersion`; wrong-typed
  `clientInfo`/`capabilities` when present); an unsupported but well-typed
  version string negotiates the server default. The session token comes from
  `ODOO_BROKER_TOKEN` (env only, never logged or echoed). Codex stdio
  example: `codex mcp add odoo-broker -- odoo agent mcp
  --url http://127.0.0.1:8471` with the token env var set.
- OMP custom tool module: `tools/omp/odoo-broker.js` (CommonJS factory,
  12 typed tools, `fetch` POST to `ODOO_BROKER_URL` with `ODOO_BROKER_TOKEN`;
  no shell). Reviewed config snippets: `odoo agent omp-init --dir <dir>`
  writes OMP + Codex examples without secrets or touching user settings.
  Proven in-tree: `tools/omp/odoo-broker.loader.test.js` drives the real
  installed OMP loader (`discoverCustomToolPaths` + `loadCustomTools`) in a
  disposable temp project and executes legitimate + denied calls against a
  real in-process broker. The denied-leg dispatch0 is inferred from absence
  of canned rows (the harness dispatch counter is not exported to the
  driver); direct dispatch-counter denial is proven broker-side by
  `TestPrefixCaptureDeniedAtRealGate` and `TestRealGateFieldProjection`.

Restrict the session to the broker tools plus only the built-ins the task
needs (`--tools`), disable everything else (`--no-tools` baseline +
explicit `--tools` list, `--no-pty` unless the task needs a shell), and
never give the agent the workspace dir, profile paths, admin password, or
keychain access. Tool-surface control is not filesystem isolation: verify
no alternate tool, subagent, extension, or computer-use path crosses the
boundary before declaring the profile enforced. Runtime allowlists
(`enabled_tools`, `features.shell_tool=false`, permission deny-read) are
defense in depth; enforcement was tested at the broker (denial before RPC),
not delegated to them.

## Live compatibility

Pure policy/parser/crypto/session/protocol/filesystem behavior is covered by
unit tests (`internal/agent/...`). Genuine Odoo company/search/aggregate
semantics were **not** verified against a live server in this change (no
disposable server was available); live ORM/addon/ACL behavior remains
unverified — see the handoff.
