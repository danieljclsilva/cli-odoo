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
domain **after** caller conditions and **overwrites** `allowed_company_ids`
/ `company_id`. The model cannot select companies. `read` by ID is converted
to a scoped `search_read` so company scoping always applies. Only direct
many2one company fields (e.g. `company_id` → `res.company`) are enforceable:
many2many links (e.g. `company_ids`) fail closed at setup/serve time with a
clear error — multi-company overlap has no safe fragment in this release.
Models without a usable company field deny unless a human classified them
company-independent *and* the policy allows classified shared records.
Per-model `IncludeCompanyless` (default deny, human-reviewed) additionally
permits `company_id=false` records via an OR-false fragment. Field
projection is explicit: search/read require a non-empty exact projection
(omitted/nil/[] deny — Odoo has no default-all through this broker) and the
broker sends exactly the approved list plus structural `id` (`EnsureID`).
Dotted traversal is denied unconditionally (minimum safe choice: domain,
order, group-by, projection, and aggregate references must be single-segment
allowlisted fields); there is no separately reviewed scoped-traversal
implementation. Hierarchy operators `child_of`/`parent_of` deny. Schema
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
  "available_companies": [{"id": 1, "name": "Acme"}],
  "enabled_companies": [1], "default_company": 1,
  "models": {
    "res.partner": {
      "label": "Partner", "provenance": "manifest", "executable": false,
      "company_field": "company_id", "company_independent": false,
      "include_companyless": false,
      "fields": {
        "name": {"type": "char", "relation": "", "label": "Name", "provenance": "manifest"}
      }
    }
  },
  "method_manifest": ["search_read", "read"]
}
```

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

Shipped in-tree (implemented, not prose):

- MCP stdio adapter: `odoo agent mcp [--url URL]` — JSON-RPC 2.0 over
  stdio with `initialize` / `tools/list` / `tools/call` for the 11 typed
  broker tools only (search, read, count, aggregate, meta, companies,
  catalog, workspace.list/read/write/mkdir). The session token comes from
  `ODOO_BROKER_TOKEN` (env only, never logged or echoed). Codex stdio
  example: `codex mcp add odoo-broker -- odoo agent mcp
  --url http://127.0.0.1:8471` with the token env var set.
- OMP custom tool module: `tools/omp/odoo-broker.js` (CommonJS factory,
  11 typed tools, `fetch` POST to `ODOO_BROKER_URL` with `ODOO_BROKER_TOKEN`;
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
