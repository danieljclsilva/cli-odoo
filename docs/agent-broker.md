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
  --ops search,read,count,meta --workspace ~/.config/odoo-cli/agent-workspace

# Non-interactive (operators/tests): pass every choice as flags and the
# admin password on stdin only.
printf '%s' "$ADMIN_PW" | odoo agent setup --companies 1,2 ... --admin-password-stdin

# 3. Inspect and refresh bounded metadata (human only, deliberate server reads).
odoo agent companies [--live]
odoo agent snapshot            # rebuild snapshot for approved models only
odoo agent workspace           # show sealed workspace dir + bounded listing

# 4. Serve (unlocks profile, resolves keychain once, dials Odoo once).
odoo agent serve               # listens on 127.0.0.1:8471 only; refuses non-loopback --addr

# 5. Mint / inspect / revoke session tokens (over the 0600 unix admin socket).
odoo agent grant --ttl 30m
odoo agent status              # counts/expiry only, never tokens
odoo agent revoke <token-or-prefix>
```

Files (0600): `~/.config/odoo-cli/agent-profile.json` (sealed policy),
`~/.config/odoo-cli/agent-snapshot.json` (approved metadata). Sealed with
PBKDF2-SHA256 (600k) + AES-GCM from the standard library; a wrong password
fails closed with no partial data. Revocation stops new requests; stop the
daemon to end all model access. Never fall back to the unrestricted CLI for
model traffic.

Company scope: the broker ANDs `[[CompanyField,"in",Enabled]]` into every
domain **after** caller conditions and **overwrites** `allowed_company_ids`
/ `company_id`. The model cannot select companies. `read` by ID is converted
to a scoped `search_read` so company scoping always applies. Models without
a usable company field deny unless a human classified them
company-independent *and* the policy allows classified shared records.

## Model API (loopback TCP, bearer session token)

Typed JSON only — no generic `call`, no method/args/kwargs forwarding, no
`context` field (unknown JSON fields are rejected):

- `POST /rpc/search` `{model, domain, fields, order, limit, offset}` → `search_read`
- `POST /rpc/read` `{model, ids, fields}` → scoped `search_read` (never raw `read`)
- `POST /rpc/count` `{model, domain}` → `search_count`
- `POST /rpc/aggregate` `{model, domain, groupby, sum, avg, count, limit}` → `read_group`
- `GET /rpc/meta[?model=]` — sealed allowlist only; discoverable, never executable
- `POST /rpc/workspace/{list,read,write}` — only if the policy enables the
  workspace; confined to the sealed directory via `os.Root`
- `GET /healthz` — no auth, no data

Every request: bearer check → `policy.Authorize` → budgets → company scoping
→ `Execute` → row/byte caps → secret redaction. Denial happens before any
RPC. Responses are capped (`max-rows-per-call`, `max-response-bytes` trim
trailing rows rather than truncating) and sessions are budgeted
(`max-calls/rows-per-session`).

Group-by interval suffixes (`date_order:month`) and `field:sum`/`field:avg`
specifiers are validated (`[A-Za-z0-9_]+`) and stripped before the gate; the
underlying field must be allowlisted.

## Wiring a runtime to the broker

The human mints a token and places it into the agent's tool config; the
model endpoint is plain typed JSON-RPC POST (curl-consumable), so any
runtime that can POST HTTP with a bearer header can use it.

**Codex (verified with installed CLI):** `codex mcp add --help` supports
`--url <URL>` for a streamable HTTP MCP server plus `--bearer-token-env-var`.
This broker serves **plain JSON-RPC, not MCP**, so Codex consumes it through
a small MCP shim that forwards typed tools to the broker with the session
token in `Authorization: Bearer`. Keep the shim's tool list exactly the
typed endpoints above (no generic forwarder). Runtime allowlists
(`enabled_tools`, `features.shell_tool=false`, permission deny-read) are
defense in depth; enforcement was tested at the broker (denial before RPC),
not delegated to them.

**OMP v18.2.6 (verified with installed CLI):** `--help` shows
`--no-tools` / `--tools=<list>` (tool gating), `--extension`/`--hook`
(TypeScript custom-tool modules) and no MCP client flags — MCP consumption
is unverified in this version. The supported path is a custom tool module
(`~/.omp/agent/tools/`, `.omp/tools`, or an explicit path) whose `execute`
POSTs to the loopback broker with the session token; see the custom-tools
docs for the module contract. Restrict the session to the broker tools plus
only the built-ins the task needs (`--tools`), disable everything else
(`--no-tools` baseline + explicit `--tools` list, `--no-pty` unless the task
needs a shell), and never give the agent the workspace dir, profile paths,
admin password, or keychain access. Tool-surface control is not filesystem
isolation: verify no alternate tool, subagent, extension, or computer-use
path crosses the boundary before declaring the profile enforced.

## Live compatibility

Pure policy/parser/crypto/session/protocol/filesystem behavior is covered by
unit tests (`internal/agent/...`). Genuine Odoo company/search/aggregate
semantics were **not** verified against a live server in this change (no
disposable server was available); live ORM/addon/ACL behavior remains
unverified — see the handoff.
