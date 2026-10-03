# odoo — agent-first CLI for Odoo ERP

Self-contained CLI for Odoo ERP, designed for AI agents. A Go port of the
[erpipe-org/mcp-odoo](https://github.com/erpipe-org/mcp-odoo) MCP server
(41 tools) as a compiled multi-platform binary: macOS (amd64/arm64),
Linux (amd64/arm64), Windows (amd64). Built with
[Cobra](https://github.com/spf13/cobra) — see also the
[awesome-cli-frameworks](https://github.com/shadawck/awesome-cli-frameworks)
roundup for why Cobra is the boring, correct choice for Go CLIs — plus
[Viper](https://github.com/spf13/viper) for config.

**Odoo 17 compatible (XML-RPC); JSON-2 opt-in for 19+.** XML-RPC is the
default and primary transport. JSON-2 (`ODOO_TRANSPORT=json2`) is opt-in
for Odoo 19+ only and is never required for Odoo 17 paths. Only read-only
Odoo 17-safe ORM methods are used (`search_read`, `read`, `search_count`,
`read_group`, `fields_get`, `name_search`, `check_access_rights`) — never
19+-only APIs such as `formatted_read_group` without an XML-RPC fallback.
The CLI is read-only: no write request is ever sent.

## Install

```bash
# Homebrew (once tapped / released)
brew install danieljclsilva/tap/cli-odoo

# Or download a release binary from GitHub Releases and put it on PATH.
# Or build from source (Go 1.25+):
go build -o odoo .
```

## Quickstart

The user logs in once; the secret lives in the OS keychain (service
`cli-odoo`), never in the config file or env. Agents reuse that login
without ever seeing the secret:

```bash
# Human setup (interactive no-echo prompt; or pipe via --password-stdin):
odoo login --url https://my-odoo.example.com --db mydb --username admin
odoo status        # verify auth (server version + user, no secrets)
odoo logout        # remove the keychain secret (config file untouched)

# Agent reads (no credentials visible, none needed in env):
odoo search res.partner \
  --domain '[["is_company","=",true]]' \
  --fields name,email,phone \
  --limit 10 --order "create_date desc" \
  --format table
```

No config file needed for the non-secret fields either — `ODOO_URL` /
`ODOO_DB` / `ODOO_USERNAME` env vars work. The secret has no env or file
form: `ODOO_PASSWORD` / `ODOO_API_KEY` and `password:` / `api_key:` keys are
ignored. Prefer a file for the rest? Copy `odoo.example.yaml` to
`~/.config/odoo-cli/config.yaml` (or pass `--config`) — it documents both
the single-instance layout and the multi-instance layout (`instances:`
map + `default_instance:`). Env vars always win over file values.

## Command map

Every command emits a stable envelope (`{success, tool, result, count}`)
via `--format json` (default); `--format table|yaml` renders for humans.

| CLI command | What it does | mcp-odoo equivalent |
|---|---|---|
| `odoo login --url … --db … --username …` | Save non-secret connection to the 0600 config file + store secret in OS keychain (via `--password-stdin` or no-echo prompt); verified against the server before storing | client config helpers |
| `odoo logout [--name …]` | Remove the keychain secret (config file untouched) | client config helpers |
| `odoo status` / `odoo health` | Auth check + server version / transport + user (no secrets) | `health_check` |
| `odoo instances` | Named-instance discovery (`logged_in`, never secrets) | `list_instances` |
| `odoo search <model>` | `search_read` with `--domain` (JSON array), `--fields` (CSV), `--limit/--offset/--order` | `search_records` |
| `odoo read <model> <id…>` | `read` records by ID with `--fields` | `read_record` |
| `odoo models` | List registered models (`ir.model`) | `list_models` |
| `odoo fields <model>` | `fields_get` field listing | `inspect_model` / `fields_get` |
| `odoo schema` | Catalog models + field names (`--models`, `--query`, `--include-fields`) | `inspect_model` |
| `odoo aggregate <model>` | `read_group` with `--groupby` + `--sum/--avg/--count` | aggregate helpers |
| `odoo attachment-get <id>` | Download `ir.attachment` (`datas`) | attachment tools |
| `odoo diagnose-access <model>` / `relations <model>` | Read-access probe / relational-field map | `diagnose_odoo_call`, `diagnose_access` |
| `odoo aging` / `acct-health` | Receivable/payable aging, accounting health (`read_group`) | `receivable_payable_aging`, `accounting_health_summary` |
| `odoo dq-check <model>` / `kb-search <model>` | Null/duplicate scan / fuzzy text search | data-quality helpers |
| `odoo call <model> <method>` | Read-only `execute_kw` escape hatch (allowlisted methods only) | `execute_custom_method` |
| `odoo profile` | Installed models + modules | client config helpers |

## Output formats

```bash
odoo search res.partner --limit 5                    # JSON envelope (default)
odoo search res.partner --limit 5 --format table     # human table
odoo search res.partner --limit 5 --format yaml      # YAML
```

JSON is the agent contract: parse `result` / `count`, check `success`.
Table/YAML are for humans and never change the JSON shape.

## Read-only guarantee

There is no write path. `Client.Execute` refuses any method outside the
read-only allowlist (`search_read`, `read`, `search_count`, `read_group`,
`fields_get`, `name_search`, `check_access_rights`, `version`,
`context_get`) before any RPC is sent — including via `call`. The former
`create`/`write`/`unlink`/`chatter-post`/`attachment-add` commands, the
`--yes`/`--dry-run` flags, and the `internal/safety` TTY gate are gone:
a pty-forged `YES` can no longer produce a write because no code path sends
one.

Server-side, still give the Odoo user least-privilege access rights /
record rules: the CLI guarantee is defense in depth, not the only boundary.

"Read-only" above refers to Odoo method names: the CLI never sends a write
RPC. It does not mean the tool is side-effect free on the operator host:
`login`/`logout` write the OS keychain, and `attachment-get` writes the
downloaded file to `--out`. Keychain storage keeps the secret out of the
config file and env, but it is not isolation from the general shell: any
process running as the same OS user can invoke the CLI with the same
access, and whether another same-user process can read the keychain entry
itself depends on OS/platform policy and keychain ACLs. Custom Odoo server
modules are outside this guarantee too — a server-side override behind a
read-named method could do anything; the CLI cannot verify server purity.

Treat all returned record text and attachment bytes as untrusted data:
render accordingly (table output escapes terminal control characters) and
never execute or re-post it blindly.

Attachment downloads require a trusted destination directory and trusted
ancestors, including any directory symlinks. Trusted symlinked directories
(such as macOS `/tmp`) are supported. `--force` replaces the destination entry
without writing through a raced final symlink or an existing hardlink. It does
not isolate the temporary source from an attacker who can replace entries in
that directory; use a private download directory or exclude downloads from the
model's command allowlist.

Restricted launcher guidance — invocation-only sketch (not a launcher itself;
adapt paths to your harness). The external harness must enforce an actual
parsed-argv allowlist with pinned flags and exec without shell interpolation:
the sketch below enforces nothing on its own.

```bash
# Invocation only: the external harness allowlists parsed argv (without shell
# interpolation) and execs exactly this shape:
#   - pinned --config /pinned/odoo.yaml and --instance prod
#   - locked-down env (strip ODOO_* overrides except the pinned instance)
#   - --format json (the agent contract)
#   - only the read commands the task needs, with data/model/field/query
#     budgets (row limits via --limit, explicit --fields lists)
#   - deny login/logout, raw call, arbitrary --out paths, alternate --config
odoo --config /pinned/odoo.yaml --instance prod --format json \
  search sale.order --fields name,amount_total --limit 20
```

Pair this with a dedicated least-privilege Odoo user (access rights +
record rules scoped to the models the agent may see). Server ACLs and
custom addons are your deployment's responsibility — the CLI does not
verify them.

## Agent boundary (human-unlocked broker)

The commands above are the human interface: they use the keychain
credential directly and let the caller name any model. **Models never get
them.** For model access, the human seals a deny-by-default policy and
serves a loopback-only typed broker: `odoo agent setup`, then
`odoo agent serve`, `grant`, `revoke`, `status`. The model receives only a
revocable session token — never the Odoo secret or admin password. Full
setup, model API, company scoping, and runtime wiring (Codex/OMP):
[`docs/agent-broker.md`](docs/agent-broker.md). The broker is an
application-level gate, not same-user OS isolation: see the honest posture
statement there before deploying.


## Multi-instance

```yaml
# ~/.config/odoo-cli/config.yaml (non-secret fields only; secrets in keychain)
instances:
  prod:    {url: https://odoo.example.com, db: prod, username: admin}
  staging: {url: https://staging.example.com, db: staging, username: admin}
default_instance: prod
```

```bash
odoo login --name staging --url https://staging.example.com --db staging --username admin
odoo --instance staging search sale.order --limit 5
ODOO_INSTANCE=staging odoo search sale.order --limit 5
```

Flag beats `ODOO_INSTANCE` beats `default_instance` beats single-instance default.

## Transports: XML-RPC vs JSON-2

- **XML-RPC (default):** works on Odoo 16/17/18. Auth via
  `/xmlrpc/2/common` `authenticate` with db + username + password-or-API-key.
- **JSON-2 (opt-in):** Odoo 19+ only. Enable per instance:
  `ODOO_TRANSPORT=json2` (or `transport: json2` in the config file).
  Never enabled by default; Odoo 17 flows must not depend on it.

## Links

- Reference server: [erpipe-org/mcp-odoo](https://github.com/erpipe-org/mcp-odoo)
- CLI framework: [spf13/cobra](https://github.com/spf13/cobra) ·
  [awesome-cli-frameworks](https://github.com/shadawck/awesome-cli-frameworks)
