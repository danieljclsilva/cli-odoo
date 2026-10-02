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
for Odoo 19+ only and is never required for Odoo 17 paths. Only Odoo
17-safe ORM methods are used (`search_read`, `read`, `search_count`,
`read_group`, `fields_get`, `name_search`, `check_access_rights`,
`message_post`, `ir.attachment` `datas`) — never 19+-only APIs such as
`formatted_read_group` without an XML-RPC fallback.

## Install

```bash
# Homebrew (once tapped / released)
brew install KomoriNoKage/tap/cli-odoo

# Or download a release binary from GitHub Releases and put it on PATH.
# Or build from source (Go 1.24+):
go build -o odoo .
```

## Quickstart

No config file needed — env vars are enough:

```bash
export ODOO_URL=https://my-odoo.example.com
export ODOO_DB=mydb
export ODOO_USERNAME=admin
export ODOO_PASSWORD='secret-or-api-key'

# Log in / verify the connection (authenticates over /xmlrpc/2/common):
odoo login

# Find recent customers and show a human-readable table:
odoo search res.partner \
  --domain '[["customer_rank",">",0]]' \
  --fields name,email,phone \
  --limit 10 --order "create_date desc" \
  --format table
```

Prefer a file? Copy `odoo.example.yaml` to
`~/.config/odoo-cli/config.yaml` (or pass `--config`) — it documents both
the single-instance layout and the multi-instance layout (`instances:`
map + `default_instance:`). Env vars always win over file values.

## Command map

Every command emits a stable envelope (`{success, tool, result, count}`)
via `--format json` (default); `--format table|yaml` renders for humans.

| CLI command | What it does | mcp-odoo equivalent |
|---|---|---|
| `odoo login` | Authenticate, print server version + uid | `health_check` / auth |
| `odoo search <model>` | `search_read` with `--domain` (JSON array), `--fields` (CSV), `--limit/--offset/--order` | `search_records` |
| `odoo read <model> <id…>` | `read` records by ID with `--fields` | `read_record` |
| `odoo schema <model>` | `fields_get` field listing | `inspect_model` / `fields_get` |
| `odoo write create/update/delete <model>` | Gated mutations (see below) | approved `create`/`write`/`unlink` |
| `odoo chatter post <model> <id>` | Post to `mail.thread` chatter | `chatter_post` |
| `odoo attach <model> <id> <file>` | Upload `ir.attachment` (`datas`) | attachment tools |
| `odoo diag <model>` | Diagnose a call / access rights | `diagnose_odoo_call`, `diagnose_access` |
| `odoo acct …` | Receivable/payable aging, accounting health (`read_group`) | `receivable_payable_aging`, `accounting_health_summary` |
| `odoo instance list/use` | Named-instance discovery and switching | `list_instances` |
| `odoo call <model> <method>` | Low-level `execute_kw` escape hatch | `execute_custom_method` |
| `odoo profile …` | Saved connection/profile helpers | client config helpers |

Global flags (inherited from root): `--instance` (named instance),
`--format json|table|yaml`, `--config`, `--verbose`.

## Output formats

```bash
odoo search res.partner --limit 5                    # JSON envelope (default)
odoo search res.partner --limit 5 --format table     # human table
odoo search res.partner --limit 5 --format yaml      # YAML
```

JSON is the agent contract: parse `result` / `count`, check `success`.
Table/YAML are for humans and never change the JSON shape.

## Write gate

Writes never run silently. Every mutating command follows
preview → confirm → execute:

```bash
# 1. Preview (never mutates, always allowed):
odoo write update res.partner 42 --values '{"phone":"+81-90-0000-0000"}' --dry-run

# 2. Execute (requires BOTH the flag AND the env gate):
export ODOO_WRITES_ENABLED=1
odoo write update res.partner 42 --values '{"phone":"+81-90-0000-0000"}' --yes
```

Rules:

- `--dry-run` previews the exact payload and bypasses all gates.
- `--yes` confirms AND requires `ODOO_WRITES_ENABLED=1` in the environment.
- Without both, the command refuses with a non-zero exit and a failure envelope.
- Same gate applies to `chatter post`, `attach`, and destructive `acct` actions.

## Multi-instance

```yaml
# ~/.config/odoo-cli/config.yaml
instances:
  prod:    {url: https://odoo.example.com, db: prod, username: admin, password: x}
  staging: {url: https://staging.example.com, db: staging, username: admin, api_key: y}
default_instance: prod
```

```bash
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
