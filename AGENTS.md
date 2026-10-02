# AGENTS.md — working notes for AI agents

`odoo` is a self-contained Go CLI for Odoo ERP (port of the 41-tool
[erpipe-org/mcp-odoo](https://github.com/erpipe-org/mcp-odoo) MCP server).
Odoo 17 compatible (XML-RPC); JSON-2 opt-in for 19+.

## Repo map

```text
main.go                  entrypoint: executes cmd.RootCmd
cmd/root.go              RootCmd + global flags (--config/--format/--instance/--verbose) + InstanceName()
cmd/version.go           `version` command (ldflags: -X <module>/cmd.Version=…)
cmd/<slice>.go           one file per command slice (search, read, schema, call, …)
internal/config/         Instance/Settings, Load(), Resolve(name), ResolveNoAuth(name), List(), DefaultName(), LoggedIn()
internal/output/         Format (json|table|yaml), Print(), Ok(tool,result,count), Fail(), Fatal()
internal/odoo/           Client, New(*config.Instance), Execute() [read-only allowlist], ServerVersion(),
                         UserContext(), IsReadOnlyMethod(), ParseDomain/ParseCSV/ParseJSONObj helpers
odoo.example.yaml        documented single + multi-instance config template
Makefile / .goreleaser.yml / .github/workflows/ci.yml   build & release plumbing
```

- Module path: `github.com/danieljclsilva/cli-odoo`. Go 1.24.
- Deps: Cobra + Viper (+ `kolo/xmlrpc`, `yaml.v3`).

## Command registration pattern

Register new commands by appending to `RootCmd` in your own file's `init()`:

```go
package cmd

import "github.com/spf13/cobra"

func init() {
    RootCmd.AddCommand(newSearchCmd())
}

func newSearchCmd() *cobra.Command {
    c := &cobra.Command{Use: "search <model>", Short: "…", RunE: …}
    c.Flags().String("domain", "", "JSON array string")
    …
    return c
}
```

Rules:

- Every command emits the stable envelope via `output.Ok` / `output.Fail`.
- Inherit global flags from root (`--instance`, `--format`); never redeclare them.
- `--domain` takes a JSON array string; `--fields` takes CSV;
  `--limit/--offset/--order` for reads.
- Read-only: no command sends a write. `call` accepts allowlisted read methods
  only. There are no `--yes`/`--dry-run` flags and no safety package.

## Contracts

- **Envelope/output** (`internal/output`): `Ok(tool, result, count)` on success,
  `Fail(tool, err)` on failure, `Fatal(err)` before any output. Default format
  comes from root's `--format` via `SetDefault`.
- **Config** (`internal/config`): `config.Load(cfgFile)` runs in root's
  `PersistentPreRunE`. Resolve with `Resolve(cmd.InstanceName())` — flag >
  `ODOO_INSTANCE` > default. Env-only mode works (no file required).
  Secrets live ONLY in the OS keychain (service `cli-odoo`); `Resolve`
  attaches the keychain secret, `ResolveNoAuth` skips it (login/logout only).
  File/env secret keys (`password:`, `api_key:`, `ODOO_PASSWORD`,
  `ODOO_API_KEY`) do not exist and are ignored.
- **Odoo client** (`internal/odoo`): XML-RPC default, JSON-2 opt-in for 19+.
  `Execute` refuses any non-allowlisted method before any RPC — there is no
  write path. Use only read-only Odoo 17-safe ORM methods (`search_read`,
  `read`, `search_count`, `read_group`, `fields_get`, `name_search`,
  `check_access_rights`). Never use 19+-only APIs
  (e.g. `formatted_read_group`) without an XML-RPC fallback. Auth via
  `/xmlrpc/2/common` `authenticate`.

## File ownership

| Owner | Files |
|---|---|
| Scaffold (scaffold/docs) | `.gitignore`, `README.md`, `AGENTS.md`, `Makefile`, `.goreleaser.yml`, `.github/workflows/ci.yml`, `odoo.example.yaml`, `LICENSE` |
| Core client | `internal/odoo/*` |
| Read pack | `cmd/search.go`, `cmd/read.go`, `cmd/schema.go` |
| Ops pack | `cmd/diag.go`, `cmd/acct.go`, `cmd/instance.go`, `cmd/call.go`, `cmd/profile.go`, `cmd/attach.go` (get only) |
| Shared (read-only) | `main.go`, `cmd/root.go`, `cmd/version.go`, `internal/config/*`, `internal/output/*`, `go.mod` |

Never touch another slice's files. Read shared contracts, do not edit them.
Coordinate via hub before editing anything shared.

## Rules

- **No test mocks for Odoo behavior.** Never mock the Odoo client/server in
  tests to prove behavior — verify against real `read_group`/`search_read`
  semantics or a throwaway script, not a fake. (Parent validates at end;
  never run `go build`/`test`/`lint`/`gofmt` inside tasks.)
- Clean cutover: migrate every caller, delete obsolete code, no shims.
- Second convention beside an existing one is prohibited — reuse patterns.

## Verification

Project-wide validation is the parent's job, run once after all slices land:
`go build ./...` plus `GOOS=` cross-compiles for darwin/windows/linux
(`make cross`). Never run formatters, linters, or project-wide builds/test
suites inside slice tasks — siblings edit concurrently.
