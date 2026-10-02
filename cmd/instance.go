package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/KomoriNoKage/cli-odoo/internal/config"
	"github.com/KomoriNoKage/cli-odoo/internal/odoo"
	"github.com/KomoriNoKage/cli-odoo/internal/output"
)

func init() {
	RootCmd.AddCommand(newInstancesCmd())
	RootCmd.AddCommand(newLoginCmd())
	RootCmd.AddCommand(newStatusCmd())
}

// opsPackClient resolves the effective instance and opens an authenticated client.
func opsPackClient() (*odoo.Client, *config.Instance, error) {
	inst, err := config.Resolve(InstanceName())
	if err != nil {
		return nil, nil, err
	}
	c, err := odoo.New(inst)
	if err != nil {
		return nil, nil, err
	}
	return c, inst, nil
}

// opsPackFloat coerces XML-RPC numerics to float64.
func opsPackFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	default:
		return 0, false
	}
}

// opsPackInt coerces XML-RPC numerics to int64 (floats only when integral).
func opsPackInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		if n > 1<<63-1 {
			return 0, false
		}
		return int64(n), true
	case float64:
		if n == float64(int64(n)) {
			return int64(n), true
		}
		return 0, false
	case float32:
		f := float64(n)
		if f == float64(int64(f)) {
			return int64(f), true
		}
		return 0, false
	default:
		return 0, false
	}
}

// opsPackBool reports whether v is boolean true.
func opsPackBool(v any) bool {
	b, ok := v.(bool)
	return ok && b
}

// opsPackStr renders v as a string ("" for nil).
func opsPackStr(v any) string {
	switch s := v.(type) {
	case nil:
		return ""
	case string:
		return s
	default:
		return fmt.Sprintf("%v", v)
	}
}

// opsPackRows normalizes an Execute list result into []map[string]any,
// skipping rows of unexpected shape.
func opsPackRows(v any) []map[string]any {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// opsPackPairID extracts the id (and display name) from an Odoo
// many2one [id, name] pair, a scalar id, or returns ok=false for
// empty values (false/nil).
func opsPackPairID(v any) (id int64, name string, ok bool) {
	switch t := v.(type) {
	case nil:
		return 0, "", false
	case bool:
		return 0, "", false
	case []any:
		if len(t) == 0 {
			return 0, "", false
		}
		id, ok := opsPackInt(t[0])
		if !ok {
			return 0, "", false
		}
		if len(t) > 1 {
			name, _ = t[1].(string)
		}
		return id, name, true
	default:
		id, ok := opsPackInt(v)
		if !ok {
			return 0, "", false
		}
		return id, "", true
	}
}

// opsPackOr builds a prefix-OR domain from single conditions.
// Zero conditions yield an empty domain; one yields [cond].
// N conditions yield N-1 "|" operators followed by the conditions:
// ["|", "|", c0, c1, c2] for three. Verified against Odoo 17
// expression.py: right-nested operand lists are rejected as leaves.
func opsPackOr(conds []any) []any {
	switch len(conds) {
	case 0:
		return []any{}
	case 1:
		return []any{conds[0]}
	}
	out := make([]any, 0, 2*len(conds)-1)
	for range len(conds) - 1 {
		out = append(out, "|")
	}
	return append(out, conds...)
}

// opsPackIDsFromNameSearch extracts ids from a name_search result
// ([[id, display_name], ...]).
func opsPackIDsFromNameSearch(v any) []int64 {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	var ids []int64
	for _, item := range list {
		pair, ok := item.([]any)
		if !ok || len(pair) == 0 {
			continue
		}
		if id, ok := opsPackInt(pair[0]); ok {
			ids = append(ids, id)
		}
	}
	return ids
}

func newInstancesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "instances",
		Short: "List configured Odoo instances (credentials are never shown)",
		Run: func(cmd *cobra.Command, args []string) {
			all := config.List()
			names := make([]string, 0, len(all))
			for n := range all {
				names = append(names, n)
			}
			sort.Strings(names)
			rows := make([]map[string]any, 0, len(names))
			for _, n := range names {
				inst := all[n]
				rows = append(rows, map[string]any{
					"name":       n,
					"url":        inst.URL,
					"db":         inst.DB,
					"username":   inst.Username,
					"transport":  inst.Transport,
					"readonly":   inst.ReadOnly,
					"is_default": inst.IsDefault || n == config.DefaultName(),
				})
			}
			output.Ok("list_instances", rows, len(rows))
		},
	}
}

func newLoginCmd() *cobra.Command {
	var url, db, username, password, apiKey, transport, target string
	var passwordStdin, apiKeyStdin bool
	var timeout int
	var verifySSL, writable bool
	c := &cobra.Command{
		Use:   "login",
		Short: "Save Odoo connection settings to the config file (mode 0600)",
		Long: `Save connection settings to the config file (default ~/.config/odoo-cli/config.yaml, or --config path).

	The file keeps the odoo.example.yaml shape and is written with mode 0600.
	The secret is never printed. Verify with: odoo status

	Provide the secret via exactly one of --password (deprecated), --password-stdin,
	--api-key, --api-key-stdin, or the ODOO_PASSWORD / ODOO_API_KEY environment.
	With none of those, the interactive prompt reads without echo.

	New instances are read-only by default (default-deny): writes are refused
	unless the instance sets readonly:false. Pass --writable to save the
	instance with readonly:false. Server-side, use a least-privilege Odoo user
	(access rights / record rules) so the CLI gate is defense in depth, not
	the only boundary.`,
		Run: func(cmd *cobra.Command, args []string) {
			const tool = "login"
			if strings.TrimSpace(url) == "" {
				output.Fail(tool, fmt.Errorf("missing --url"))
				return
			}
			if strings.TrimSpace(db) == "" {
				output.Fail(tool, fmt.Errorf("missing --db"))
				return
			}
			if strings.TrimSpace(username) == "" {
				output.Fail(tool, fmt.Errorf("missing --username"))
				return
			}
			nSet := 0
			if password != "" {
				nSet++
			}
			if passwordStdin {
				nSet++
			}
			if strings.TrimSpace(apiKey) != "" {
				nSet++
			}
			if apiKeyStdin {
				nSet++
			}
			if nSet > 1 {
				output.Fail(tool, fmt.Errorf("pass at most one of --password, --password-stdin, --api-key, --api-key-stdin"))
				return
			}
			secret := password
			if passwordStdin {
				b, err := io.ReadAll(os.Stdin)
				if err != nil {
					output.Fail(tool, fmt.Errorf("reading password from stdin: %w", err))
					return
				}
				secret = strings.TrimSpace(string(b))
			}
			if apiKeyStdin {
				b, err := io.ReadAll(os.Stdin)
				if err != nil {
					output.Fail(tool, fmt.Errorf("reading API key from stdin: %w", err))
					return
				}
				apiKey = strings.TrimSpace(string(b))
			}
			if secret == "" && strings.TrimSpace(apiKey) == "" {
				if env := strings.TrimSpace(os.Getenv("ODOO_PASSWORD")); env != "" {
					secret = env
				} else if env := strings.TrimSpace(os.Getenv("ODOO_API_KEY")); env != "" {
					apiKey = env
				} else {
					s, err := readSecretNoEcho("Password: ")
					if err != nil {
						output.Fail(tool, fmt.Errorf("reading password: %w", err))
						return
					}
					secret = s
				}
			}
			if secret == "" && strings.TrimSpace(apiKey) == "" {
				output.Fail(tool, fmt.Errorf("no secret provided (use --password-stdin, --api-key, --api-key-stdin, or ODOO_PASSWORD/ODOO_API_KEY)"))
				return
			}
			tr := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(transport)), "-", "")
			switch tr {
			case "", "xmlrpc":
				tr = "xmlrpc"
			case "json2":
				tr = "json2"
			default:
				output.Fail(tool, fmt.Errorf("invalid --transport %q (want xmlrpc|json2)", transport))
				return
			}
			path := cfgFile
			if strings.TrimSpace(path) == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					output.Fail(tool, err)
					return
				}
				path = filepath.Join(home, ".config", "odoo-cli", "config.yaml")
			}
			entry := map[string]any{
				"url":        strings.TrimSpace(url),
				"db":         strings.TrimSpace(db),
				"username":   strings.TrimSpace(username),
				"transport":  tr,
				"timeout":    timeout,
				"verify_ssl": verifySSL,
				"readonly":   !writable,
			}
			if secret != "" {
				entry["password"] = secret
			} else {
				entry["api_key"] = strings.TrimSpace(apiKey)
			}
			instName, err := opsPackLoginSave(path, strings.TrimSpace(target), entry)
			if err != nil {
				output.Fail(tool, err)
				return
			}
			output.Ok(tool, map[string]any{
				"path":      path,
				"instance":  instName,
				"url":       entry["url"],
				"db":        entry["db"],
				"username":  entry["username"],
				"transport": tr,
				"readonly":  !writable,
			}, 1)
		},
	}
	c.Flags().StringVar(&url, "url", "", "Odoo server URL (required)")
	c.Flags().StringVar(&db, "db", "", "database name (required)")
	c.Flags().StringVar(&username, "username", "", "login username (required)")
	c.Flags().StringVar(&password, "password", "", "password (deprecated: use --password-stdin or ODOO_PASSWORD env)")
	c.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read password from stdin")
	c.Flags().StringVar(&apiKey, "api-key", "", "API key instead of password")
	c.Flags().BoolVar(&apiKeyStdin, "api-key-stdin", false, "read API key from stdin")
	_ = c.Flags().MarkDeprecated("password", "use --password-stdin or ODOO_PASSWORD env")
	c.Flags().StringVar(&transport, "transport", "xmlrpc", "transport: xmlrpc (Odoo 17 default) | json2 (Odoo 19+ opt-in)")
	c.Flags().StringVar(&target, "name", "", "save as a named instance (default: single-instance file)")
	c.Flags().IntVar(&timeout, "timeout", 30, "request timeout in seconds")
	c.Flags().BoolVar(&verifySSL, "verify-ssl", true, "verify TLS certificates")
	c.Flags().BoolVar(&writable, "writable", false, "save with readonly:false (default saves readonly:true)")
	return c
}

// readSecretNoEcho prompts on stderr and reads a secret without echo when
// stdin is a terminal; otherwise it falls back to a line read so piped
// input keeps working.
func readSecretNoEcho(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// opsPackLoginSave merges entry into the YAML config at path and writes it
// with mode 0600, preserving the odoo.example.yaml shape. It returns the
// effective instance name.
func opsPackLoginSave(path, target string, entry map[string]any) (string, error) {
	doc := map[string]any{}
	if b, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(b, &doc); err != nil {
			return "", fmt.Errorf("parsing existing config %s: %w", path, err)
		}
		if doc == nil {
			doc = map[string]any{}
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("reading existing config %s: %w", path, err)
	}
	connKeys := []string{"url", "db", "username", "password", "api_key", "transport", "timeout", "verify_ssl", "verify", "lang", "locale", "readonly", "audit_log"}
	instances, _ := doc["instances"].(map[string]any)
	if target != "" || instances != nil {
		if instances == nil {
			instances = map[string]any{}
		}
		name := target
		if name == "" {
			if d, _ := doc["default_instance"].(string); d != "" {
				name = d
			} else {
				return "", fmt.Errorf("config file has named instances: pass --name to choose which one to update")
			}
		}
		// Migrate a legacy single-instance body under "default" so stale
		// flat keys do not shadow the named layout.
		if _, ok := instances["default"]; !ok {
			migrated := map[string]any{}
			moved := false
			for _, k := range connKeys {
				if v, ok := doc[k]; ok {
					migrated[k] = v
					moved = true
				}
			}
			if moved {
				instances["default"] = migrated
			}
		}
		for _, k := range connKeys {
			delete(doc, k)
		}
		instances[name] = entry
		doc["instances"] = instances
		if d, _ := doc["default_instance"].(string); d == "" {
			doc["default_instance"] = name
		}
		if err := opsPackWriteConfig(path, doc); err != nil {
			return "", err
		}
		return name, nil
	}
	for _, k := range connKeys {
		delete(doc, k)
	}
	for k, v := range entry {
		doc[k] = v
	}
	delete(doc, "instances")
	delete(doc, "default_instance")
	if err := opsPackWriteConfig(path, doc); err != nil {
		return "", err
	}
	return "default", nil
}

// opsPackWriteConfig writes doc as YAML, enforcing mode 0600 for secrets.
func opsPackWriteConfig(path string, doc map[string]any) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("creating config dir: %w", err)
		}
	}
	b, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("writing config %s: %w", path, err)
	}
	// WriteFile keeps existing permissions; enforce 0600 for secrets.
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("securing config %s: %w", path, err)
	}
	return nil
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check authentication and report the server version",
		Run: func(cmd *cobra.Command, args []string) {
			const tool = "server_status"
			client, inst, err := opsPackClient()
			if err != nil {
				output.Fail(tool, err)
				return
			}
			ver, err := client.ServerVersion()
			if err != nil {
				output.Fail(tool, err)
				return
			}
			name := InstanceName()
			if name == "" {
				name = config.DefaultName()
			}
			if name == "" {
				name = inst.Name
			}
			res := map[string]any{
				"instance":       name,
				"url":            inst.URL,
				"db":             inst.DB,
				"username":       inst.Username,
				"transport":      inst.Transport,
				"authenticated":  true,
				"server_version": ver,
			}
			if user, uerr := client.UserContext(); uerr != nil {
				res["user_error"] = uerr.Error()
			} else {
				res["user"] = user
			}
			output.Ok(tool, res, 1)
		},
	}
}
