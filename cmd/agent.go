// Command agent is the human-side daemon boundary: serve/grant/revoke/status.
//
//   - `agent serve` (human, TTY): opens the sealed profile with the admin
//     password (prompted, never args/env), resolves the Odoo secret from
//     the OS keychain once, dials Odoo once, and serves the model listener
//     (loopback TCP) plus the admin mux (0600 unix socket).
//   - `agent grant/revoke/status` talk to a RUNNING daemon over the admin
//     unix socket (POST-only) derived from --addr (or --socket): no keychain,
//     no password, no tokens on disk. The daemon never exposes these on TCP.
//
// Same-user posture (honest): the loopback listener and the 0600 admin
// socket assume a non-hostile local user. Any local process as the same
// user (or root) can reach both; this package claims no same-user process
// isolation. Deployment docs (manager-owned) carry the host-control
// requirements.
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/danieljclsilva/cli-odoo/internal/agent/broker"
	"github.com/danieljclsilva/cli-odoo/internal/agent/lock"
	"github.com/danieljclsilva/cli-odoo/internal/agent/mcpadapter"
	"github.com/danieljclsilva/cli-odoo/internal/agent/policy"
	"github.com/danieljclsilva/cli-odoo/internal/agent/snapshot"
	"github.com/danieljclsilva/cli-odoo/internal/config"
	"github.com/danieljclsilva/cli-odoo/internal/output"
)

// agentParent finds or creates the shared "agent" parent: whichever of
// cmd/agent.go or cmd/agentsetup.go init runs second attaches to the
// first's parent instead of registering a duplicate.
func agentParent() *cobra.Command {
	for _, c := range RootCmd.Commands() {
		if c.Name() == "agent" {
			return c
		}
	}
	p := &cobra.Command{
		Use:   "agent",
		Short: "Human-unlocked agent boundary daemon (model API broker)",
	}
	RootCmd.AddCommand(p)
	return p
}

// loadServingStack opens profilePath with the admin password, decodes the
// sealed policy JSON, and loads the snapshot it points at. It resolves
// nothing and dials nothing: broker.Serve does that on the human machine.
func loadServingStack(profilePath, adminPassword string) (*policy.Policy, *config.Instance, snapshot.Snapshot, error) {
	raw, err := os.ReadFile(profilePath)
	if err != nil {
		return nil, nil, snapshot.Snapshot{}, fmt.Errorf("reading profile: %w", err)
	}
	var prof lock.Profile
	if err := json.Unmarshal(raw, &prof); err != nil {
		return nil, nil, snapshot.Snapshot{}, fmt.Errorf("decoding profile: %w", err)
	}
	opened, err := prof.Open(adminPassword)
	if err != nil {
		return nil, nil, snapshot.Snapshot{}, err
	}
	var pol policy.Policy
	dec := json.NewDecoder(bytes.NewReader(opened))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pol); err != nil {
		return nil, nil, snapshot.Snapshot{}, fmt.Errorf("decoding sealed policy: %w", err)
	}
	if pol.Version != 1 {
		return nil, nil, snapshot.Snapshot{}, fmt.Errorf("unsupported sealed policy version %d", pol.Version)
	}
	snapPath := pol.SnapshotPath
	if strings.TrimSpace(snapPath) == "" {
		snapPath = DefaultAgentSnapshotPath()
	}
	snap, err := snapshot.Load(snapPath)
	if err != nil {
		return nil, nil, snapshot.Snapshot{}, err
	}
	inst, err := config.ResolveNoAuth(pol.Instance)
	if err != nil {
		return nil, nil, snapshot.Snapshot{}, err
	}
	out := *inst
	return &pol, &out, snap, nil
}

// readAdminPassword unifies the two password sources: --admin-password-stdin
// reads stdin; otherwise an interactive TTY prompt. Passwords never come
// from args or env.
func readAdminPassword(stdinFlag bool) (string, error) {
	if stdinFlag {
		return lock.ReadAdminPasswordStdin()
	}
	return lock.PromptAdminPassword("Admin password: ")
}

func newAgentServeCmd() *cobra.Command {
	var profilePath, addr, socketPath string
	var stdinFlag bool
	c := &cobra.Command{
		Use:   "serve",
		Short: "Unlock the profile and serve the model listener (human only)",
		Run: func(cmd *cobra.Command, _ []string) {
			const tool = "agent_serve"
			if profilePath == "" {
				profilePath = DefaultAgentProfilePath()
			}
			pw, err := readAdminPassword(stdinFlag)
			if err != nil {
				output.Fail(tool, err)
			}
			pol, inst, snap, err := loadServingStack(profilePath, pw)
			if err != nil {
				output.Fail(tool, err)
			}
			b, err := broker.New(pol, inst, snap)
			if err != nil {
				output.Fail(tool, err)
			}
			if socketPath != "" {
				b.SetAdminSocket(socketPath)
			}
			fmt.Fprintf(os.Stderr, "serving model API on %s\n", addr)
			if err := b.Serve(addr); err != nil {
				output.Fail(tool, err)
			}
		},
	}
	c.Flags().StringVar(&profilePath, "profile", "", "sealed profile path (default "+DefaultAgentProfilePath()+")")
	c.Flags().StringVar(&addr, "addr", "127.0.0.1:8471", "loopback bind address (127.0.0.1, ::1, or localhost only)")
	c.Flags().StringVar(&socketPath, "socket", "", "admin unix-socket path (default derived from --addr)")
	c.Flags().BoolVar(&stdinFlag, "admin-password-stdin", false, "read admin password from stdin (never args/env)")
	return c
}

// adminClient dials the daemon's admin unix socket.
func adminClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}
}

// adminPost sends one POST to the admin socket and decodes the envelope.
func adminPost(socketPath, path string, body any) (map[string]any, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader([]byte("{}"))
	}
	req, err := http.NewRequest(http.MethodPost, "http://admin"+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := adminClient(socketPath).Do(req)
	if err != nil {
		return nil, fmt.Errorf("daemon not reachable on %s: %w", socketPath, err)
	}
	defer res.Body.Close()
	var env struct {
		Success bool           `json:"success"`
		Error   string         `json:"error"`
		Result  map[string]any `json:"result"`
		Count   int            `json:"count"`
	}
	if err := json.NewDecoder(res.Body).Decode(&env); err != nil {
		return nil, fmt.Errorf("decoding daemon response: %w", err)
	}
	if !env.Success {
		return nil, fmt.Errorf("%s", env.Error)
	}
	return env.Result, nil
}

// adminSocketFor resolves --socket or the derived default for --addr.
func adminSocketFor(addr, socketPath string) string {
	if socketPath != "" {
		return socketPath
	}
	return broker.AdminSocketPath(addr)
}

func newAgentGrantCmd() *cobra.Command {
	var addr, socketPath string
	var ttl string
	c := &cobra.Command{
		Use:   "grant",
		Short: "Mint a session token on the running daemon (human only)",
		Run: func(cmd *cobra.Command, _ []string) {
			const tool = "agent_grant"
			d, err := time.ParseDuration(ttl)
			if err != nil || d <= 0 {
				output.Fail(tool, fmt.Errorf("invalid --ttl %q: want positive duration like 30m", ttl))
			}
			res, err := adminPost(adminSocketFor(addr, socketPath), "/admin/grant",
				map[string]any{"ttl_seconds": int64(d / time.Second)})
			if err != nil {
				output.Fail(tool, err)
			}
			tok, _ := res["token"].(string)
			output.Ok(tool, map[string]any{"token": tok, "ttl": ttl}, 1)
		},
	}
	c.Flags().StringVar(&addr, "addr", "127.0.0.1:8471", "daemon model listener address (derives admin socket)")
	c.Flags().StringVar(&socketPath, "socket", "", "admin unix-socket path (overrides derived)")
	c.Flags().StringVar(&ttl, "ttl", "30m", "session lifetime (Go duration, e.g. 30m, 2h)")
	return c
}

func newAgentRevokeCmd() *cobra.Command {
	var addr, socketPath string
	c := &cobra.Command{
		Use:   "revoke <token-or-prefix>",
		Short: "Revoke a session token on the running daemon (human only)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			const tool = "agent_revoke"
			target := strings.TrimSpace(args[0])
			if target == "" {
				output.Fail(tool, fmt.Errorf("token or prefix is required"))
			}
			// The daemon resolves full tokens and unambiguous prefixes
			// identically; always send prefix and let it decide.
			body := map[string]any{"prefix": target}
			if _, err := adminPost(adminSocketFor(addr, socketPath), "/admin/revoke", body); err != nil {
				output.Fail(tool, err)
			}
			output.Ok(tool, map[string]any{"revoked": true}, 1)
		},
	}
	c.Flags().StringVar(&addr, "addr", "127.0.0.1:8471", "daemon model listener address (derives admin socket)")
	c.Flags().StringVar(&socketPath, "socket", "", "admin unix-socket path (overrides derived)")
	return c
}

func newAgentStatusCmd() *cobra.Command {
	var addr, socketPath string
	c := &cobra.Command{
		Use:   "status",
		Short: "Show daemon session counts/expiry (human only, no tokens)",
		Run: func(cmd *cobra.Command, _ []string) {
			const tool = "agent_status"
			res, err := adminPost(adminSocketFor(addr, socketPath), "/admin/status", nil)
			if err != nil {
				output.Fail(tool, err)
			}
			n := 0
			if f, ok := res["sessions"].(float64); ok {
				n = int(f)
			}
			output.Ok(tool, res, n)
		},
	}
	c.Flags().StringVar(&addr, "addr", "127.0.0.1:8471", "daemon model listener address (derives admin socket)")
	c.Flags().StringVar(&socketPath, "socket", "", "admin unix-socket path (overrides derived)")
	return c
}

func init() {
	parent := agentParent()
	parent.AddCommand(newAgentServeCmd())
	parent.AddCommand(newAgentGrantCmd())
	parent.AddCommand(newAgentRevokeCmd())
	parent.AddCommand(newAgentStatusCmd())
	parent.AddCommand(newAgentMCPCmd())
	parent.AddCommand(newAgentOMPInitCmd())
}

// newAgentMCPCmd runs the MCP stdio adapter: JSON-RPC 2.0 on stdin/stdout
// forwarding ONLY the typed broker tools (no admin/raw routing). The token
// comes from ODOO_BROKER_TOKEN in the environment (never argv) and is never
// logged.
func newAgentMCPCmd() *cobra.Command {
	var brokerURL string
	c := &cobra.Command{
		Use:   "mcp",
		Short: "Serve typed broker tools over MCP stdio (model runtime adapter)",
		Run: func(cmd *cobra.Command, _ []string) {
			const tool = "agent_mcp"
			cfg := mcpadapter.Config{BaseURL: brokerURL}.Resolve()
			if strings.TrimSpace(cfg.Token) == "" {
				output.Fail(tool, fmt.Errorf("ODOO_BROKER_TOKEN is not set (token via env only, never args)"))
			}
			srv := mcpadapter.New(cfg)
			if err := srv.Serve(cmd.Context()); err != nil {
				output.Fail(tool, err)
			}
		},
	}
	c.Flags().StringVar(&brokerURL, "url", "", "broker model listener URL (default $ODOO_BROKER_URL or http://127.0.0.1:8471)")
	return c
}

// newAgentOMPInitCmd writes a reviewed OMP tools config snippet plus a Codex
// MCP config snippet into --dir (examples only; never user settings). The
// snippet references the broker URL placeholder and the token env var; no
// secrets are written.
func newAgentOMPInitCmd() *cobra.Command {
	var dir, brokerURL string
	c := &cobra.Command{
		Use:   "omp-init",
		Short: "Write reviewed OMP/Codex wiring snippets (examples only)",
		Run: func(_ *cobra.Command, _ []string) {
			const tool = "agent_omp_init"
			if strings.TrimSpace(dir) == "" {
				output.Fail(tool, fmt.Errorf("--dir is required"))
			}
			if strings.TrimSpace(brokerURL) == "" {
				brokerURL = "http://127.0.0.1:8471"
			}
			if err := os.MkdirAll(dir, 0o755); err != nil {
				output.Fail(tool, err)
			}
			ompSnippet := "// Reviewed OMP wiring for the cli-odoo Odoo broker (generated by `agent omp-init`).\n" +
				"// Copy odoo-broker.js from tools/omp/ beside this file, then require it:\n" +
				"//   const { tools } = require('./odoo-broker.js');\n" +
				"// Broker: " + brokerURL + " (set ODOO_BROKER_URL to override).\n" +
				"// Auth: export ODOO_BROKER_TOKEN in the OMP process env (never write the token here).\n" +
				"// Typed tools only: odoo.search/read/count/aggregate/meta/companies/catalog/workspace.*.\n" +
				"module.exports = { brokerURL: " + fmt.Sprintf("%q", brokerURL) + " };\n"
			codexSnippet := "# Codex MCP config snippet (generated by `agent omp-init`; merge by hand).\n" +
				"# Restricted: typed broker tools only, token via env var, no secrets written.\n" +
				"#   codex mcp add odoo-broker -- cli-odoo agent mcp --url " + brokerURL + "\n" +
				"# Env required: ODOO_BROKER_URL=" + brokerURL + " ODOO_BROKER_TOKEN=<session-token>\n"
			if err := os.WriteFile(filepath.Join(dir, "odoo-broker.omp.js"), []byte(ompSnippet), 0o644); err != nil {
				output.Fail(tool, err)
			}
			if err := os.WriteFile(filepath.Join(dir, "codex-mcp-snippet.txt"), []byte(codexSnippet), 0o644); err != nil {
				output.Fail(tool, err)
			}
			output.Ok(tool, map[string]any{"dir": dir, "broker_url": brokerURL}, 2)
		},
	}
	c.Flags().StringVar(&dir, "dir", "", "output directory for example snippets (never user settings)")
	c.Flags().StringVar(&brokerURL, "url", "", "broker model listener URL placeholder (default http://127.0.0.1:8471)")
	return c
}
