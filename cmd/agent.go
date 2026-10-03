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
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/danieljclsilva/cli-odoo/internal/agent/broker"
	"github.com/danieljclsilva/cli-odoo/internal/agent/lock"
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
}
