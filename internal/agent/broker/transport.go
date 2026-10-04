// Runtime consumption findings (verified 2026-10-03, read-only):
//
//   - `codex mcp add --help`: supports `--url <URL>` for a "streamable HTTP
//     MCP server" plus `--bearer-token-env-var` (bearer auth), and stdio
//     servers via `-- <COMMAND>...`. Codex CAN consume MCP Streamable HTTP.
//   - `codex mcp list`: shows configured servers (stdio commands and HTTP
//     URLs observed live), confirming both transports in real use.
//   - `omp --help` (v18.2.6): NO mcp subcommand and no MCP client flags
//     (`grep -i mcp` over full help: no match). OMP has `--no-tools` /
//     `--tools=<list>` (tool gating, already known) and `--extension` /
//     `--hook` files, but no documented way to attach a remote MCP server
//     in this version. OMP MCP consumption is UNVERIFIED.
//
// Decision: serve plain typed JSON-RPC POST only (curl-consumable by any
// runtime, including OMP extensions/shell), no MCP Streamable HTTP endpoint.
// Adding a full MCP session protocol (initialize/tools-list/tools-call)
// for one runtime while the other cannot verifiably consume it would be an
// unaudited second surface. Revisit when OMP documents MCP consumption.
//
// Same-user posture (honest): the loopback listener and the 0600 unix admin
// socket assume a non-hostile local user. Any local process as the same
// user (or root) can reach both; deployment docs (manager-owned) must say
// so and require restricted tool surfaces + host controls. The broker does
// NOT claim same-user process isolation.
package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/danieljclsilva/cli-odoo/internal/agent/policy"
	"github.com/danieljclsilva/cli-odoo/internal/agent/snapshot"
	"github.com/danieljclsilva/cli-odoo/internal/agent/workspace"
	"github.com/danieljclsilva/cli-odoo/internal/config"
	"github.com/danieljclsilva/cli-odoo/internal/odoo"
)

// maxBodyBytes bounds a single model request body.
const maxBodyBytes = 1 << 20 // 1 MiB

// realBuildExec dials Odoo once (human serve path). Assigned in New; tests
// override it (or b.exec directly) so no keychain/network is touched.
func realBuildExec(inst *config.Instance) (executor, error) {
	c, err := odoo.New(inst)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// checkLoopbackAddr refuses any bind address whose host is not loopback
// (127.0.0.0/8, ::1 incl. IPv4-in-IPv6 forms, or localhost). Matching the
// repo's isLoopbackHost semantics (internal/odoo/client.go): real IP-literal
// test, exact hostname match only (127.evil.com is NOT loopback),
// resolver shorthand fails closed. addr must be host:port
// (net.SplitHostPort); missing/empty host is refused.
func checkLoopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("broker: invalid addr %q: %w", addr, err)
	}
	h := strings.TrimSpace(host)
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if strings.EqualFold(h, "localhost") {
		return nil
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		if ip.WithZone("").Unmap().IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("broker: refusing non-loopback bind address %q (loopback only)", addr)
}

// PrivateAdminDir is the per-user private directory holding the admin unix
// socket (e.g. /tmp/cli-odoo-agent-501 on Unix, keyed by euid so two users
// never share it). ensurePrivateDir creates it 0700 and verifies ownership
// before the admin listener binds. It is NOT the shared temp root itself:
// passing os.TempDir() directly would fail closed on Linux (mode 1777) or,
// worse, co-locate the socket with world-writable siblings.
func PrivateAdminDir() string {
	return filepath.Join(os.TempDir(), "cli-odoo-agent-"+adminDirSuffix())
}

// AdminSocketPath derives the deterministic admin unix-socket path for a
// model listener addr (e.g. 127.0.0.1:8080 ->
// $TMPDIR/cli-odoo-agent-<user>/cli-odoo-agent-127-0-0-1-8080.sock). The
// daemon creates the parent with ensurePrivateDir and the socket itself
// with mode 0600; access control is filesystem-only (same-user posture, see
// package header). Overridable via SetAdminSocket/--socket (still confined
// to the serving admin dir resolved at Serve time).
func AdminSocketPath(addr string) string {
	var b strings.Builder
	b.WriteString("cli-odoo-agent-")
	for _, r := range strings.ToLower(strings.TrimSpace(addr)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	b.WriteString(".sock")
	return filepath.Join(PrivateAdminDir(), b.String())
}

// effectiveAdminSocket returns the override or the derived default.
// Callers must still pass it through resolveAdminSocketPath so an explicit
// --socket cannot escape the serving admin dir.
func (b *Broker) effectiveAdminSocket(addr string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.adminSock != "" {
		return b.adminSock
	}
	return AdminSocketPath(addr)
}

// maxServingFileBytes bounds every profile/snapshot file the serve boundary
// loads before credential resolution (4 MiB, matching snapshot.MaxFileBytes;
// malformed or over-cap input denies before secrets are touched).
const maxServingFileBytes = 4 << 20

// checkServeFile bounds one serve-boundary file load through its held open
// descriptor (snapshot.ReadBoundedFile: Lstat pre-check without following,
// nonblocking open, held-handle fstat + SameFile, cap+1 bounded read): no
// Stat-then-ReadFile window, symlinks and non-regular files (including
// FIFOs) are refused without blocking, and a file that grows past
// maxServingFileBytes denies over-cap. The caller (Serve) runs this BEFORE
// credential resolution on every loading path.
func checkServeFile(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("broker: empty serving file path")
	}
	raw, err := snapshot.ReadBoundedFile(path, maxServingFileBytes, "serving file")
	if err != nil {
		return nil, fmt.Errorf("broker: serving file %q: %w", path, err)
	}
	return raw, nil
}

// verifyServingDigest recomputes snapshot.CanonicalDigest(snap) and compares
// it to the sealed policy binding BEFORE any credential resolves. A mismatch
// (swapped, edited, or stale snapshot) denies; the daemon never serves an
// unbound snapshot. The digest peer (snapshot slice) owns canonicalization;
// the broker only compares.
func verifyServingDigest(pol *policy.Policy, snap snapshot.Snapshot) error {
	got, err := snapshot.CanonicalDigest(snap)
	if err != nil {
		return fmt.Errorf("broker: snapshot digest: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(got), strings.TrimSpace(pol.SnapshotSHA256)) {
		return fmt.Errorf("broker: snapshot digest mismatch: sealed binding does not match loaded snapshot (re-seal via setup)")
	}
	return nil
}

// verifyCompanyFields runs policy.CompanyFieldValid for every allowlisted
// model BEFORE credential resolution: scoped models must resolve their
// CompanyField through the snapshot schema to a res.company
// many2one/many2many relation, and contradictory independent-with-field
// rules fail. Syntactically valid but semantically non-company fields deny
// before secrets are touched.
func verifyCompanyFields(pol *policy.Policy, snap snapshot.Snapshot) error {
	for name := range pol.Models {
		norm, ok := policy.NormalizeName(name)
		if !ok {
			return fmt.Errorf("broker: bad model name %q", name)
		}
		_ = norm
		if err := pol.CompanyFieldValid(snap, name); err != nil {
			return fmt.Errorf("broker: company field: %w", err)
		}
	}
	return nil
}

// servingProtected collects the file/dir paths the workspace must be
// confined against: the actual profile path, the actual snapshot path (or
// the sealed policy's SnapshotPath when the serving override is empty), the
// config dir, and the admin socket dir. Empty entries are dropped by
// workspace.ValidateDedicatedDir anyway.
func servingProtected(paths ServingPaths, pol *policy.Policy) []string {
	snapPath := strings.TrimSpace(paths.SnapshotPath)
	if snapPath == "" {
		snapPath = strings.TrimSpace(pol.SnapshotPath)
	}
	return []string{
		strings.TrimSpace(paths.ProfilePath),
		snapPath,
		strings.TrimSpace(paths.ConfigDir),
		strings.TrimSpace(paths.AdminDir),
	}
}

// resolveAdminSocketPath confines the effective admin socket path to the
// serving admin dir: the parent dir is created 0700 if missing, and an
// explicit override that escapes the dir denies. The returned path is the
// only socket path Serve may bind or remove.
func resolveAdminSocketPath(sockPath, adminDir string) (string, error) {
	dir := strings.TrimSpace(adminDir)
	if dir == "" {
		dir = filepath.Dir(strings.TrimSpace(sockPath))
	}
	if err := ensurePrivateDir(dir); err != nil {
		return "", err
	}
	absSock, err := filepath.Abs(sockPath)
	if err != nil {
		return "", fmt.Errorf("broker: admin socket path: %w", err)
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("broker: admin dir: %w", err)
	}
	rel, err := filepath.Rel(absDir, absSock)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("broker: admin socket %q escapes admin dir %q", sockPath, dir)
	}
	if filepath.Dir(absSock) != absDir {
		return "", fmt.Errorf("broker: admin socket %q must sit directly in admin dir %q", sockPath, dir)
	}
	return absSock, nil
}

// ensurePrivateDir creates dir with 0700 when missing, then verifies it
// resolves to a real directory owned by this uid with no group/other write
// (0700-equivalent on Unix; Windows skips the mode check). Anything else
// denies before the admin listener binds.
func ensurePrivateDir(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("broker: empty admin dir")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("broker: creating admin dir %q: %w", dir, err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("broker: admin dir %q: %w", dir, err)
	}
	if !st.IsDir() {
		return fmt.Errorf("broker: admin dir %q is not a directory", dir)
	}
	if err := checkSocketOwner(st); err != nil {
		return fmt.Errorf("broker: admin dir %q: %w", dir, err)
	}
	if st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("broker: admin dir %q has mode %04o: group/other access refused", dir, st.Mode().Perm())
	}
	return nil
}

// removeOnlyOwnedSocket removes path ONLY when stat proves it is a unix
// socket owned by this uid; anything else (regular file, dir, symlink,
// foreign-owned) denies instead of unlinking. Stale-socket cleanup and
// lifecycle teardown must go through this — never os.Remove on an arbitrary
// --socket path. Missing path is a no-op so first boot succeeds.
func removeOnlyOwnedSocket(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("broker: admin socket %q: %w", path, err)
	}
	if st.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("broker: refusing to remove non-socket %q (mode %v)", path, st.Mode())
	}
	if err := checkSocketOwner(st); err != nil {
		return fmt.Errorf("broker: refusing to remove foreign-owned socket %q: %w", path, err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("broker: removing stale socket %q: %w", path, err)
	}
	return nil
}

// Serve binds the model listener on addr (loopback only) plus the admin
// mux on a 0600 unix socket, and blocks. It resolves the keychain secret
// and dials Odoo once here — never in New. No admin endpoints exist on the
// TCP listener (typed tools + /healthz only).
//
// Serve order is load-bearing: BEFORE any credential resolves or any dial,
// in order: (1) bounded profile+snapshot file checks (regular file,
// <=4 MiB, on every loading path); (2) pol.Validate(); (3) recomputed
// snapshot.CanonicalDigest(snap) vs pol.SnapshotSHA256 (mismatch denies);
// (4) per-model CompanyFieldValid via the snapshot schema for scoped
// models; (5) config Instance.Name == pol.Instance plus snapshot scope
// match; (6) workspace.OpenValidated(wsDir, protected) where protected is
// the actual profile path + snapshot path + config dir + admin socket dir.
// Only then do credentials resolve, exec builds, and listeners bind.
func (b *Broker) Serve(addr string) error {
	if err := checkLoopbackAddr(addr); err != nil {
		return err
	}
	b.mu.Lock()
	pol := b.pol
	snap := b.snap
	paths := b.paths
	resolve := b.resolve
	build := b.buildExec
	instName := b.inst.Name
	allowWS := b.pol.AllowWorkspace
	wsDir := b.pol.WorkspaceDir
	b.mu.Unlock()
	// (1) Bounded serving-file loads first: reject over-cap/malformed
	// profile and snapshot files before secrets are touched. Empty paths
	// (in-process callers) skip the file check; the in-memory snap is
	// still digest- and scope-checked below.
	if strings.TrimSpace(paths.ProfilePath) != "" {
		if _, err := checkServeFile(paths.ProfilePath); err != nil {
			return err
		}
	}
	snapPath := strings.TrimSpace(paths.SnapshotPath)
	if snapPath == "" {
		snapPath = strings.TrimSpace(pol.SnapshotPath)
	}
	if snapPath != "" {
		if _, err := checkServeFile(snapPath); err != nil {
			return err
		}
	}
	// (2) Re-validate the sealed policy at serve time.
	if err := pol.Validate(); err != nil {
		return fmt.Errorf("broker: invalid policy: %w", err)
	}
	// (3) Digest binding: recompute and compare before credentials.
	if err := verifyServingDigest(pol, snap); err != nil {
		return err
	}
	// (4) Per-model company-field validity through the snapshot schema.
	if err := verifyCompanyFields(pol, snap); err != nil {
		return err
	}
	// (5) Instance + scope match (config name, snapshot instance/scope).
	if err := b.checkScopeMatch(); err != nil {
		return err
	}
	// Admin socket path: confined to the serving admin dir (override or
	// derived default). Resolved BEFORE the workspace opens so the socket
	// dir joins the protected set; bound AFTER credentials (below).
	rawSock := b.effectiveAdminSocket(addr)
	sockPath, err := resolveAdminSocketPath(rawSock, paths.AdminDir)
	if err != nil {
		return err
	}
	adminDir := filepath.Dir(sockPath)
	// (6) Workspace opens validated against the real protected set. The
	// helper already compares the held root against the validated path
	// (rename/substitution between validate and open denies) and checks
	// protected separation; Serve revalidates the held root immediately
	// before credential use below (after the scope match), so protected
	// state that moved in between still denies before secrets resolve.
	var wsProtected []string
	if allowWS {
		protected := servingProtected(paths, pol)
		protected = append(protected, sockPath, adminDir)
		wsProtected = append([]string(nil), protected...)
		ws, err := workspace.OpenValidated(wsDir, protected)
		if err != nil {
			return fmt.Errorf("broker: open workspace: %w", err)
		}
		b.mu.Lock()
		b.ws = ws
		b.mu.Unlock()
	}
	// Revalidate the held workspace root against the protected set
	// immediately before credential use: OpenValidated's checks were exact
	// at open time, but a rename/substitution or protected-path move since
	// then must still deny before secrets resolve. This is the
	// workspace-side helper; Serve owns the ordering (after scope match,
	// before resolve/dial).
	if allowWS {
		b.mu.Lock()
		ws := b.ws
		b.mu.Unlock()
		if ws == nil {
			return fmt.Errorf("broker: open workspace: workspace unavailable")
		}
		if err := ws.RevalidateProtectedSeparation(wsProtected); err != nil {
			return fmt.Errorf("broker: open workspace: %w", err)
		}
	}
	// Only now: resolve credentials and build exec.
	resolved, err := resolve(instName)
	if err != nil {
		return fmt.Errorf("broker: resolve instance: %w", err)
	}
	exec, err := build(resolved)
	if err != nil {
		return fmt.Errorf("broker: dial odoo: %w", err)
	}
	b.mu.Lock()
	b.exec = exec
	b.secrets = brokerSecrets(resolved)
	b.mu.Unlock()

	// Stale-socket cleanup removes ONLY a proven-owned socket; an
	// attacker-planted regular file at the path denies instead of unlinking.
	if err := removeOnlyOwnedSocket(sockPath); err != nil {
		return err
	}
	adminLn, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("broker: admin socket: %w", err)
	}
	// Chmod the actual listener socket 0600: umask-independent.
	if err := os.Chmod(sockPath, 0600); err != nil {
		_ = adminLn.Close()
		_ = removeOnlyOwnedSocket(sockPath)
		return fmt.Errorf("broker: admin socket mode: %w", err)
	}
	createdSock := true
	defer func() {
		_ = adminLn.Close()
		if createdSock {
			_ = removeOnlyOwnedSocket(sockPath)
		}
	}()
	adminErr := make(chan error, 1)
	go func() {
		srv := &http.Server{
			Handler:      b.adminMux(),
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
		}
		adminErr <- srv.Serve(adminLn)
	}()

	// Bounds: every model response (search/read/count/aggregate/meta/
	// companies/catalog/workspace) is capped by the sealed
	// Budgets.MaxResponseBytes envelope check at write time, and the
	// listeners carry read/write/idle timeouts so a stalled model peer
	// cannot hold a session handler forever.
	modelSrv := &http.Server{
		Addr:         addr,
		Handler:      b.modelMux(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	// Serve model+admin concurrently and propagate EITHER failure: an
	// admin-listener failure never passes silently while the model
	// listener keeps serving.
	modelDone := make(chan error, 1)
	go func() { modelDone <- modelSrv.ListenAndServe() }()
	select {
	case err := <-adminErr:
		return fmt.Errorf("broker: admin socket: %w", err)
	case err := <-modelDone:
		select {
		case aerr := <-adminErr:
			return fmt.Errorf("broker: admin socket: %w", aerr)
		default:
			return err
		}
	}
}

// ---------------------------------------------------------------------------
// Model mux (loopback TCP): typed tools + /healthz. No admin surface.
// ---------------------------------------------------------------------------

func (b *Broker) modelMux() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("/healthz", b.handleHealthz)
	m.HandleFunc("/rpc/search", b.requirePost(b.handleSearch))
	m.HandleFunc("/rpc/read", b.requirePost(b.handleRead))
	m.HandleFunc("/rpc/count", b.requirePost(b.handleCount))
	m.HandleFunc("/rpc/aggregate", b.requirePost(b.handleAggregate))
	m.HandleFunc("/rpc/meta", b.requireGet(b.handleMeta))
	m.HandleFunc("/rpc/companies", b.requireGet(b.handleCompanies))
	m.HandleFunc("/rpc/catalog", b.requireGet(b.handleCatalog))
	m.HandleFunc("/rpc/workspace/list", b.requirePost(b.handleWorkspaceList))
	m.HandleFunc("/rpc/workspace/read", b.requirePost(b.handleWorkspaceRead))
	m.HandleFunc("/rpc/workspace/write", b.requirePost(b.handleWorkspaceWrite))
	m.HandleFunc("/rpc/workspace/mkdir", b.requirePost(b.handleWorkspaceMkdir))
	return m
}

// adminMux (unix socket): grant/revoke/status, POST-only. Never served on
// TCP. POST-only (including status) avoids verb confusion; anything else is
// denied with 405.
func (b *Broker) adminMux() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("/admin/grant", b.requirePost(b.handleAdminGrant))
	m.HandleFunc("/admin/revoke", b.requirePost(b.handleAdminRevoke))
	m.HandleFunc("/admin/status", b.requirePost(b.handleAdminStatus))
	return m
}

func (b *Broker) requirePost(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			b.writeError(w, r, http.StatusMethodNotAllowed, "method not allowed (POST only)")
			return
		}
		h(w, r)
	}
}

func (b *Broker) requireGet(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			b.writeError(w, r, http.StatusMethodNotAllowed, "method not allowed (GET only)")
			return
		}
		h(w, r)
	}
}

// handleHealthz is the only unauthenticated endpoint. No secret, no data.
func (b *Broker) handleHealthz(w http.ResponseWriter, r *http.Request) {
	b.writeEnvelope(w, r, "", map[string]any{"ok": true}, 0)
}

// bearerToken extracts the session token. Anything else => unknown token.
func bearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", ErrSessionUnknown
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", ErrSessionUnknown
	}
	tok := strings.TrimSpace(strings.TrimPrefix(h, prefix))
	if tok == "" {
		return "", ErrSessionUnknown
	}
	return tok, nil
}

// checkError maps session failures to HTTP status without echoing tokens.
// Every branch routes through the single capped envelope writer so error
// responses obey Budgets.MaxResponseBytes like success responses.
func (b *Broker) checkError(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrSessionUnknown), errors.Is(err, ErrSessionExpired):
		b.writeError(w, r, http.StatusUnauthorized, err.Error())
	case errors.Is(err, ErrSessionBudget):
		b.writeError(w, r, http.StatusTooManyRequests, err.Error())
	default:
		b.writeError(w, r, http.StatusUnauthorized, ErrSessionUnknown.Error())
	}
	return true
}

// decodeBody parses exactly one JSON object with unknown fields rejected (so
// a caller-supplied context/CompanyIDs block fails closed) and an explicit
// 1 MiB byte cap enforced before decode. Trailing bytes beyond one complete
// object deny (trailing whitespace is allowed; a second value, `null`, or
// garbage is not). A null body into a struct denies: the target must stay a
// JSON object. Denials route through the capped error writer.
func (b *Broker) decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		b.writeError(w, r, http.StatusBadRequest, "unreadable request body")
		return false
	}
	if int64(len(body)) > maxBodyBytes {
		b.writeError(w, r, http.StatusRequestEntityTooLarge, "request body too large")
		return false
	}
	if len(bytes.TrimSpace(body)) == 0 {
		b.writeError(w, r, http.StatusBadRequest, "invalid request: empty body")
		return false
	}
	if string(bytes.TrimSpace(body)) == "null" {
		b.writeError(w, r, http.StatusBadRequest, "invalid request: null body")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		b.writeError(w, r, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", sanitizeBrokerErr(err)))
		return false
	}
	// Exactly one JSON value: a second decode must hit EOF (trailing
	// whitespace is consumed by Decode, so only real trailing data denies).
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		b.writeError(w, r, http.StatusBadRequest, "invalid request: trailing data after JSON object")
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Typed request shapes. No context/CompanyIDs fields exist: the broker
// injects the enforced scope after authorization; caller values cannot be
// supplied at all.
// ---------------------------------------------------------------------------

type searchBody struct {
	Model  string   `json:"model"`
	Domain any      `json:"domain"`
	Fields []string `json:"fields"`
	Order  string   `json:"order"`
	Limit  int      `json:"limit"`
	Offset int      `json:"offset"`
}

type readBody struct {
	Model  string   `json:"model"`
	IDs    []int    `json:"ids"`
	Fields []string `json:"fields"`
}

type countBody struct {
	Model  string `json:"model"`
	Domain any    `json:"domain"`
}

type aggregateBody struct {
	Model   string   `json:"model"`
	Domain  any      `json:"domain"`
	GroupBy []string `json:"groupby"`
	Sum     []string `json:"sum"`
	Avg     []string `json:"avg"`
	Count   bool     `json:"count"`
	Limit   int      `json:"limit"`
}

// scopedArgs ANDs the enforced company fragment into the caller domain
// AFTER caller conditions, and overwrites context keys: caller context
// cannot survive (no caller context is even parsed). The caller domain must
// already be gate-authorized (arity-complete), so the appended fragment
// always narrows via implicit AND. Unenforceable scope (enforce required
// but no fragment) fails closed here as defense in depth behind the gate.
func (b *Broker) scopedArgs(rule policy.ModelRule, domain any) ([]any, map[string]any, error) {
	frag, enforce := b.frag(rule, b.pol.Scope)
	if enforce && len(frag) == 0 {
		return nil, nil, errors.New("company scope unenforceable for this model")
	}
	full := make([]any, 0, len(frag)+4)
	if arr, ok := domain.([]any); ok {
		full = append(full, arr...)
	} else if domain != nil {
		return nil, nil, errors.New("invalid domain: want JSON array")
	}
	full = append(full, frag...)
	enabled := make([]any, 0, len(b.pol.Scope.Enabled))
	for _, id := range b.pol.Scope.Enabled {
		enabled = append(enabled, id)
	}
	kwargs := map[string]any{
		"context": map[string]any{
			"allowed_company_ids": enabled,
			"company_id":          b.pol.Scope.Default,
		},
	}
	return full, kwargs, nil
}

// authorize runs token check then the policy gate. Denial happens before
// any Execute call; both failures are JSON errors, never partial data.
func (b *Broker) authorize(w http.ResponseWriter, r *http.Request) (string, bool) {
	tok, err := bearerToken(r)
	if b.checkError(w, r, err) {
		return "", false
	}
	if b.checkError(w, r, b.Check(tok)) {
		return "", false
	}
	return tok, true
}

// gateMeta authorizes the unscoped discovery surface (meta listing,
// companies, catalog): no model membership, zero paging, no caller company
// selection. It mirrors the Authorize policy-listing branch without
// depending on the injected test gate (fakes are allow-all stubs for the
// data path, not the discovery authz).
func (b *Broker) gateMeta(w http.ResponseWriter, r *http.Request) bool {
	b.mu.Lock()
	pol := b.pol
	b.mu.Unlock()
	if !pol.Operations[policy.OpMeta] {
		b.writeError(w, r, http.StatusForbidden, "denied: "+policy.ReasonOperationDenied)
		return false
	}
	return true
}

// gate checks the deny-by-default policy for one request. The rule lookup
// uses the normalized model name so padded/case-variant input that the gate
// allowed (NormalizeName trims) resolves to the same sealed rule.
func (b *Broker) gate(w http.ResponseWriter, r *http.Request, req policy.Request) (policy.ModelRule, bool) {
	dec := b.gateAuth(req)
	if !dec.Allow {
		b.writeError(w, r, http.StatusForbidden, "denied: "+dec.Reason)
		return policy.ModelRule{}, false
	}
	name, _ := policy.NormalizeName(req.Model)
	b.mu.Lock()
	rule := b.pol.Models[name]
	b.mu.Unlock()
	return rule, true
}

func (b *Broker) gateAuth(req policy.Request) policy.Decision {
	return b.authz.Authorize(b.schemaView(), req)
}

// schemaView exposes the snapshot as the advisory schema for dot-path
// traversal checks. The policy allowlist stays authoritative.
func (b *Broker) schemaView() policy.SchemaView { return b.snap }

func defaultSearchLimit() int { return 50 }

// execOf returns the bound executor (nil until Serve builds it; protocol
// tests bind a fake directly).
func (b *Broker) execOf() executor {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exec
}

func (b *Broker) handleSearch(w http.ResponseWriter, r *http.Request) {
	tok, ok := b.authorize(w, r)
	if !ok {
		return
	}
	var in searchBody
	if !b.decodeBody(w, r, &in) {
		b.release(tok)
		return
	}
	limit := in.Limit
	if limit <= 0 {
		limit = defaultSearchLimit()
	}
	rule, ok := b.gate(w, r, policy.Request{
		Operation: policy.OpSearch, Model: in.Model, Fields: in.Fields,
		Domain: in.Domain, Order: in.Order, Limit: limit, Offset: in.Offset,
	})
	if !ok {
		b.release(tok)
		return
	}
	if !b.enforceable(w, r, rule) {
		b.release(tok)
		return
	}
	domain, kwargs, err := b.scopedArgs(rule, in.Domain)
	if err != nil {
		b.writeError(w, r, http.StatusBadRequest, err.Error())
		b.release(tok)
		return
	}
	kwargs["domain"] = domain
	kwargs["limit"] = limit
	kwargs["offset"] = in.Offset
	// Exact authorized projection: the gate already approved in.Fields, and
	// Odoo implicitly returns `id` on search_read, so send exactly the
	// approved list with `id` appended when absent (see policy.EnsureID).
	fs := make([]any, 0, len(in.Fields)+1)
	for _, f := range policy.EnsureID(in.Fields) {
		fs = append(fs, f)
	}
	kwargs["fields"] = fs
	if in.Order != "" {
		kwargs["order"] = in.Order
	}
	// Atomic row reservation BEFORE the RPC: reserve the whole admitted
	// limit (deny when want exceeds remaining — never silently reserve a
	// smaller min); on success settleRows refunds the unused headroom, on
	// RPC or output failure the attempt keeps its reservation (billed).
	// dispatchExec takes one in-flight slot (429 when saturated, rolled
	// back via releaseReserve since no RPC ran). Context-aware executors
	// abort the upstream call on timeout/cancel; legacy executors keep
	// the slot until the actual Execute returns, so saturation keeps
	// denying until real work drains (HTTP WriteTimeout alone cannot
	// bound the upstream call); dispatched failures keep the reservation.
	reserved, err := b.reserveForLimit(tok, limit)
	if b.checkError(w, r, err) {
		b.release(tok)
		return
	}
	res, err := b.dispatchExec(r, in.Model, "search_read", nil, kwargs)
	if err != nil {
		if errors.Is(err, ErrSessionBudget) {
			b.writeError(w, r, http.StatusTooManyRequests, ErrSessionBudget.Error())
			b.releaseReserve(tok, reserved)
			return
		}
		if errors.Is(err, errBrokerNotServing) {
			b.writeError(w, r, http.StatusServiceUnavailable, "broker not serving")
			b.releaseReserve(tok, reserved)
			return
		}
		b.writeError(w, r, http.StatusBadGateway, b.redactErr(r.Context(), err).Error())
		return
	}
	if err := b.live(tok); err != nil {
		b.checkError(w, r, err)
		return
	}
	b.writeRows(w, r, tok, res, reserved)
}

func (b *Broker) handleRead(w http.ResponseWriter, r *http.Request) {
	tok, ok := b.authorize(w, r)
	if !ok {
		return
	}
	var in readBody
	if !b.decodeBody(w, r, &in) {
		b.release(tok)
		return
	}
	if len(in.IDs) == 0 {
		b.writeError(w, r, http.StatusBadRequest, "ids is required")
		b.release(tok)
		return
	}
	ids := make([]any, 0, len(in.IDs))
	for _, id := range in.IDs {
		ids = append(ids, id)
	}
	// Never raw read: by-id converts to a scoped search_read so the
	// company fragment still applies to every row.
	rule, ok := b.gate(w, r, policy.Request{
		Operation: policy.OpRead, Model: in.Model, Fields: in.Fields,
		Domain: []any{[]any{"id", "in", ids}}, Limit: len(ids),
	})
	if !ok {
		b.release(tok)
		return
	}
	if !b.enforceable(w, r, rule) {
		b.release(tok)
		return
	}
	domain, kwargs, err := b.scopedArgs(rule, []any{[]any{"id", "in", ids}})
	if err != nil {
		b.writeError(w, r, http.StatusBadRequest, err.Error())
		b.release(tok)
		return
	}
	kwargs["domain"] = domain
	kwargs["limit"] = len(ids)
	kwargs["offset"] = 0
	// Same exact-projection rule as search: approved fields plus `id`.
	rfs := make([]any, 0, len(in.Fields)+1)
	for _, f := range policy.EnsureID(in.Fields) {
		rfs = append(rfs, f)
	}
	kwargs["fields"] = rfs
	reserved, err := b.reserveForLimit(tok, len(ids))
	if b.checkError(w, r, err) {
		b.release(tok)
		return
	}
	res, err := b.dispatchExec(r, in.Model, "search_read", nil, kwargs)
	if err != nil {
		if errors.Is(err, ErrSessionBudget) {
			b.writeError(w, r, http.StatusTooManyRequests, ErrSessionBudget.Error())
			b.releaseReserve(tok, reserved)
			return
		}
		if errors.Is(err, errBrokerNotServing) {
			b.writeError(w, r, http.StatusServiceUnavailable, "broker not serving")
			b.releaseReserve(tok, reserved)
			return
		}
		b.writeError(w, r, http.StatusBadGateway, b.redactErr(r.Context(), err).Error())
		return
	}
	if err := b.live(tok); err != nil {
		b.checkError(w, r, err)
		return
	}
	b.writeRows(w, r, tok, res, reserved)
}

func (b *Broker) handleCount(w http.ResponseWriter, r *http.Request) {
	tok, ok := b.authorize(w, r)
	if !ok {
		return
	}
	var in countBody
	if !b.decodeBody(w, r, &in) {
		b.release(tok)
		return
	}
	// A count returns one scalar; authorize with zero paging.
	rule, ok := b.gate(w, r, policy.Request{
		Operation: policy.OpCount, Model: in.Model, Domain: in.Domain,
	})
	if !ok {
		b.release(tok)
		return
	}
	domain, kwargs, err := b.scopedArgs(rule, in.Domain)
	if err != nil {
		b.writeError(w, r, http.StatusBadRequest, err.Error())
		b.release(tok)
		return
	}
	if !b.enforceable(w, r, rule) {
		b.release(tok)
		return
	}
	// A count result is one scalar row surface: reserve exactly 1 before
	// dispatch so exhausted row budgets deny rather than serve unbilled.
	// The attempt stays billed on RPC/output failure (no release). The
	// semaphore denial below rolls back via releaseReserve (no RPC ran).
	reserved, err := b.reserveForLimit(tok, 1)
	if b.checkError(w, r, err) {
		b.release(tok)
		return
	}
	res, err := b.dispatchExec(r, in.Model, "search_count", []any{domain}, kwargs)
	if err != nil {
		if errors.Is(err, ErrSessionBudget) {
			b.writeError(w, r, http.StatusTooManyRequests, ErrSessionBudget.Error())
			b.releaseReserve(tok, reserved)
			return
		}
		if errors.Is(err, errBrokerNotServing) {
			b.writeError(w, r, http.StatusServiceUnavailable, "broker not serving")
			b.releaseReserve(tok, reserved)
			return
		}
		b.writeError(w, r, http.StatusBadGateway, b.redactErr(r.Context(), err).Error())
		return
	}
	if err := b.live(tok); err != nil {
		b.checkError(w, r, err)
		return
	}
	b.settleRows(tok, reserved, 1)
	b.writeEnvelope(w, r, tok, res, 1)
}

func (b *Broker) handleAggregate(w http.ResponseWriter, r *http.Request) {
	tok, ok := b.authorize(w, r)
	if !ok {
		return
	}
	var in aggregateBody
	if !b.decodeBody(w, r, &in) {
		b.release(tok)
		return
	}
	if len(in.GroupBy) == 0 {
		b.writeError(w, r, http.StatusBadRequest, "groupby is required")
		b.release(tok)
		return
	}
	if len(in.Sum) == 0 && len(in.Avg) == 0 && !in.Count {
		b.writeError(w, r, http.StatusBadRequest, "at least one of sum, avg, count is required")
		b.release(tok)
		return
	}
	// Authorize on plain field names: groupby interval suffixes
	// (date_order:month) and read_group :sum/:avg specifiers are stripped
	// for the gate, and the suffix itself must be [A-Za-z0-9_]+.
	plain := make([]string, 0, len(in.GroupBy)+len(in.Sum)+len(in.Avg))
	plainGroup := make([]string, 0, len(in.GroupBy))
	for _, g := range in.GroupBy {
		head, suffix, _ := strings.Cut(g, ":")
		if strings.TrimSpace(head) == "" {
			b.writeError(w, r, http.StatusBadRequest, "invalid groupby entry")
			b.release(tok)
			return
		}
		if suffix != "" {
			for _, ch := range suffix {
				if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_') {
					b.writeError(w, r, http.StatusBadRequest, "invalid groupby interval")
					b.release(tok)
					return
				}
			}
		}
		plain = append(plain, head)
		plainGroup = append(plainGroup, head)
	}
	plain = append(plain, in.Sum...)
	plain = append(plain, in.Avg...)
	limit := maxLimitOr(in.Limit, defaultSearchLimit())
	rule, ok := b.gate(w, r, policy.Request{
		Operation: policy.OpAggregate, Model: in.Model, Fields: plain,
		Domain: in.Domain, GroupBy: plainGroup,
		Limit: limit,
	})
	if !ok {
		b.release(tok)
		return
	}
	domain, kwargs, err := b.scopedArgs(rule, in.Domain)
	if err != nil {
		b.writeError(w, r, http.StatusBadRequest, err.Error())
		b.release(tok)
		return
	}
	if !b.enforceable(w, r, rule) {
		b.release(tok)
		return
	}
	var fields, gb []any
	for _, g := range in.GroupBy {
		fields = append(fields, g)
		gb = append(gb, g)
	}
	for _, s := range in.Sum {
		fields = append(fields, s+":sum")
	}
	for _, a := range in.Avg {
		fields = append(fields, a+":avg")
	}
	kwargs["lazy"] = false
	kwargs["limit"] = limit
	reserved, err := b.reserveForLimit(tok, limit)
	if b.checkError(w, r, err) {
		b.release(tok)
		return
	}
	res, err := b.dispatchExec(r, in.Model, "read_group", []any{domain, fields, gb}, kwargs)
	if err != nil {
		if errors.Is(err, ErrSessionBudget) {
			b.writeError(w, r, http.StatusTooManyRequests, ErrSessionBudget.Error())
			b.releaseReserve(tok, reserved)
			return
		}
		if errors.Is(err, errBrokerNotServing) {
			b.writeError(w, r, http.StatusServiceUnavailable, "broker not serving")
			b.releaseReserve(tok, reserved)
			return
		}
		b.writeError(w, r, http.StatusBadGateway, b.redactErr(r.Context(), err).Error())
		return
	}
	if err := b.live(tok); err != nil {
		b.checkError(w, r, err)
		return
	}
	b.writeRows(w, r, tok, res, reserved)
}

// enforceable is defense in depth behind the policy gate: a scoped model
// (neither company-independent nor companyless-opted) must carry an
// enforceable company fragment, or the request denies even if Authorize
// passed. Never serve no-fragment scoped models.
func (b *Broker) enforceable(w http.ResponseWriter, r *http.Request, rule policy.ModelRule) bool {
	if rule.CompanyIndependent {
		if rule.CompanyField != "" {
			// Contradictory (rejected by Validate, denied by Authorize):
			// fail closed here too.
			b.writeError(w, r, http.StatusForbidden, "denied: company scope unenforceable for this model")
			return false
		}
		return true
	}
	b.mu.Lock()
	scope := b.pol.Scope
	b.mu.Unlock()
	frag, enforce := b.frag(rule, scope)
	if enforce && len(frag) == 0 {
		b.writeError(w, r, http.StatusForbidden, "denied: company scope unenforceable for this model")
		return false
	}
	if !enforce {
		b.writeError(w, r, http.StatusForbidden, "denied: company scope unenforceable for this model")
		return false
	}
	return true
}

// handleMeta is discoverable-not-executable: it serves the sealed
// allowlist (operations, models, fields) from memory and never calls
// Execute. The schema view behind Authorize is the human-built snapshot,
// but meta itself discloses policy only — no record data, no secrets.
func (b *Broker) handleMeta(w http.ResponseWriter, r *http.Request) {
	tok, ok := b.authorize(w, r)
	if !ok {
		return
	}
	model := strings.TrimSpace(r.URL.Query().Get("model"))
	if model != "" {
		rule, ok := b.gate(w, r, policy.Request{Operation: policy.OpMeta, Model: model})
		if !ok {
			b.release(tok)
			return
		}
		if err := b.live(tok); err != nil {
			b.checkError(w, r, err)
			return
		}
		b.record(tok, 0)
		b.writeEnvelope(w, r, tok, map[string]any{
			"model": model, "fields": rule.Fields,
			"max_limit": rule.MaxLimit, "allow_aggregate": rule.AllowAggregate,
		}, len(rule.Fields))
		return
	}
	if !b.gateMeta(w, r) {
		b.release(tok)
		return
	}
	if err := b.live(tok); err != nil {
		b.checkError(w, r, err)
		return
	}
	ops := make([]string, 0, len(b.pol.Operations))
	for op, allow := range b.pol.Operations {
		if allow {
			ops = append(ops, string(op))
		}
	}
	models := make(map[string]any, len(b.pol.Models))
	for name, rule := range b.pol.Models {
		models[name] = map[string]any{
			"fields": rule.Fields, "max_limit": rule.MaxLimit,
			"allow_aggregate": rule.AllowAggregate,
		}
	}
	b.record(tok, 0)
	b.writeEnvelope(w, r, tok, map[string]any{
		"instance": b.pol.Instance, "operations": ops, "models": models,
		"default_company": b.pol.Scope.Default, "workspace": b.pol.AllowWorkspace,
	}, len(models))
}

// handleCompanies serves company discovery from the sealed policy plus the
// human-built snapshot (no Execute): available companies come from the
// snapshot's discovered res.company rows, while enabled/default come from
// the sealed scope. The model cannot select companies from this listing;
// the broker injects the enforced scope on every RPC regardless.
func (b *Broker) handleCompanies(w http.ResponseWriter, r *http.Request) {
	tok, ok := b.authorize(w, r)
	if !ok {
		return
	}
	if !b.gateMeta(w, r) {
		b.release(tok)
		return
	}
	if err := b.live(tok); err != nil {
		b.checkError(w, r, err)
		return
	}
	b.mu.Lock()
	avail := make([]any, 0, len(b.snap.AvailableCompanies))
	availByID := make(map[int]string, len(b.snap.AvailableCompanies))
	for _, c := range b.snap.AvailableCompanies {
		avail = append(avail, map[string]any{"id": c.ID, "name": c.Name})
		availByID[c.ID] = c.Name
	}
	enabled := append([]int(nil), b.pol.Scope.Enabled...)
	def := b.pol.Scope.Default
	b.mu.Unlock()
	enabledOut := make([]any, 0, len(enabled))
	for _, id := range enabled {
		name := availByID[id]
		enabledOut = append(enabledOut, map[string]any{"id": id, "name": name})
	}
	b.record(tok, 0)
	b.writeEnvelope(w, r, tok, map[string]any{
		"available": avail, "enabled": enabledOut, "default": def,
	}, len(avail))
}

// handleCatalog serves the per-model catalog from the sealed policy plus
// the snapshot (no Execute). executable is true only for models in
// Policy.Models; discoverable-only snapshot models list with
// executable:false and are denied to read/call by the gate (unknown-model
// deny), never auto-enabled.
//
// method_manifest is the snapshot-level MethodManifest (informational ONLY:
// presence never authorizes execution and no Execute path takes a name from
// it) plus per-field provenance: recorded per-field provenance when present,
// else explicit "unknown" with an unknown_provenance entry listing the field.
func (b *Broker) handleCatalog(w http.ResponseWriter, r *http.Request) {
	model := strings.TrimSpace(r.URL.Query().Get("model"))
	if model != "" {
		norm, ok := policy.NormalizeName(model)
		if !ok {
			b.writeError(w, r, http.StatusBadRequest, "invalid model name")
			return
		}
		_ = norm
		tok, ok := b.authorize(w, r)
		if !ok {
			return
		}
		if !b.gateMeta(w, r) {
			b.release(tok)
			return
		}
		if _, allowed := b.pol.Models[model]; !allowed {
			if _, allowed := b.pol.Models[norm]; !allowed {
				b.writeError(w, r, http.StatusForbidden, "denied: "+policy.ReasonUnknownModel)
				b.release(tok)
				return
			}
		}
		if err := b.live(tok); err != nil {
			b.checkError(w, r, err)
			return
		}
		entry, _ := b.catalogEntry(model)
		if entry == nil {
			entry, _ = b.catalogEntry(norm)
		}
		if entry == nil {
			b.writeError(w, r, http.StatusForbidden, "denied: "+policy.ReasonUnknownModel)
			b.release(tok)
			return
		}
		b.record(tok, 0)
		b.writeEnvelope(w, r, tok, entry, 1)
		return
	}
	tok, ok := b.authorize(w, r)
	if !ok {
		return
	}
	if !b.gateMeta(w, r) {
		b.release(tok)
		return
	}
	if err := b.live(tok); err != nil {
		b.checkError(w, r, err)
		return
	}
	b.mu.Lock()
	models := make(map[string]any, len(b.snap.Models)+len(b.pol.Models))
	for name, meta := range b.snap.Models {
		_, exec := b.pol.Models[name]
		fields, unknown := catalogFields(meta)
		entry := map[string]any{
			"label": meta.Label, "provenance": meta.Provenance,
			"executable": exec, "fields": fields,
		}
		if len(unknown) > 0 {
			entry["unknown_provenance"] = unknown
		}
		models[name] = entry
	}
	for name, rule := range b.pol.Models {
		if _, seen := models[name]; seen {
			continue
		}
		fields := make(map[string]any, len(rule.Fields))
		unknown := make([]string, 0, len(rule.Fields))
		for _, fname := range rule.Fields {
			fields[fname] = map[string]any{
				"type": "", "relation": "", "label": fname,
				"provenance": snapshot.ProvUnknown,
			}
			unknown = append(unknown, fname)
		}
		entry := map[string]any{
			"label": name, "provenance": snapshot.ProvUnknown,
			"executable": true, "fields": fields,
			"unknown_provenance": unknown,
		}
		models[name] = entry
	}
	manifest := append([]string(nil), b.snap.MethodManifest...)
	b.mu.Unlock()
	b.record(tok, 0)
	b.writeEnvelope(w, r, tok, map[string]any{"models": models, "method_manifest": manifest}, len(models))
}

// catalogFields renders one snapshot model's fields with per-field
// provenance: the recorded per-field provenance when present, else explicit
// "unknown". The second return lists fields with unknown provenance.
func catalogFields(meta snapshot.ModelMeta) (map[string]any, []string) {
	fields := make(map[string]any, len(meta.Fields))
	var unknown []string
	for fname, f := range meta.Fields {
		prov := strings.TrimSpace(f.Provenance)
		if prov == "" {
			prov = snapshot.ProvUnknown
			unknown = append(unknown, fname)
		}
		fields[fname] = map[string]any{
			"type": f.Type, "relation": f.Relation,
			"label": f.Label, "provenance": prov,
		}
	}
	return fields, unknown
}

// catalogEntry renders one model's catalog entry (same shape as the
// per-model values in handleCatalog, without the manifest wrapper).
func (b *Broker) catalogEntry(name string) (map[string]any, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if meta, ok := b.snap.Models[name]; ok {
		_, exec := b.pol.Models[name]
		fields, unknown := catalogFields(meta)
		entry := map[string]any{
			"label": meta.Label, "provenance": meta.Provenance,
			"executable": exec, "fields": fields,
		}
		if len(unknown) > 0 {
			entry["unknown_provenance"] = unknown
		}
		return entry, true
	}
	if rule, ok := b.pol.Models[name]; ok {
		fields := make(map[string]any, len(rule.Fields))
		unknown := make([]string, 0, len(rule.Fields))
		for _, fname := range rule.Fields {
			fields[fname] = map[string]any{
				"type": "", "relation": "", "label": fname,
				"provenance": snapshot.ProvUnknown,
			}
			unknown = append(unknown, fname)
		}
		return map[string]any{
			"label": name, "provenance": snapshot.ProvUnknown,
			"executable": true, "fields": fields,
			"unknown_provenance": unknown,
		}, true
	}
	return nil, false
}

// ---------------------------------------------------------------------------
// Row/byte caps + billing.
// ---------------------------------------------------------------------------

// toSlice coerces an Execute list result to []any.
func toSlice(v any) ([]any, bool) {
	if v == nil {
		return nil, true
	}
	if s, ok := v.([]any); ok {
		return s, true
	}
	return nil, false
}

// writeRows settles the pre-RPC row reservation and writes the success
// envelope through the single MaxResponseBytes envelope cap. There is NO
// silent pagination or truncation here: when the RPC returns more rows than
// the atomic reservation (or more than the MaxRowsPerCall cap), writeRows
// DENIES with a budget error instead of false-completing a narrowed slice
// (fail closed: a "success" envelope must never claim count=N for fewer
// than N admitted rows). There is no reviewed pagination contract anywhere
// in this codebase (searched: no paginate/cursor/continuation envelope
// exists on the typed RPC surface), so the only honest over-cap behavior is
// denial. Likewise, a serialized envelope that exceeds MaxResponseBytes
// denies: shedding trailing rows to fit the byte cap would present a partial
// payload as a complete one. An RPC success that yields zero deliverable
// rows still bills the admitted call (Check reservation stands, no release).
// Any output that cannot fit the envelope denies instead of sending partial
// data; the admitted reservation stays billed on every post-RPC denial.
func (b *Broker) writeRows(w http.ResponseWriter, r *http.Request, tok string, res any, reserved int) {
	rows, ok := toSlice(res)
	if !ok {
		b.writeError(w, r, http.StatusBadGateway, "unexpected result shape")
		return
	}
	b.mu.Lock()
	maxRows := b.pol.Budgets.MaxRowsPerCall
	maxBytes := b.pol.Budgets.MaxResponseBytes
	b.mu.Unlock()
	if maxRows > 0 && len(rows) > maxRows {
		b.writeError(w, r, http.StatusTooManyRequests, ErrSessionBudget.Error())
		return
	}
	if len(rows) > reserved {
		b.writeError(w, r, http.StatusTooManyRequests, ErrSessionBudget.Error())
		return
	}
	n, err := json.Marshal(map[string]any{"success": true, "result": rows, "count": len(rows)})
	if err != nil {
		b.writeError(w, r, http.StatusInternalServerError, "encode response")
		return
	}
	if maxBytes > 0 && len(n) > maxBytes {
		b.writeError(w, r, http.StatusBadGateway, fmt.Sprintf("response %d bytes exceeds cap %d", len(n), maxBytes))
		return
	}
	b.settleRows(tok, reserved, len(rows))
	b.writeEnvelope(w, r, tok, rows, len(rows))
}

// writeEnvelope marshals ANY model response and enforces the single total
// serialized envelope cap (Budgets.MaxResponseBytes) for every endpoint,
// including meta/companies/catalog/workspace/count. Over-cap output denies
// with an error instead of sending; the admitted call stays billed (no
// release-on-failure). w and r are unused except for the response path;
// r is kept for redaction context parity with the RPC handlers.
func (b *Broker) writeEnvelope(w http.ResponseWriter, r *http.Request, tok string, result any, count int) {
	_ = r
	_ = tok
	b.writeEnvelopeRaw(w, http.StatusOK, map[string]any{"success": true, "result": result, "count": count})
}

// writeError is the single error-envelope writer: every model/admin error
// response is JSON-capped by Budgets.MaxResponseBytes like success
// envelopes. When even the error envelope exceeds the cap the message is
// replaced with a short generic denial (never truncated JSON, never a bare
// http.Error). The admitted call stays billed; callers must not release.
func (b *Broker) writeError(w http.ResponseWriter, r *http.Request, code int, msg string) {
	_ = r
	b.writeEnvelopeRaw(w, code, map[string]any{"success": false, "error": msg})
}

// writeEnvelopeRaw marshals one success response and enforces the single
// total serialized envelope cap (Budgets.MaxResponseBytes) for every
// endpoint, including meta/companies/catalog/workspace/count. Over-cap
// output denies with an error instead of sending; the admitted call stays
// billed (no release-on-failure). It is the shared tail of writeEnvelope
// (session-billed model responses) and writeError's fallback shape.
//
// Oversize-error honesty: the fallback denial itself is capped (see
// writeCappedError/writeRawDenied). When the cap cannot carry even the
// minimum JSON denial, a bounded empty-body transport denial preserves the
// status code with no JSON claim — never an uncapped write or truncated
// JSON. Success and error outputs therefore share one actual serialized
// cap on every path.
func (b *Broker) writeEnvelopeRaw(w http.ResponseWriter, code int, body map[string]any) {
	n, err := json.Marshal(body)
	if err != nil {
		b.writeRawDenied(w, code)
		return
	}
	b.mu.Lock()
	maxBytes := b.pol.Budgets.MaxResponseBytes
	b.mu.Unlock()
	if maxBytes > 0 && len(n) > maxBytes {
		if _, isErr := body["error"]; isErr {
			b.writeCappedError(w, code, "request denied", maxBytes)
			return
		}
		b.writeCappedError(w, http.StatusBadGateway, fmt.Sprintf("response %d bytes exceeds cap %d", len(n), maxBytes), maxBytes)
		return
	}
	if v, isErr := body["error"]; isErr {
		errMsg, _ := v.(string)
		if errMsg == "" {
			errMsg = "request denied"
		}
		b.writeCappedError(w, code, errMsg, maxBytes)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if code != http.StatusOK {
		w.WriteHeader(code)
	}
	_, _ = w.Write(n)
}

// writeCappedError writes one error envelope known to fit maxBytes, or a
// bounded empty-body denial when no JSON denial can fit. It never calls
// the uncapped writeRPCError on oversize paths: every byte the model sees
// passed the cap check.
func (b *Broker) writeCappedError(w http.ResponseWriter, code int, msg string, maxBytes int) {
	n, err := json.Marshal(map[string]any{"success": false, "error": msg})
	if err != nil || (maxBytes > 0 && len(n) > maxBytes) {
		short, serr := json.Marshal(map[string]any{"success": false, "error": "request denied"})
		if serr != nil || (maxBytes > 0 && len(short) > maxBytes) {
			b.writeRawDenied(w, code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write(short)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(n)
}

// writeRawDenied is the last resort: an empty-body transport denial with
// the status code preserved. Used only when the configured cap cannot carry
// even the minimum JSON denial — no JSON is emitted, so nothing exceeds
// the cap by construction.
func (b *Broker) writeRawDenied(w http.ResponseWriter, code int) {
	if code == 0 {
		code = http.StatusBadGateway
	}
	w.WriteHeader(code)
}

func maxLimitOr(v, d int) int {
	if v > 0 {
		return v
	}
	return d
}

// sanitizeBrokerErr mirrors the odoo client sanitizeErr semantics for the
// model path: broker-held secrets (resolved keychain password/API key, URL
// userinfo) are replaced with "***" before the error reaches the model.
// Secrets are fixed at Serve time; pre-Serve errors carry nothing to redact.
func (b *Broker) sanitizeBrokerErr(err error) error {
	if err == nil {
		return nil
	}
	b.mu.Lock()
	secrets := append([]string(nil), b.secrets...)
	b.mu.Unlock()
	s := err.Error()
	changed := false
	for _, sec := range secrets {
		if sec == "" {
			continue
		}
		if strings.Contains(s, sec) {
			s = strings.ReplaceAll(s, sec, "***")
			changed = true
		}
	}
	if !changed {
		return err
	}
	return errors.New(s)
}

// redactErr strips broker-held secrets from error text before it reaches
// the model, mirroring the odoo client sanitizeErr semantics: secrets
// become "***", never echoed.
func (b *Broker) redactErr(_ context.Context, err error) error {
	return b.sanitizeBrokerErr(err)
}

// brokerSecrets collects redactable values from a resolved instance: the
// keychain password/API key plus URL userinfo, longest first. Short
// (<=3 rune) fragments are skipped so redaction cannot blank generic text.
func brokerSecrets(inst *config.Instance) []string {
	if inst == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if len([]rune(v)) <= 3 || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	add(inst.Password)
	add(inst.APIKey)
	if u, uerr := url.Parse(inst.URL); uerr == nil && u != nil && u.User != nil {
		add(u.User.Username())
		if pw, ok := u.User.Password(); ok {
			add(pw)
		}
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// sanitizeBrokerErr is the package-level form used by tests without a Broker.
func sanitizeBrokerErr(err error) error {
	if err == nil {
		return nil
	}
	return err
}

// ---------------------------------------------------------------------------
// Admin handlers (unix socket only, POST-only except status).
// ---------------------------------------------------------------------------

type grantBody struct {
	TTLSeconds int64 `json:"ttl_seconds"`
}

// handleAdminGrant mints a session token (returned once) over the admin
// socket. Never on TCP.
func (b *Broker) handleAdminGrant(w http.ResponseWriter, r *http.Request) {
	var in grantBody
	if !b.decodeBody(w, r, &in) {
		return
	}
	ttl := time.Duration(in.TTLSeconds) * time.Second
	if in.TTLSeconds <= 0 {
		b.writeError(w, r, http.StatusBadRequest, "ttl_seconds must be positive")
		return
	}
	tok, err := b.Grant(ttl)
	if err != nil {
		b.writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	b.writeEnvelope(w, r, "", map[string]any{"token": tok, "ttl_seconds": in.TTLSeconds}, 1)
}

// handleAdminRevoke revokes by full token or unambiguous prefix carried in
// {"token": ...} or {"prefix": ...}. Unknown or ambiguous prefixes fail
// without revoking anything. Never on TCP.
func (b *Broker) handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token  string `json:"token"`
		Prefix string `json:"prefix"`
	}
	if !b.decodeBody(w, r, &in) {
		return
	}
	target := in.Token
	if target == "" {
		target = in.Prefix
	}
	if target == "" {
		b.writeError(w, r, http.StatusBadRequest, "token or prefix is required")
		return
	}
	if in.Token != "" {
		if !b.hasSession(target) {
			b.writeError(w, r, http.StatusNotFound, ErrSessionUnknown.Error())
			return
		}
		b.Revoke(target)
		b.writeEnvelope(w, r, "", map[string]any{"revoked": true}, 1)
		return
	}
	if err := b.revokePrefix(target); err != nil {
		if errors.Is(err, ErrSessionUnknown) {
			b.writeError(w, r, http.StatusNotFound, err.Error())
			return
		}
		b.writeError(w, r, http.StatusConflict, err.Error())
		return
	}
	b.writeEnvelope(w, r, "", map[string]any{"revoked": true}, 1)
}

// hasSession reports whether token names a live session.
func (b *Broker) hasSession(token string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.sessions[token]
	return ok
}

// handleAdminStatus returns counts/expiry only — never tokens or secrets.
// Never on TCP.
func (b *Broker) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	n, ttls, version, instance := b.sessionStats()
	b.writeEnvelope(w, r, "", map[string]any{
		"sessions": n, "expires_in_seconds": ttls,
		"policy_version": version, "instance": instance,
	}, n)
}

// ---------------------------------------------------------------------------
// Workspace handlers (model TCP, gated by policy.AllowWorkspace).
//
// Row-budget semantics: list and read are billable row surfaces with atomic
// reservations like the RPC row paths — list reserves its effective
// max_entries want (deny when want exceeds remaining, never silently list
// more than reserved) and settles to delivered rows; read reserves exactly
// 1; mkdir reserves exactly 1 (one created directory = one billed row).
// record() is NOT used for these row surfaces. Write bills no rows.
// Metadata counts (envelope "count") never reserve or settle.
// ---------------------------------------------------------------------------

// handleWorkspaceList lists workspace entries (broker-confined reads).
// Caller max_entries can only narrow the policy row cap, never widen it:
// effective = min(caller-or-default, MaxRowsPerCall). The effective want is
// reserved atomically BEFORE listing; over-remaining wants deny.
func (b *Broker) handleWorkspaceList(w http.ResponseWriter, r *http.Request) {
	tok, ok := b.authorize(w, r)
	if !ok {
		return
	}
	if !b.workspaceAllowed(w, r) {
		b.release(tok)
		return
	}
	var in struct {
		Path       string `json:"path"`
		MaxEntries int    `json:"max_entries"`
	}
	if !b.decodeBody(w, r, &in) {
		b.release(tok)
		return
	}
	ws := b.workspace()
	if ws == nil {
		b.writeError(w, r, http.StatusServiceUnavailable, "workspace unavailable")
		b.release(tok)
		return
	}
	b.mu.Lock()
	capRows := b.pol.Budgets.MaxRowsPerCall
	b.mu.Unlock()
	want := in.MaxEntries
	if want <= 0 {
		want = 100
	}
	maxEntries := want
	if capRows > 0 && maxEntries > capRows {
		maxEntries = capRows
	}
	reserved, err := b.reserveForLimit(tok, maxEntries)
	if b.checkError(w, r, err) {
		b.release(tok)
		return
	}
	entries, err := ws.List(in.Path, maxEntries)
	if err != nil {
		b.writeError(w, r, http.StatusBadRequest, b.redactErr(r.Context(), err).Error())
		return
	}
	if err := b.live(tok); err != nil {
		b.checkError(w, r, err)
		return
	}
	if len(entries) > reserved {
		b.writeError(w, r, http.StatusTooManyRequests, ErrSessionBudget.Error())
		return
	}
	b.settleRows(tok, reserved, len(entries))
	b.writeEnvelope(w, r, tok, entries, len(entries))
}

// handleWorkspaceRead reads one workspace file, capped by policy budgets.
// It reserves exactly 1 row before reading (deny when no headroom); the
// admitted read stays billed even on read/output failure.
func (b *Broker) handleWorkspaceRead(w http.ResponseWriter, r *http.Request) {
	tok, ok := b.authorize(w, r)
	if !ok {
		return
	}
	if !b.workspaceAllowed(w, r) {
		b.release(tok)
		return
	}
	var in struct {
		Path string `json:"path"`
	}
	if !b.decodeBody(w, r, &in) {
		b.release(tok)
		return
	}
	ws := b.workspace()
	if ws == nil {
		b.writeError(w, r, http.StatusServiceUnavailable, "workspace unavailable")
		b.release(tok)
		return
	}
	reserved, err := b.reserveForLimit(tok, 1)
	if b.checkError(w, r, err) {
		b.release(tok)
		return
	}
	b.mu.Lock()
	maxBytes := b.pol.Budgets.MaxResponseBytes
	b.mu.Unlock()
	if maxBytes <= 0 {
		maxBytes = maxBodyBytes
	}
	data, err := ws.Read(in.Path, maxBytes)
	if err != nil {
		b.writeError(w, r, http.StatusBadRequest, b.redactErr(r.Context(), err).Error())
		return
	}
	if err := b.live(tok); err != nil {
		b.checkError(w, r, err)
		return
	}
	b.settleRows(tok, reserved, 1)
	b.writeEnvelope(w, r, tok, map[string]any{"path": in.Path, "content": string(data)}, 1)
}

// handleWorkspaceWrite writes one workspace file (0600, atomic rename).
func (b *Broker) handleWorkspaceWrite(w http.ResponseWriter, r *http.Request) {
	tok, ok := b.authorize(w, r)
	if !ok {
		return
	}
	if !b.workspaceAllowed(w, r) {
		b.release(tok)
		return
	}
	var in struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if !b.decodeBody(w, r, &in) {
		b.release(tok)
		return
	}
	ws := b.workspace()
	if ws == nil {
		b.writeError(w, r, http.StatusServiceUnavailable, "workspace unavailable")
		b.release(tok)
		return
	}
	if err := ws.Write(in.Path, []byte(in.Content)); err != nil {
		b.writeError(w, r, http.StatusBadRequest, b.redactErr(r.Context(), err).Error())
		b.release(tok)
		return
	}
	if err := b.live(tok); err != nil {
		b.checkError(w, r, err)
		return
	}
	b.record(tok, 0)
	b.writeEnvelope(w, r, tok, map[string]any{"path": in.Path, "written": true}, 1)
}

// handleWorkspaceMkdir creates one directory (plus missing parents) inside
// the workspace — the safe parent-creation workflow for tool flows that
// need nested report directories without shell access. Bounded path/size
// via ws.MkdirAll (os.Root-confined, 0700), bills exactly 1 row (reserved
// atomically before creation), and writes through the capped envelope.
func (b *Broker) handleWorkspaceMkdir(w http.ResponseWriter, r *http.Request) {
	tok, ok := b.authorize(w, r)
	if !ok {
		return
	}
	if !b.workspaceAllowed(w, r) {
		b.release(tok)
		return
	}
	var in struct {
		Path string `json:"path"`
	}
	if !b.decodeBody(w, r, &in) {
		b.release(tok)
		return
	}
	ws := b.workspace()
	if ws == nil {
		b.writeError(w, r, http.StatusServiceUnavailable, "workspace unavailable")
		b.release(tok)
		return
	}
	reserved, err := b.reserveForLimit(tok, 1)
	if b.checkError(w, r, err) {
		b.release(tok)
		return
	}
	if err := ws.MkdirAll(in.Path); err != nil {
		b.writeError(w, r, http.StatusBadRequest, b.redactErr(r.Context(), err).Error())
		return
	}
	if err := b.live(tok); err != nil {
		b.checkError(w, r, err)
		return
	}
	b.settleRows(tok, reserved, 1)
	b.writeEnvelope(w, r, tok, map[string]any{"path": in.Path, "created": true}, 1)
}

// workspaceAllowed denies when the sealed policy disables the workspace.
func (b *Broker) workspaceAllowed(w http.ResponseWriter, r *http.Request) bool {
	b.mu.Lock()
	allow := b.pol.AllowWorkspace
	b.mu.Unlock()
	if !allow {
		b.writeError(w, r, http.StatusForbidden, "denied: workspace disabled")
		return false
	}
	return true
}

// workspace returns the os.Root-confined workspace (nil until Serve or tests).
func (b *Broker) workspace() *workspace.Workspace {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ws
}
