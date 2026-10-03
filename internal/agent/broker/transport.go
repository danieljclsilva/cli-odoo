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

// AdminSocketPath derives the deterministic admin unix-socket path for a
// model listener addr (e.g. 127.0.0.1:8080 ->
// $TMPDIR/cli-odoo-agent-127-0-0-1-8080.sock). The daemon creates it with
// mode 0600; access control is filesystem-only (same-user posture, see
// package header). Overridable via SetAdminSocket/--socket.
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
	return filepath.Join(os.TempDir(), b.String())
}

// effectiveAdminSocket returns the override or the derived default.
func (b *Broker) effectiveAdminSocket(addr string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.adminSock != "" {
		return b.adminSock
	}
	return AdminSocketPath(addr)
}

// Serve binds the model listener on addr (loopback only) plus the admin
// mux on a 0600 unix socket, and blocks. It resolves the keychain secret
// and dials Odoo once here — never in New. No admin endpoints exist on the
// TCP listener (typed tools + /healthz only).
//
// Serve re-validates the sealed policy and refuses to serve when the
// snapshot disagrees with it (instance identity, exact enabled-company set
// and default): a swapped or mismatched snapshot never reaches credential
// resolution.
func (b *Broker) Serve(addr string) error {
	if err := checkLoopbackAddr(addr); err != nil {
		return err
	}
	b.mu.Lock()
	pol := b.pol
	b.mu.Unlock()
	if err := pol.Validate(); err != nil {
		return fmt.Errorf("broker: invalid policy: %w", err)
	}
	if err := b.checkScopeMatch(); err != nil {
		return err
	}
	b.mu.Lock()
	resolve := b.resolve
	build := b.buildExec
	instName := b.inst.Name
	allowWS := b.pol.AllowWorkspace
	wsDir := b.pol.WorkspaceDir
	b.mu.Unlock()

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

	if allowWS {
		ws, err := workspace.Open(wsDir)
		if err != nil {
			return fmt.Errorf("broker: open workspace: %w", err)
		}
		b.mu.Lock()
		b.ws = ws
		b.mu.Unlock()
	}

	sockPath := b.effectiveAdminSocket(addr)
	_ = os.Remove(sockPath) // stale socket from an unclean exit
	adminLn, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("broker: admin socket: %w", err)
	}
	defer func() {
		_ = adminLn.Close()
		_ = os.Remove(sockPath)
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
	modelErr := modelSrv.ListenAndServe()
	select {
	case err := <-adminErr:
		return fmt.Errorf("broker: admin socket: %w", err)
	default:
		return modelErr
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
			writeRPCError(w, http.StatusMethodNotAllowed, "method not allowed (POST only)")
			return
		}
		h(w, r)
	}
}

func (b *Broker) requireGet(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeRPCError(w, http.StatusMethodNotAllowed, "method not allowed (GET only)")
			return
		}
		h(w, r)
	}
}

// handleHealthz is the only unauthenticated endpoint. No secret, no data.
func (b *Broker) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeRPCOK(w, map[string]any{"ok": true}, 0)
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
func checkError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrSessionUnknown), errors.Is(err, ErrSessionExpired):
		writeRPCError(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, ErrSessionBudget):
		writeRPCError(w, http.StatusTooManyRequests, err.Error())
	default:
		writeRPCError(w, http.StatusUnauthorized, ErrSessionUnknown.Error())
	}
	return true
}

// decodeBody parses exactly one JSON object with unknown fields rejected (so
// a caller-supplied context/CompanyIDs block fails closed) and a 1 MiB cap.
// Trailing bytes beyond one complete object deny (trailing whitespace is
// allowed; a second value, `null`, or garbage is not). A null body into a
// struct denies: the target must stay a JSON object.
func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, "unreadable request body")
		return false
	}
	if int64(len(body)) > maxBodyBytes {
		writeRPCError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return false
	}
	if len(bytes.TrimSpace(body)) == 0 {
		writeRPCError(w, http.StatusBadRequest, "invalid request: empty body")
		return false
	}
	if string(bytes.TrimSpace(body)) == "null" {
		writeRPCError(w, http.StatusBadRequest, "invalid request: null body")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeRPCError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", sanitizeBrokerErr(err)))
		return false
	}
	// Exactly one JSON value: a second decode must hit EOF (trailing
	// whitespace is consumed by Decode, so only real trailing data denies).
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		writeRPCError(w, http.StatusBadRequest, "invalid request: trailing data after JSON object")
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
	if checkError(w, err) {
		return "", false
	}
	if checkError(w, b.Check(tok)) {
		return "", false
	}
	return tok, true
}

// gateMeta authorizes the unscoped discovery surface (meta listing,
// companies, catalog): no model membership, zero paging, no caller company
// selection. It mirrors the Authorize policy-listing branch without
// depending on the injected test gate (fakes are allow-all stubs for the
// data path, not the discovery authz).
func (b *Broker) gateMeta(w http.ResponseWriter) bool {
	b.mu.Lock()
	pol := b.pol
	b.mu.Unlock()
	if !pol.Operations[policy.OpMeta] {
		writeRPCError(w, http.StatusForbidden, "denied: "+policy.ReasonOperationDenied)
		return false
	}
	return true
}

// gate checks the deny-by-default policy for one request. The rule lookup
// uses the normalized model name so padded/case-variant input that the gate
// allowed (NormalizeName trims) resolves to the same sealed rule.
func (b *Broker) gate(w http.ResponseWriter, req policy.Request) (policy.ModelRule, bool) {
	dec := b.gateAuth(req)
	if !dec.Allow {
		writeRPCError(w, http.StatusForbidden, "denied: "+dec.Reason)
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
	if !decodeBody(w, r, &in) {
		b.release(tok)
		return
	}
	limit := in.Limit
	if limit <= 0 {
		limit = defaultSearchLimit()
	}
	rule, ok := b.gate(w, policy.Request{
		Operation: policy.OpSearch, Model: in.Model, Fields: in.Fields,
		Domain: in.Domain, Order: in.Order, Limit: limit, Offset: in.Offset,
	})
	if !ok {
		b.release(tok)
		return
	}
	if !b.enforceable(w, rule) {
		b.release(tok)
		return
	}
	domain, kwargs, err := b.scopedArgs(rule, in.Domain)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, err.Error())
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
	// limit; on success settleRows refunds the unused headroom, on RPC or
	// output failure the attempt keeps its reservation (still billed).
	reserved, err := b.reserveForLimit(tok, limit)
	if checkError(w, err) {
		b.release(tok)
		return
	}
	exec := b.execOf()
	if exec == nil {
		writeRPCError(w, http.StatusServiceUnavailable, "broker not serving")
		b.releaseReserve(tok, reserved)
		return
	}
	res, err := exec.Execute(in.Model, "search_read", nil, kwargs)
	if err != nil {
		writeRPCError(w, http.StatusBadGateway, b.redactErr(r.Context(), err).Error())
		return
	}
	if err := b.live(tok); err != nil {
		checkError(w, err)
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
	if !decodeBody(w, r, &in) {
		b.release(tok)
		return
	}
	if len(in.IDs) == 0 {
		writeRPCError(w, http.StatusBadRequest, "ids is required")
		b.release(tok)
		return
	}
	ids := make([]any, 0, len(in.IDs))
	for _, id := range in.IDs {
		ids = append(ids, id)
	}
	// Never raw read: by-id converts to a scoped search_read so the
	// company fragment still applies to every row.
	rule, ok := b.gate(w, policy.Request{
		Operation: policy.OpRead, Model: in.Model, Fields: in.Fields,
		Domain: []any{[]any{"id", "in", ids}}, Limit: len(ids),
	})
	if !ok {
		b.release(tok)
		return
	}
	if !b.enforceable(w, rule) {
		b.release(tok)
		return
	}
	domain, kwargs, err := b.scopedArgs(rule, []any{[]any{"id", "in", ids}})
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, err.Error())
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
	if checkError(w, err) {
		b.release(tok)
		return
	}
	exec := b.execOf()
	if exec == nil {
		writeRPCError(w, http.StatusServiceUnavailable, "broker not serving")
		b.releaseReserve(tok, reserved)
		return
	}
	res, err := exec.Execute(in.Model, "search_read", nil, kwargs)
	if err != nil {
		writeRPCError(w, http.StatusBadGateway, b.redactErr(r.Context(), err).Error())
		return
	}
	if err := b.live(tok); err != nil {
		checkError(w, err)
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
	if !decodeBody(w, r, &in) {
		b.release(tok)
		return
	}
	// A count returns one scalar; authorize with zero paging.
	rule, ok := b.gate(w, policy.Request{
		Operation: policy.OpCount, Model: in.Model, Domain: in.Domain,
	})
	if !ok {
		b.release(tok)
		return
	}
	domain, kwargs, err := b.scopedArgs(rule, in.Domain)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, err.Error())
		b.release(tok)
		return
	}
	if !b.enforceable(w, rule) {
		b.release(tok)
		return
	}
	exec := b.execOf()
	if exec == nil {
		writeRPCError(w, http.StatusServiceUnavailable, "broker not serving")
		b.release(tok)
		return
	}
	res, err := exec.Execute(in.Model, "search_count", []any{domain}, kwargs)
	if err != nil {
		writeRPCError(w, http.StatusBadGateway, b.redactErr(r.Context(), err).Error())
		return
	}
	if err := b.live(tok); err != nil {
		checkError(w, err)
		return
	}
	b.record(tok, 1)
	b.writeEnvelope(w, r, tok, res, 1)
}

func (b *Broker) handleAggregate(w http.ResponseWriter, r *http.Request) {
	tok, ok := b.authorize(w, r)
	if !ok {
		return
	}
	var in aggregateBody
	if !decodeBody(w, r, &in) {
		b.release(tok)
		return
	}
	if len(in.GroupBy) == 0 {
		writeRPCError(w, http.StatusBadRequest, "groupby is required")
		b.release(tok)
		return
	}
	if len(in.Sum) == 0 && len(in.Avg) == 0 && !in.Count {
		writeRPCError(w, http.StatusBadRequest, "at least one of sum, avg, count is required")
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
			writeRPCError(w, http.StatusBadRequest, "invalid groupby entry")
			b.release(tok)
			return
		}
		if suffix != "" {
			for _, r := range suffix {
				if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
					writeRPCError(w, http.StatusBadRequest, "invalid groupby interval")
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
	rule, ok := b.gate(w, policy.Request{
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
		writeRPCError(w, http.StatusBadRequest, err.Error())
		b.release(tok)
		return
	}
	if !b.enforceable(w, rule) {
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
	if checkError(w, err) {
		b.release(tok)
		return
	}
	exec := b.execOf()
	if exec == nil {
		writeRPCError(w, http.StatusServiceUnavailable, "broker not serving")
		b.releaseReserve(tok, reserved)
		return
	}
	res, err := exec.Execute(in.Model, "read_group", []any{domain, fields, gb}, kwargs)
	if err != nil {
		writeRPCError(w, http.StatusBadGateway, b.redactErr(r.Context(), err).Error())
		return
	}
	if err := b.live(tok); err != nil {
		checkError(w, err)
		return
	}
	b.writeRows(w, r, tok, res, reserved)
}

// enforceable is defense in depth behind the policy gate: a scoped model
// (neither company-independent nor companyless-opted) must carry an
// enforceable company fragment, or the request denies even if Authorize
// passed. Never serve no-fragment scoped models.
func (b *Broker) enforceable(w http.ResponseWriter, rule policy.ModelRule) bool {
	if rule.CompanyIndependent {
		if rule.CompanyField != "" {
			// Contradictory (rejected by Validate, denied by Authorize):
			// fail closed here too.
			writeRPCError(w, http.StatusForbidden, "denied: company scope unenforceable for this model")
			return false
		}
		return true
	}
	b.mu.Lock()
	scope := b.pol.Scope
	b.mu.Unlock()
	frag, enforce := b.frag(rule, scope)
	if enforce && len(frag) == 0 {
		writeRPCError(w, http.StatusForbidden, "denied: company scope unenforceable for this model")
		return false
	}
	if !enforce {
		writeRPCError(w, http.StatusForbidden, "denied: company scope unenforceable for this model")
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
		rule, ok := b.gate(w, policy.Request{Operation: policy.OpMeta, Model: model})
		if !ok {
			b.release(tok)
			return
		}
		if err := b.live(tok); err != nil {
			checkError(w, err)
			return
		}
		b.record(tok, 0)
		b.writeEnvelope(w, r, tok, map[string]any{
			"model": model, "fields": rule.Fields,
			"max_limit": rule.MaxLimit, "allow_aggregate": rule.AllowAggregate,
		}, len(rule.Fields))
		return
	}
	if !b.gateMeta(w) {
		b.release(tok)
		return
	}
	if err := b.live(tok); err != nil {
		checkError(w, err)
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
	if !b.gateMeta(w) {
		b.release(tok)
		return
	}
	if err := b.live(tok); err != nil {
		checkError(w, err)
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
func (b *Broker) handleCatalog(w http.ResponseWriter, r *http.Request) {
	tok, ok := b.authorize(w, r)
	if !ok {
		return
	}
	if !b.gateMeta(w) {
		b.release(tok)
		return
	}
	if err := b.live(tok); err != nil {
		checkError(w, err)
		return
	}
	b.mu.Lock()
	models := make(map[string]any, len(b.snap.Models)+len(b.pol.Models))
	for name, meta := range b.snap.Models {
		_, exec := b.pol.Models[name]
		fields := make(map[string]any, len(meta.Fields))
		for fname, f := range meta.Fields {
			fields[fname] = map[string]any{
				"type": f.Type, "relation": f.Relation,
				"label": f.Label, "provenance": meta.Provenance,
			}
		}
		models[name] = map[string]any{
			"label": meta.Label, "provenance": meta.Provenance,
			"executable": exec, "fields": fields,
		}
	}
	for name, rule := range b.pol.Models {
		if _, seen := models[name]; seen {
			continue
		}
		fields := make(map[string]any, len(rule.Fields))
		for _, fname := range rule.Fields {
			fields[fname] = map[string]any{
				"type": "", "relation": "", "label": fname,
				"provenance": "unknown",
			}
		}
		models[name] = map[string]any{
			"label": name, "provenance": "unknown",
			"executable": true, "fields": fields,
		}
	}
	b.mu.Unlock()
	b.record(tok, 0)
	b.writeEnvelope(w, r, tok, map[string]any{"models": models}, len(models))
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

// writeRows caps rows (MaxRowsPerCall), settles the pre-RPC row reservation
// (refunding unused headroom), and writes the success envelope through the
// single MaxResponseBytes envelope cap. Row-trimming for the byte cap
// happens BEFORE settle so the session keeps only delivered rows; an RPC
// success that yields zero deliverable rows still bills the admitted call
// (Check reservation stands, no release). Any output that cannot fit the
// envelope denies instead of sending a partial payload.
func (b *Broker) writeRows(w http.ResponseWriter, r *http.Request, tok string, res any, reserved int) {
	rows, ok := toSlice(res)
	if !ok {
		writeRPCError(w, http.StatusBadGateway, "unexpected result shape")
		return
	}
	b.mu.Lock()
	maxRows := b.pol.Budgets.MaxRowsPerCall
	b.mu.Unlock()
	if maxRows > 0 && len(rows) > maxRows {
		rows = rows[:maxRows]
	}
	if len(rows) > reserved {
		rows = rows[:reserved]
	}
	for len(rows) > 0 {
		n, err := json.Marshal(map[string]any{"success": true, "result": rows, "count": len(rows)})
		if err != nil {
			writeRPCError(w, http.StatusInternalServerError, "encode response")
			return
		}
		b.mu.Lock()
		maxBytes := b.pol.Budgets.MaxResponseBytes
		b.mu.Unlock()
		if maxBytes <= 0 || len(n) <= maxBytes {
			break
		}
		rows = rows[:len(rows)-1]
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
	n, err := json.Marshal(map[string]any{"success": true, "result": result, "count": count})
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, "encode response")
		return
	}
	b.mu.Lock()
	maxBytes := b.pol.Budgets.MaxResponseBytes
	b.mu.Unlock()
	if maxBytes > 0 && len(n) > maxBytes {
		writeRPCError(w, http.StatusBadGateway, fmt.Sprintf("response %d bytes exceeds cap %d", len(n), maxBytes))
		return
	}
	writeRPCOK(w, result, count)
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
	if !decodeBody(w, r, &in) {
		return
	}
	ttl := time.Duration(in.TTLSeconds) * time.Second
	if in.TTLSeconds <= 0 {
		writeRPCError(w, http.StatusBadRequest, "ttl_seconds must be positive")
		return
	}
	tok, err := b.Grant(ttl)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeRPCOK(w, map[string]any{"token": tok, "ttl_seconds": in.TTLSeconds}, 1)
}

// handleAdminRevoke revokes by full token or unambiguous prefix carried in
// {"token": ...} or {"prefix": ...}. Unknown or ambiguous prefixes fail
// without revoking anything. Never on TCP.
func (b *Broker) handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token  string `json:"token"`
		Prefix string `json:"prefix"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	target := in.Token
	if target == "" {
		target = in.Prefix
	}
	if target == "" {
		writeRPCError(w, http.StatusBadRequest, "token or prefix is required")
		return
	}
	if in.Token != "" {
		if !b.hasSession(target) {
			writeRPCError(w, http.StatusNotFound, ErrSessionUnknown.Error())
			return
		}
		b.Revoke(target)
		writeRPCOK(w, map[string]any{"revoked": true}, 1)
		return
	}
	if err := b.revokePrefix(target); err != nil {
		if errors.Is(err, ErrSessionUnknown) {
			writeRPCError(w, http.StatusNotFound, err.Error())
			return
		}
		writeRPCError(w, http.StatusConflict, err.Error())
		return
	}
	writeRPCOK(w, map[string]any{"revoked": true}, 1)
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
func (b *Broker) handleAdminStatus(w http.ResponseWriter, _ *http.Request) {
	n, ttls, version, instance := b.sessionStats()
	writeRPCOK(w, map[string]any{
		"sessions": n, "expires_in_seconds": ttls,
		"policy_version": version, "instance": instance,
	}, n)
}

// ---------------------------------------------------------------------------
// Workspace handlers (model TCP, gated by policy.AllowWorkspace).
// ---------------------------------------------------------------------------

// handleWorkspaceList lists workspace entries (broker-confined reads).
// Caller max_entries can only narrow the policy row cap, never widen it:
// effective = min(caller-or-default, MaxRowsPerCall).
func (b *Broker) handleWorkspaceList(w http.ResponseWriter, r *http.Request) {
	tok, ok := b.authorize(w, r)
	if !ok {
		return
	}
	if !b.workspaceAllowed(w) {
		b.release(tok)
		return
	}
	var in struct {
		Path       string `json:"path"`
		MaxEntries int    `json:"max_entries"`
	}
	if !decodeBody(w, r, &in) {
		b.release(tok)
		return
	}
	ws := b.workspace()
	if ws == nil {
		writeRPCError(w, http.StatusServiceUnavailable, "workspace unavailable")
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
	entries, err := ws.List(in.Path, maxEntries)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, b.redactErr(r.Context(), err).Error())
		b.release(tok)
		return
	}
	if err := b.live(tok); err != nil {
		checkError(w, err)
		return
	}
	b.record(tok, len(entries))
	b.writeEnvelope(w, r, tok, entries, len(entries))
}

// handleWorkspaceRead reads one workspace file, capped by policy budgets.
func (b *Broker) handleWorkspaceRead(w http.ResponseWriter, r *http.Request) {
	tok, ok := b.authorize(w, r)
	if !ok {
		return
	}
	if !b.workspaceAllowed(w) {
		b.release(tok)
		return
	}
	var in struct {
		Path string `json:"path"`
	}
	if !decodeBody(w, r, &in) {
		b.release(tok)
		return
	}
	ws := b.workspace()
	if ws == nil {
		writeRPCError(w, http.StatusServiceUnavailable, "workspace unavailable")
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
		writeRPCError(w, http.StatusBadRequest, b.redactErr(r.Context(), err).Error())
		b.release(tok)
		return
	}
	if err := b.live(tok); err != nil {
		checkError(w, err)
		return
	}
	b.record(tok, 1)
	b.writeEnvelope(w, r, tok, map[string]any{"path": in.Path, "content": string(data)}, 1)
}

// handleWorkspaceWrite writes one workspace file (0600, atomic rename).
func (b *Broker) handleWorkspaceWrite(w http.ResponseWriter, r *http.Request) {
	tok, ok := b.authorize(w, r)
	if !ok {
		return
	}
	if !b.workspaceAllowed(w) {
		b.release(tok)
		return
	}
	var in struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if !decodeBody(w, r, &in) {
		b.release(tok)
		return
	}
	ws := b.workspace()
	if ws == nil {
		writeRPCError(w, http.StatusServiceUnavailable, "workspace unavailable")
		b.release(tok)
		return
	}
	if err := ws.Write(in.Path, []byte(in.Content)); err != nil {
		writeRPCError(w, http.StatusBadRequest, b.redactErr(r.Context(), err).Error())
		b.release(tok)
		return
	}
	if err := b.live(tok); err != nil {
		checkError(w, err)
		return
	}
	b.record(tok, 0)
	b.writeEnvelope(w, r, tok, map[string]any{"path": in.Path, "written": true}, 1)
}

// workspaceAllowed denies when the sealed policy disables the workspace.
func (b *Broker) workspaceAllowed(w http.ResponseWriter) bool {
	b.mu.Lock()
	allow := b.pol.AllowWorkspace
	b.mu.Unlock()
	if !allow {
		writeRPCError(w, http.StatusForbidden, "denied: workspace disabled")
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

// ---------------------------------------------------------------------------
// JSON envelopes (mirror output.Envelope shape for agent consumers).
// ---------------------------------------------------------------------------

func writeRPCOK(w http.ResponseWriter, result any, count int) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true, "result": result, "count": count,
	})
}

func writeRPCError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": false, "error": msg,
	})
}
