package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/danieljclsilva/cli-odoo/internal/agent/policy"
	"github.com/danieljclsilva/cli-odoo/internal/agent/snapshot"
	"github.com/danieljclsilva/cli-odoo/internal/agent/workspace"
	"github.com/danieljclsilva/cli-odoo/internal/config"
)

// Session errors. Messages are generic on purpose: they never echo the
// token, the policy, or credentials.
var (
	// ErrSessionUnknown is returned for missing or revoked tokens.
	ErrSessionUnknown = errors.New("broker: unknown or revoked session token")
	// ErrSessionExpired is returned for past-expiry tokens.
	ErrSessionExpired = errors.New("broker: session token expired")
	// ErrSessionBudget is returned when a session exhausted its budgets.
	ErrSessionBudget = errors.New("broker: session budget exhausted")
)

// maxLiveSessions caps the session table. Grant evicts the
// earliest-expiring session when full so the table cannot grow without
// bound; eviction is deterministic (never random).
const maxLiveSessions = 64

// defaultInflightLimit bounds concurrent admitted RPC dispatches when the
// policy carries no usable concurrency signal. It is deliberately small:
// each in-flight call may hold a full row reservation plus an upstream
// connection, so unbounded fan-out would let one session exhaust both.
const defaultInflightLimit = 8

// defaultRPCTimeout bounds one admitted Execute call. Context-aware
// executors (see ctxExecutor) enforce it by cancelling the upstream call;
// legacy executors run under a timeout wrapper in callExec (see below).
const defaultRPCTimeout = 30 * time.Second

// inflightLimit derives the dispatch semaphore capacity from validated
// Policy.Budgets centrally: MaxCallsPerSession, when positive, caps the
// useful concurrency (more in-flight calls than session calls can never be
// admitted anyway); otherwise the small default applies. Invalid budgets
// cannot reach here — New rejects them via pol.Validate — so there is no
// second budget-validation path to drift.
func inflightLimit(p *policy.Policy) int {
	if p != nil && p.Budgets.MaxCallsPerSession > 0 && p.Budgets.MaxCallsPerSession < defaultInflightLimit {
		return int(p.Budgets.MaxCallsPerSession)
	}
	return defaultInflightLimit
}

// rpcTimeoutFor derives the per-RPC bound. There is currently no separate
// timeout budget in Policy.Budgets (frozen cross-slice contract), so the
// broker applies the fixed default; a future Budgets.MaxRPCSeconds field
// would be read here, centrally, with invalid values rejected by Validate.
func rpcTimeoutFor(_ *policy.Policy) time.Duration {
	return defaultRPCTimeout
}

// setInflightForTest replaces the semaphore capacity (tests only).
func (b *Broker) setInflightForTest(n int) {
	if n < 1 {
		n = 1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.inflight = make(chan struct{}, n)
}

// tryAcquireInflight takes one dispatch slot without blocking. False means
// the mux is saturated: the caller denies 429 and releases its Check
// reservation (no RPC ran, nothing billed beyond the rollback).
func (b *Broker) tryAcquireInflight() bool {
	b.mu.Lock()
	ch := b.inflight
	b.mu.Unlock()
	if ch == nil {
		return true
	}
	select {
	case ch <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseInflight frees one dispatch slot.
func (b *Broker) releaseInflight() {
	b.mu.Lock()
	ch := b.inflight
	b.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case <-ch:
	default:
	}
}

// rpcTimeoutOf reads the per-RPC bound.
func (b *Broker) rpcTimeoutOf() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.rpcTimeout <= 0 {
		return defaultRPCTimeout
	}
	return b.rpcTimeout
}

// execResult carries one Execute outcome across the legacy timeout wrapper.
type execResult struct {
	res any
	err error
}

// ctxExecutor is the context-aware execution seam. *odoo.Client implements
// it via ExecuteContext (cancellation aborts the upstream HTTP call); fakes
// and future executors that only implement Execute run under the legacy
// wrapper in callExec with the dispatch slot retained until the actual
// Execute returns.
type ctxExecutor interface {
	ExecuteContext(ctx context.Context, model, method string, args []any, kwargs map[string]any) (any, error)
}

// callExec runs one admitted Execute under the request context plus the
// per-RPC timeout. Context-aware executors receive the derived ctx
// directly, so expiry/cancel aborts the upstream call — no orphan
// goroutine, no accumulation beyond the inflight bound. Legacy executors
// (Execute only) run in a child goroutine; the caller in dispatchExec
// retains the dispatch slot until that goroutine actually returns, so a
// timed-out call still occupies its slot instead of admitting unbounded
// replacement work. Either way the admitted reservation stays billed (the
// dispatch was admitted). A nil executor, nil request context, or an
// already-cancelled context fails closed before any dispatch.
func (b *Broker) callExec(ctx context.Context, exec executor, model, method string, args []any, kwargs map[string]any) (any, error) {
	if exec == nil {
		return nil, errBrokerNotServing
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	timeout := b.rpcTimeoutOf()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if ce, ok := exec.(ctxExecutor); ok {
		return ce.ExecuteContext(ctx, model, method, args, kwargs)
	}
	done := make(chan execResult, 1)
	go func() {
		res, err := exec.Execute(model, method, args, kwargs)
		select {
		case done <- execResult{res, err}:
		case <-ctx.Done():
		}
	}()
	select {
	case out := <-done:
		return out.res, out.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// errBrokerNotServing reports a missing executor (nil until Serve builds it).
var errBrokerNotServing = errors.New("broker not serving")

// dispatchExec is the single admitted-dispatch path for RPC handlers: it
// takes one in-flight slot (deny 429 when saturated), runs callExec with
// the request context, and frees the slot only when no actual Execute is
// outstanding. Context-aware executors return with the upstream call
// already aborted, so the deferred release is exact. Legacy executors may
// still be running after callExec reports a timeout: then the release is
// transferred to the late goroutine, which frees the slot on actual
// completion — saturated requests keep denying 429 until real work
// drains, so repeated cancel/block attempts cannot accumulate outstanding
// goroutines beyond the bound. Reserved rows are owned by the caller: on
// semaphore denial the caller rolls back via releaseReserve (no RPC ran);
// on dispatch (success or failure) the reservation stays billed and the
// slot frees only after actual completion.
func (b *Broker) dispatchExec(r *http.Request, model, method string, args []any, kwargs map[string]any) (any, error) {
	exec := b.execOf()
	if exec == nil {
		return nil, errBrokerNotServing
	}
	var ctx context.Context
	if r != nil {
		ctx = r.Context()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, ok := exec.(ctxExecutor); ok {
		// Cancellation aborts the upstream call inside ExecuteContext:
		// no late goroutine can outlive the return.
		if !b.tryAcquireInflight() {
			return nil, ErrSessionBudget
		}
		defer b.releaseInflight()
		return b.callExec(ctx, exec, model, method, args, kwargs)
	}
	// Legacy executor: retain semaphore ownership until the actual
	// Execute returns. The select below reports the timeout to the
	// caller while the worker goroutine is still running; the slot is
	// freed by the reaper when Execute finally returns (fast path
	// releases synchronously before returning).
	if !b.tryAcquireInflight() {
		return nil, ErrSessionBudget
	}
	done := make(chan execResult, 1)
	finished := make(chan struct{})
	timeout := b.rpcTimeoutOf()
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	go func() {
		defer close(finished)
		res, err := exec.Execute(model, method, args, kwargs)
		select {
		case done <- execResult{res, err}:
		case <-callCtx.Done():
		}
	}()
	select {
	case out := <-done:
		<-finished
		b.releaseInflight()
		return out.res, out.err
	case <-callCtx.Done():
		err := callCtx.Err()
		go func() {
			<-finished
			b.releaseInflight()
		}()
		return nil, err
	}
}

// Session is a minted model credential. The token is returned once at
// Grant time; it is never listed again (status exposes counts/expiry only).
type Session struct {
	Token         string
	ExpiresAt     time.Time
	PolicyVersion int
}

// sess is the broker-side session ledger.
type sess struct {
	expires time.Time
	version int
	calls   int64
	rows    int64
}

// executor runs scoped Odoo reads. *odoo.Client satisfies it; protocol
// tests inject a fake.
type executor interface {
	Execute(model, method string, args []any, kwargs map[string]any) (any, error)
}

// authorizer is the policy gate seam. policyGate adapts *policy.Policy;
// protocol tests inject a fake.
type authorizer interface {
	Authorize(schema policy.SchemaView, r policy.Request) policy.Decision
}

// policyGate adapts the deny-by-default policy to the authorizer seam.
type policyGate struct{ p *policy.Policy }

// Authorize denies before any RPC; see package policy.
func (g policyGate) Authorize(s policy.SchemaView, r policy.Request) policy.Decision {
	return g.p.Authorize(s, r)
}

// ServingPaths threads the human-side file locations through New into Serve
// so the serve boundary can bound-check the exact files it serves from and
// confine the workspace against them. Empty fields mean "unknown": Serve
// skips the corresponding file check (in-process tests) and falls back to
// the sealed policy's SnapshotPath and the derived admin socket path.
type ServingPaths struct {
	ProfilePath  string
	SnapshotPath string
	ConfigDir    string
	AdminDir     string
}

// Broker holds the sealed policy in memory and mints revocable session
// tokens. New stores policy and client params only: it never touches the
// keychain and never dials. Serve (human path) resolves the secret and
// builds the Odoo client once.
type Broker struct {
	mu       sync.Mutex
	pol      *policy.Policy
	inst     *config.Instance
	snap     snapshot.Snapshot
	paths    ServingPaths
	sessions map[string]*sess

	// inflight bounds concurrent admitted RPC dispatches (ModelMux
	// half of the budget story). The semaphore capacity derives from
	// Policy.Budgets at New time (see inflightLimit); requests beyond it
	// deny with 429 instead of queueing unboundedly. Tests may replace
	// the channel via setInflightForTest.
	inflight chan struct{}
	// rpcTimeout bounds one admitted Execute call. Context-aware executors
	// (*odoo.Client via ExecuteContext) enforce it by cancelling the
	// upstream HTTP call; legacy executors run under a timeout wrapper in
	// this package (callExec) with the dispatch slot retained until the
	// actual Execute returns (see dispatchExec). An HTTP WriteTimeout alone
	// is insufficient: it bounds the response write, not the upstream call.
	rpcTimeout time.Duration

	authz     authorizer
	exec      executor
	frag      func(policy.ModelRule, policy.CompanyScope) ([]any, bool)
	buildExec func(inst *config.Instance) (executor, error)
	resolve   func(name string) (*config.Instance, error)
	secrets   []string

	adminSock string
	ws        *workspace.Workspace
}

// New stores p and inst without resolving the keychain or dialing Odoo. The
// sealed policy must Validate (central budget/scope/contradiction checks);
// anything invalid fails here so the daemon never serves an undefined
// allowlist. Snapshot-vs-policy scope matching is a Serve-time check (the
// snapshot is compared right before credentials resolve).
//
// The optional ServingPaths (at most one; the first wins) threads the
// human-side file locations into Serve so the serve boundary can bound-check
// the exact profile/snapshot files it serves from and confine the workspace
// against them. Callers without files (in-process tests) omit it.
func New(p *policy.Policy, inst *config.Instance, snap snapshot.Snapshot, paths ...ServingPaths) (*Broker, error) {
	if p == nil {
		return nil, errors.New("broker: nil policy")
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("broker: invalid policy: %w", err)
	}
	if inst == nil {
		return nil, errors.New("broker: nil instance")
	}
	var sp ServingPaths
	if len(paths) > 0 {
		sp = paths[0]
	}
	return &Broker{
		pol:        p,
		inst:       inst,
		snap:       snap,
		paths:      sp,
		sessions:   map[string]*sess{},
		inflight:   make(chan struct{}, inflightLimit(p)),
		rpcTimeout: rpcTimeoutFor(p),
		authz:      policyGate{p: p},
		frag:       policy.CompanyDomain,
		buildExec:  realBuildExec,
		resolve:    config.Resolve,
	}, nil
}

// SetAdminSocket overrides the derived admin unix-socket path (tests and
// --socket). Empty restores the derived default.
func (b *Broker) SetAdminSocket(path string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.adminSock = path
}

// SetWorkspaceForTest injects an os.Root-confined workspace for in-process
// protocol tests (mcpadapter, broker tests) exercising workspace ops
// against the real mux via ModelMuxForTest with AllowWorkspace. Tests own
// the workspace lifetime (Open/Close); Serve overwrites it. Nil clears it
// (workspace unavailable denial).
func (b *Broker) SetWorkspaceForTest(ws *workspace.Workspace) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ws = ws
}

// ModelMuxForTest exposes the loopback model mux for in-process protocol
// tests (mcpadapter, broker tests). It serves the same typed handlers as
// Serve without binding, resolving, or dialing.
func (b *Broker) ModelMuxForTest() http.Handler {
	return b.modelMux()
}

// NewForTest builds a broker with injected gate/exec seams for in-process
// protocol tests (no keychain, no network). The policy still Validate()s.
func NewForTest(p *policy.Policy, inst *config.Instance, snap snapshot.Snapshot, authz authorizer, exec executor, paths ...ServingPaths) (*Broker, error) {
	b, err := New(p, inst, snap, paths...)
	if err != nil {
		return nil, err
	}
	if authz != nil {
		b.authz = authz
	}
	if exec != nil {
		b.exec = exec
	}
	return b, nil
}

// Grant mints a random 256-bit hex session token valid for ttl. The token
// is returned once; only its expiry and counters are retained. ttl is
// clamped to [1m, 24h] so a mis-scoped caller cannot mint an immortal or a
// sub-second session. Live sessions are capped at maxLiveSessions; the
// earliest-expiring session is evicted to make room.
func (b *Broker) Grant(ttl time.Duration) (string, error) {
	if ttl <= 0 {
		return "", errors.New("broker: non-positive session ttl")
	}
	if ttl < time.Minute {
		ttl = time.Minute
	}
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("broker: mint token: %w", err)
	}
	tok := hex.EncodeToString(raw[:])
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.sessions) >= maxLiveSessions {
		// Evict the earliest-expiring session (deterministic, no
		// randomness in which caller loses its credential).
		var oldest string
		var oldestExp time.Time
		first := true
		for k, s := range b.sessions {
			if first || s.expires.Before(oldestExp) {
				oldest, oldestExp, first = k, s.expires, false
			}
		}
		if oldest == "" {
			break
		}
		delete(b.sessions, oldest)
	}
	b.sessions[tok] = &sess{expires: time.Now().Add(ttl), version: b.pol.Version}
	return tok, nil
}

// Revoke drops an exact session token. Unknown tokens are a no-op so
// revoke stays idempotent.
func (b *Broker) Revoke(token string) {
	if token == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.sessions, token)
}

// revokePrefix revokes by full token or unambiguous prefix. Empty, unknown,
// or multi-match prefixes fail without revoking anything.
func (b *Broker) revokePrefix(prefix string) error {
	if prefix == "" {
		return ErrSessionUnknown
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var match string
	n := 0
	for tok := range b.sessions {
		if strings.HasPrefix(tok, prefix) {
			match = tok
			n++
		}
	}
	switch {
	case n == 0:
		return ErrSessionUnknown
	case n > 1:
		return errors.New("broker: token prefix is ambiguous")
	default:
		delete(b.sessions, match)
		return nil
	}
}

// Check enforces expiry, revocation, and session-budget headroom, and
// atomically reserves one call so concurrent requests cannot all pass on
// the last remaining budget and overshoot. The reservation is rolled back
// by release() when the request denies or errors before any RPC billing;
// ReserveRows/settleRows handle the row half (see below). Once an RPC has
// executed, the admitted call stays billed: post-RPC paths never release.
func (b *Broker) Check(token string) error {
	if token == "" {
		return ErrSessionUnknown
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.sessions[token]
	if !ok {
		return ErrSessionUnknown
	}
	if !time.Now().Before(s.expires) {
		delete(b.sessions, token)
		return ErrSessionExpired
	}
	max := b.pol.Budgets.MaxCallsPerSession
	if max > 0 && s.calls >= max {
		return ErrSessionBudget
	}
	maxRows := b.pol.Budgets.MaxRowsPerSession
	if maxRows > 0 && s.rows >= maxRows {
		return ErrSessionBudget
	}
	s.calls++
	return nil
}

// ReserveRows atomically reserves n result rows against
// Budgets.MaxRowsPerSession AFTER a request was admitted (Check) and
// authorized (gate). n is the exact row want: count/workspace-read bill 1,
// read bills len(ids), search/aggregate bill the Authorize-admitted limit.
// Metadata counts (success-envelope "count") never reserve or settle rows:
// only actually dispatched rows (delivered or attempted) consume the row
// budget. The reservation is rolled back ONLY when the RPC never executes
// (releaseReserve); once the RPC has executed the attempted rows stay billed
// even on RPC/output failure (no release-on-failure), with settleRows
// refunding only the unused headroom on success.
func (b *Broker) ReserveRows(token string, n int) error {
	if token == "" {
		return ErrSessionUnknown
	}
	if n < 1 {
		return ErrSessionBudget
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.sessions[token]
	if !ok {
		return ErrSessionUnknown
	}
	if !time.Now().Before(s.expires) {
		delete(b.sessions, token)
		return ErrSessionExpired
	}
	if maxRows := b.pol.Budgets.MaxRowsPerSession; maxRows > 0 {
		if s.rows >= maxRows {
			return ErrSessionBudget
		}
		if int64(n) > maxRows-s.rows {
			return ErrSessionBudget
		}
	}
	s.rows += int64(n)
	return nil
}

// reserveForLimit atomically reserves the REQUESTED want against
// Budgets.MaxRowsPerSession and reports it back. When want exceeds the
// remaining rows it DENIES with ErrSessionBudget — it never silently
// reserves a smaller min while the handler still sends the original want
// (that would under-bill and let sessions overshoot). A non-positive want
// or exhausted budget denies.
func (b *Broker) reserveForLimit(token string, want int) (int, error) {
	if want < 1 {
		return 0, ErrSessionBudget
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.sessions[token]
	if !ok {
		return 0, ErrSessionUnknown
	}
	if !time.Now().Before(s.expires) {
		delete(b.sessions, token)
		return 0, ErrSessionExpired
	}
	if maxRows := b.pol.Budgets.MaxRowsPerSession; maxRows > 0 {
		if rem := maxRows - s.rows; int64(want) > rem {
			return 0, ErrSessionBudget
		}
	}
	s.rows += int64(want)
	return want, nil
}

// release rolls back one Check reservation (deny/error before any row
// reservation and before any RPC).
func (b *Broker) release(token string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if s, ok := b.sessions[token]; ok && s.calls > 0 {
		s.calls--
	}
}

// releaseReserve rolls back one Check reservation plus an n-row ReserveRows
// reservation. Call ONLY when the RPC never executed (decode/gate/scope
// deny, missing executor, over-cap workspace input). Post-RPC paths must
// NOT call this: admitted attempts stay billed.
func (b *Broker) releaseReserve(token string, n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.sessions[token]
	if !ok {
		return
	}
	if s.calls > 0 {
		s.calls--
	}
	s.rows -= int64(n)
	if s.rows < 0 {
		s.rows = 0
	}
}

// settleRows converts an n-row reservation into actual-row billing after a
// successful RPC (actual <= reserved; the unused headroom is refunded).
// Never called on RPC/output failure: the attempt keeps its reservation.
func (b *Broker) settleRows(token string, reserved, actual int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.sessions[token]
	if !ok {
		return
	}
	s.rows += int64(actual - reserved)
	if s.rows < 0 {
		s.rows = 0
	}
}

// live re-checks token validity (expiry + revocation) WITHOUT consuming
// budget. Handlers call it after the RPC before writing the response so
// in-flight work after a revoke/expiry gets a revoked-before-write denial
// (still billed: the Check reservation stands).
func (b *Broker) live(token string) error {
	if token == "" {
		return ErrSessionUnknown
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.sessions[token]
	if !ok {
		return ErrSessionUnknown
	}
	if !time.Now().Before(s.expires) {
		delete(b.sessions, token)
		return ErrSessionExpired
	}
	return nil
}

// record bills one served call (rows = rows actually returned). The call was
// already reserved by Check, so record only adds rows here. Prefer
// ReserveRows/settleRows for row-returning RPC paths; record stays for
// scalar/metadata paths that reserve no rows.
func (b *Broker) record(token string, rows int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if s, ok := b.sessions[token]; ok && rows > 0 {
		s.rows += int64(rows)
	}
}

// checkScopeMatch refuses to serve when the snapshot or the resolved config
// instance disagrees with the sealed policy: config Instance.Name, snapshot
// instance, and the exact company scope (ordered enabled set plus default)
// must match before any credential resolves.
func (b *Broker) checkScopeMatch() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.inst == nil {
		return fmt.Errorf("broker: nil instance")
	}
	if b.inst.Name != b.pol.Instance {
		return fmt.Errorf("broker: config instance %q != policy instance %q", b.inst.Name, b.pol.Instance)
	}
	if b.snap.Instance != b.pol.Instance {
		return fmt.Errorf("broker: snapshot instance %q != policy instance %q", b.snap.Instance, b.pol.Instance)
	}
	if b.snap.DefaultCompany != b.pol.Scope.Default {
		return fmt.Errorf("broker: snapshot default company %d != policy default %d", b.snap.DefaultCompany, b.pol.Scope.Default)
	}
	if len(b.snap.EnabledCompanies) != len(b.pol.Scope.Enabled) {
		return fmt.Errorf("broker: snapshot enabled companies %v != policy scope %v", b.snap.EnabledCompanies, b.pol.Scope.Enabled)
	}
	for i, id := range b.snap.EnabledCompanies {
		if id != b.pol.Scope.Enabled[i] {
			return fmt.Errorf("broker: snapshot enabled companies %v != policy scope %v", b.snap.EnabledCompanies, b.pol.Scope.Enabled)
		}
	}
	return nil
}

// sessionStats returns live-session count plus per-session remaining TTLs
// (counts/expiry only — never tokens).
func (b *Broker) sessionStats() (int, []int64, int, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	ttls := make([]int64, 0, len(b.sessions))
	for _, s := range b.sessions {
		ttls = append(ttls, int64(s.expires.Sub(now)/time.Second))
	}
	return len(b.sessions), ttls, b.pol.Version, b.inst.Name
}
