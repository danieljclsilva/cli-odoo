package broker

import (
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

// Broker holds the sealed policy in memory and mints revocable session
// tokens. New stores policy and client params only: it never touches the
// keychain and never dials. Serve (human path) resolves the secret and
// builds the Odoo client once.
type Broker struct {
	mu       sync.Mutex
	pol      *policy.Policy
	inst     *config.Instance
	snap     snapshot.Snapshot
	sessions map[string]*sess

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
func New(p *policy.Policy, inst *config.Instance, snap snapshot.Snapshot) (*Broker, error) {
	if p == nil {
		return nil, errors.New("broker: nil policy")
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("broker: invalid policy: %w", err)
	}
	if inst == nil {
		return nil, errors.New("broker: nil instance")
	}
	return &Broker{
		pol:       p,
		inst:      inst,
		snap:      snap,
		sessions:  map[string]*sess{},
		authz:     policyGate{p: p},
		frag:      policy.CompanyDomain,
		buildExec: realBuildExec,
		resolve:   config.Resolve,
	}, nil
}

// SetAdminSocket overrides the derived admin unix-socket path (tests and
// --socket). Empty restores the derived default.
func (b *Broker) SetAdminSocket(path string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.adminSock = path
}

// ModelMuxForTest exposes the loopback model mux for in-process protocol
// tests (mcpadapter, broker tests). It serves the same typed handlers as
// Serve without binding, resolving, or dialing.
func (b *Broker) ModelMuxForTest() http.Handler {
	return b.modelMux()
}

// NewForTest builds a broker with injected gate/exec seams for in-process
// protocol tests (no keychain, no network). The policy still Validate()s.
func NewForTest(p *policy.Policy, inst *config.Instance, snap snapshot.Snapshot, authz authorizer, exec executor) (*Broker, error) {
	b, err := New(p, inst, snap)
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
// authorized (gate). n is the effective row want,
// min(limit-effective, remainingRows); n < 1 or no remaining headroom
// denies with ErrSessionBudget. The reservation is rolled back ONLY when
// the RPC never executes (releaseReserve); once the RPC has executed the
// attempted rows stay billed even on RPC/output failure (no
// release-on-failure), with settleRows refunding only the unused headroom
// on success.
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

// reserveForLimit reserves min(want, remainingRows) and reports the
// reserved n. want is the effective per-call row want (already within the
// Authorize-admitted limit); a non-positive want or exhausted row budget
// denies.
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
	n := want
	if maxRows := b.pol.Budgets.MaxRowsPerSession; maxRows > 0 {
		rem := maxRows - s.rows
		if rem < 1 {
			return 0, ErrSessionBudget
		}
		if int64(n) > rem {
			n = int(rem)
		}
	}
	s.rows += int64(n)
	return n, nil
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

// checkScopeMatch refuses to serve when the snapshot disagrees with the
// sealed policy: instance identity and the exact company scope (ordered
// enabled set plus default) must match before any credential resolves.
func (b *Broker) checkScopeMatch() error {
	b.mu.Lock()
	defer b.mu.Unlock()
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
