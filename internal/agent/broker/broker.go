package broker

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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

// New stores p and inst without resolving the keychain or dialing Odoo.
// A malformed policy (nil, wrong version) fails here so the daemon never
// serves an undefined allowlist.
func New(p *policy.Policy, inst *config.Instance, snap snapshot.Snapshot) (*Broker, error) {
	if p == nil {
		return nil, errors.New("broker: nil policy")
	}
	if p.Version != 1 {
		return nil, fmt.Errorf("broker: unsupported policy version %d", p.Version)
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

// Grant mints a random 256-bit hex session token valid for ttl. The token
// is returned once; only its expiry and counters are retained.
func (b *Broker) Grant(ttl time.Duration) (string, error) {
	if ttl <= 0 {
		return "", errors.New("broker: non-positive session ttl")
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("broker: mint token: %w", err)
	}
	tok := hex.EncodeToString(raw[:])
	b.mu.Lock()
	defer b.mu.Unlock()
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
// by release() when the request denies or errors before billing; record()
// converts the reservation into final billing.
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

// release rolls back one Check reservation (deny/error before billing).
func (b *Broker) release(token string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if s, ok := b.sessions[token]; ok && s.calls > 0 {
		s.calls--
	}
}

// record bills one served call (rows = rows actually returned). The call was
// already reserved by Check, so record only adds rows here.
func (b *Broker) record(token string, rows int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if s, ok := b.sessions[token]; ok && rows > 0 {
		s.rows += int64(rows)
	}
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
