// Package mcpadapter exposes the broker's TYPED tools over MCP stdio
// (JSON-RPC 2.0 on stdin/stdout) for runtimes that consume MCP servers.
//
// Typed tools only: search, read, count, aggregate, meta, companies,
// catalog, workspace.list, workspace.read, workspace.write, workspace.mkdir.
// There are no admin, raw, exec, or shell tools: Grant/Revoke never cross
// this surface, and the adapter never spawns a child process.
//
// The catalog tool is a read-only pass-through: the broker serves the
// per-model catalog carrying MethodManifest (informational, never
// executable) plus per-model/per-field provenance, and this adapter
// forwards that envelope to MCP content unchanged.
//
// Auth: the broker session token comes from the ODOO_BROKER_TOKEN
// environment variable (or the configured Token field, e.g. read from
// stdin by the host). The token is sent as an HTTP Bearer header only; it
// is never logged, never echoed in errors, and never placed in model
// output. Broker URL comes from ODOO_BROKER_URL (or BaseURL).
//
// Protocol errors use JSON-RPC error objects. Broker denials surface as
// tool errors (IsError content), not protocol errors.
//
// Transport bounds: one newline-terminated stdio frame per request capped
// at 1 MiB (oversized input gets one ParseError and resynchronizes on the
// next frame, never a repeat-decode loop); one whole broker response body
// capped at 4 MiB (over-cap bodies are denied before any JSON decode, never
// truncated-then-decoded); an encoder failure aborts Serve
// with an error so the host exits non-zero; cancellation flows from Serve
// into every broker request; the broker client never follows redirects and
// only dials loopback http(s); tool arguments are strictly typed
// (unknown/wrong-typed arguments are rejected before dispatch); the session
// token is redacted from every error surface.
//
// Session lifecycle: uninitialized -> awaiting-initialized (after a
// successful initialize response) -> ready (after the
// notifications/initialized notification). tools/list and tools/call
// before ready get a deterministic not-initialized error and never
// dispatch; ping is allowed anytime; initialize is idempotent and
// re-answers deterministically (a repeat while ready stays ready, never
// regresses or widens); a notifications/initialized notification with no
// prior initialize is a no-op.
package mcpadapter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Version is the adapter protocol surface version (not an OMP version).
const Version = "1.0.0"

// maxFrameBytes bounds one stdio JSON-RPC frame (one newline-terminated
// value). Oversized input is rejected with a single ParseError without
// entering a repeat-decode loop.
const maxFrameBytes = 1 << 20 // 1 MiB

// maxDiscardBytes bounds recovery after an over-cap frame: at most this
// many bytes are dropped looking for the next newline before reporting.
const maxDiscardBytes = 8 << 20 // 8 MiB

// maxBrokerResponseBytes bounds one whole broker response body. The body is
// read with a cap+1 limit and rejected before any JSON decode when it
// exceeds the cap, so an unbounded response can never materialize (truncated
// reads would otherwise decode attacker-chosen prefixes as valid).
const maxBrokerResponseBytes = 4 << 20 // 4 MiB

// defaultProtocolVersion is negotiated when the client offers nothing the
// adapter supports.
const defaultProtocolVersion = "2024-11-05"

// supportedVersions lists the MCP protocol versions the adapter negotiates
// on initialize, oldest first. A client offering one of these gets it
// echoed back; anything else (or nothing) gets the default.
var supportedVersions = []string{"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}

// Config carries the broker endpoint and credential. Token is never logged.
type Config struct {
	// BaseURL is the broker model listener, e.g. http://127.0.0.1:8471.
	BaseURL string
	// Token is the broker session token. Prefer env ODOO_BROKER_TOKEN;
	// Config.Token is the explicit override (host-read, e.g. stdin).
	Token string
	// HTTPClient, if nil, defaults to a loopback-only no-redirect client.
	HTTPClient *http.Client
}

// loopbackClient is the default credential-bearing client: 30s timeout and
// no redirect following. Redirects (even loopback-to-loopback) are refused
// before the Authorization header can move: callTool surfaces a tool error
// instead of following, so a compromised or misconfigured broker cannot
// bounce the session token to an attacker-chosen target.
func loopbackClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errRedirectRefused
		},
	}
}

// errRedirectRefused marks a refused redirect: the adapter never follows
// redirects with the session token attached.
var errRedirectRefused = errors.New("mcpadapter: refusing redirect (redirects are not followed)")

// errFrameTooLarge marks an over-cap stdio frame.
var errFrameTooLarge = errors.New("mcpadapter: frame exceeds 1 MiB")

// errFrameDesync marks input that stayed mid-line past maxDiscardBytes:
// recovery cannot resynchronize within bounds, so Serve aborts instead of
// emitting repeat ParseErrors over a stuck desync.
var errFrameDesync = errors.New("mcpadapter: frame exceeds recovery bound")

// Resolve fills BaseURL/Token from the environment when unset:
// ODOO_BROKER_URL (default http://127.0.0.1:8471) and ODOO_BROKER_TOKEN.
func (c Config) Resolve() Config {
	out := c
	if strings.TrimSpace(out.BaseURL) == "" {
		out.BaseURL = strings.TrimSpace(os.Getenv("ODOO_BROKER_URL"))
		if out.BaseURL == "" {
			out.BaseURL = "http://127.0.0.1:8471"
		}
	}
	if out.Token == "" {
		out.Token = strings.TrimSpace(os.Getenv("ODOO_BROKER_TOKEN"))
	}
	if out.HTTPClient == nil {
		out.HTTPClient = loopbackClient()
	}
	return out
}

// rawLoopbackPrechecks rejects smuggled URL structure on the RAW text
// before url.Parse normalizes it away: userinfo ('@' in the authority can
// steer the effective host), query ('?') or fragment ('#') anywhere (they
// can smuggle filter state past a prefix check), and any non-root path
// (only empty or "/" is a bare broker endpoint). Anything else fails
// closed here, before the parse+loopback check below.
func rawLoopbackPrechecks(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" {
		return false
	}
	i := strings.Index(t, "://")
	if i < 0 {
		return false
	}
	rest := t[i+3:]
	auth := rest
	path := ""
	if j := strings.Index(rest, "/"); j >= 0 {
		auth, path = rest[:j], rest[j:]
	}
	if strings.Contains(auth, "@") {
		return false
	}
	if strings.Contains(t, "?") || strings.Contains(t, "#") {
		return false
	}
	if path != "" && path != "/" {
		return false
	}
	return true
}

// isLoopbackURL reports whether raw is an http(s) URL whose host is a
// loopback literal (127.0.0.0/8, ::1 incl. IPv4-in-IPv6) or localhost
// (exact match only: 127.evil.com is NOT loopback). Anything else —
// unparsable, wrong scheme, missing host, non-loopback, userinfo,
// query/fragment, or a non-root path — fails closed.
func isLoopbackURL(raw string) bool {
	if !rawLoopbackPrechecks(raw) {
		return false
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil {
		return false
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return addr.WithZone("").Unmap().IsLoopback()
	}
	return false
}

// validateBaseURL rejects non-loopback broker endpoints before any request
// is built: the session token must never travel beyond the local broker.
// Raw pre-parse checks (userinfo, query/fragment, non-root path) run first;
// the existing parse+loopback check follows.
func validateBaseURL(raw string) error {
	if !rawLoopbackPrechecks(raw) {
		return errors.New("broker URL must be a loopback http(s) URL")
	}
	if !isLoopbackURL(raw) {
		return errors.New("broker URL must be a loopback http(s) URL")
	}
	return nil
}

// Tool describes one typed broker tool on tools/list.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// Tools lists the typed broker tools only. No admin/raw/exec entries.
// workspace.mkdir matches the broker's POST /rpc/workspace/mkdir handler
// (bounded MkdirAll); the catalog output carries MethodManifest plus
// per-field/per-model provenance as read-only pass-through.
func Tools() []Tool {
	obj := func(props map[string]any, required ...string) map[string]any {
		m := map[string]any{"type": "object", "properties": props}
		if len(required) > 0 {
			m["required"] = required
		}
		return m
	}
	str := map[string]any{"type": "string"}
	strs := map[string]any{"type": "array", "items": map[string]any{"type": "string"}}
	num := map[string]any{"type": "integer"}
	boolean := map[string]any{"type": "boolean"}
	domain := map[string]any{}
	return []Tool{
		{Name: "search", Description: "Scoped search_read over an allowlisted model.",
			InputSchema: obj(map[string]any{"model": str, "domain": domain, "fields": strs, "order": str, "limit": num, "offset": num}, "model", "fields")},
		{Name: "read", Description: "Scoped by-id read (converted to search_read server-side).",
			InputSchema: obj(map[string]any{"model": str, "ids": map[string]any{"type": "array", "items": num}, "fields": strs}, "model", "ids", "fields")},
		{Name: "count", Description: "Scoped record count.",
			InputSchema: obj(map[string]any{"model": str, "domain": domain}, "model")},
		{Name: "aggregate", Description: "Scoped read_group aggregation.",
			InputSchema: obj(map[string]any{"model": str, "domain": domain, "groupby": strs, "sum": strs, "avg": strs, "count": boolean, "limit": num}, "model", "groupby")},
		{Name: "meta", Description: "Sealed allowlist metadata (no record data). Optional model query.",
			InputSchema: obj(map[string]any{"model": str})},
		{Name: "companies", Description: "Company discovery: available/enabled/default (no record data).",
			InputSchema: obj(map[string]any{})},
		{Name: "catalog", Description: "Per-model catalog with MethodManifest and provenance (read-only pass-through, no record data).",
			InputSchema: obj(map[string]any{})},
		{Name: "workspace.list", Description: "List broker-confined workspace entries.",
			InputSchema: obj(map[string]any{"path": str, "max_entries": num}, "path")},
		{Name: "workspace.read", Description: "Read one broker-confined workspace file.",
			InputSchema: obj(map[string]any{"path": str}, "path")},
		{Name: "workspace.write", Description: "Write one broker-confined workspace file.",
			InputSchema: obj(map[string]any{"path": str, "content": str}, "path", "content")},
		{Name: "workspace.mkdir", Description: "Create broker-confined workspace directories (bounded MkdirAll).",
			InputSchema: obj(map[string]any{"path": str}, "path")},
	}
}

// rpcRequest is one JSON-RPC 2.0 request. Notifications carry no ID.
type rpcRequest struct {
	JSONRPC string           `json:"jsonrpc"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params"`
	ID      *json.RawMessage `json:"id"`
}

// rpcResponse is one JSON-RPC 2.0 response or error.
type rpcResponse struct {
	JSONRPC string  `json:"jsonrpc"`
	ID      any     `json:"id,omitempty"`
	Result  any     `json:"result,omitempty"`
	Error   *rpcErr `json:"error,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Server adapts typed broker tools to MCP stdio. In and Out default to
// os.Stdin/os.Stdout; tests inject buffers.
type Server struct {
	cfg Config
	In  io.Reader
	Out io.Writer
	// Session lifecycle state: sessionUninitialized -> sessionAwaitInit
	// (after a successful initialize RESPONSE is sent) -> sessionReady
	// (after the notifications/initialized notification). tools/list and
	// tools/call require sessionReady; ping needs nothing; initialize is
	// idempotent. Stored as an atomic int32 so concurrent handler paths
	// observe a monotonic lifecycle without a mutex.
	state atomic.Int32
}

// Session lifecycle states. The order is the lifecycle order: transitions
// move forward only, never backward.
const (
	sessionUninitialized int32 = iota
	sessionAwaitInit
	sessionReady
)

// ready reports whether the session reached ready (initialize response
// sent, then notifications/initialized received).
func (s *Server) ready() bool {
	return s != nil && s.state.Load() == sessionReady
}

// errNotInitialized marks tools/call and tools/list before ready (no
// successful initialize response followed by notifications/initialized yet).
var errNotInitialized = errors.New("mcpadapter: session not initialized (send initialize first)")

// New returns a stdio server bound to cfg (resolved) with process stdio.
func New(cfg Config) *Server {
	return &Server{cfg: cfg.Resolve(), In: os.Stdin, Out: os.Stdout}
}

// readFrame reads one newline-terminated frame, bounded by maxFrameBytes.
// Framing is incremental: fragments are pulled with ReadSlice and appended
// only while the total stays within maxFrameBytes+1, so an unbounded line
// never materializes before the cap check. It returns io.EOF only when no
// bytes remain. An over-cap frame is consumed exactly through its newline
// (the remainder is discarded with ReadSlice, which never consumes past the
// newline, so the next valid frame is preserved) and reported once as
// errFrameTooLarge, so the caller emits one ParseError and resynchronizes
// on the next frame instead of looping on a stuck decoder. A transport
// error is terminal and returned as-is; recovery that finds no newline
// within maxDiscardBytes reports errFrameDesync.
func readFrame(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		frag, err := r.ReadSlice('\n')
		if len(frag) > 0 {
			if len(buf)+len(frag) > maxFrameBytes+1 {
				// Over cap: a newline-terminated fragment means the
				// whole over-cap frame is already consumed exactly;
				// otherwise drop the remainder up to (and including)
				// the newline without touching the frame after it.
				if err == nil {
					return nil, errFrameTooLarge
				}
				if derr := discardRestOfLine(r); derr != nil {
					return nil, derr
				}
				return nil, errFrameTooLarge
			}
			// Copy: frag aliases the reader buffer and is invalidated
			// by the next read.
			buf = append(buf, frag...)
		}
		if err == nil {
			return buf, nil
		}
		if err == bufio.ErrBufferFull {
			if len(frag) == 0 {
				// No progress possible: treat as terminal rather than
				// spin on an unreadable buffer.
				return nil, err
			}
			// Buffer filled without a newline: keep framing within cap.
			continue
		}
		if err == io.EOF {
			if len(buf) > 0 {
				return buf, nil
			}
			return nil, io.EOF
		}
		return nil, err
	}
}

// discardRestOfLine drops bytes up to and including the next newline, EOF,
// a read error, or maxDiscardBytes — bounding recovery from an over-cap
// frame. It consumes exactly through the newline (ReadSlice never reads
// past it), so the next frame starts clean. It returns nil once resync is
// complete (newline or EOF), the transport error when input fails, or
// errFrameDesync when no newline appears within maxDiscardBytes.
func discardRestOfLine(r *bufio.Reader) error {
	dropped := 0
	for dropped < maxDiscardBytes {
		frag, err := r.ReadSlice('\n')
		dropped += len(frag)
		if err == nil {
			return nil
		}
		if err == bufio.ErrBufferFull {
			if len(frag) == 0 {
				return errFrameDesync
			}
			continue
		}
		if err == io.EOF {
			return nil
		}
		return err
	}
	return errFrameDesync
}

// Serve reads newline-framed JSON-RPC 2.0 requests from In and writes
// responses to Out until EOF or cancellation. Each frame is decoded
// independently, so malformed input costs exactly one ParseError and the
// loop continues on the next frame. Notifications get no reply. An output
// (encoder) failure aborts Serve with an error so the host process exits
// non-zero instead of silently dropping responses.
//
// Transport errors are terminal: a failing input reader aborts Serve with
// the error instead of emitting repeat ParseErrors in a tight loop. Only
// over-cap frames (errFrameTooLarge) and malformed JSON recover with one
// ParseError each; input that never resynchronizes (errFrameDesync) aborts.
//
// Cancellation preempts even an idle blocked read: one reader goroutine
// owned by this Serve call feeds whole frames over a rendezvous channel
// while the loop selects on ctx.Done. On abort the input is closed when it
// is an io.Closer (os.Stdin, pipes) so the parked read unblocks and the
// single reader exits — no per-read goroutines, no unbounded leak. The
// initial ctx check fails fast without starting the reader at all.
func (s *Server) Serve(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r := bufio.NewReader(s.In)
	enc := json.NewEncoder(s.Out)
	respond := func(v rpcResponse) error { return enc.Encode(v) }
	// unblock releases a reader parked in input Read on abort paths. It
	// is a no-op for non-closable inputs, where at most the single owned
	// reader stays parked until input arrives or the process exits.
	var unblock func()
	if closer, ok := s.In.(io.Closer); ok {
		unblock = func() { _ = closer.Close() }
	} else {
		unblock = func() {}
	}
	type frameRes struct {
		frame []byte
		err   error
	}
	done := make(chan struct{})
	defer close(done)
	frames := make(chan frameRes)
	go func() {
		for {
			frame, err := readFrame(r)
			select {
			case frames <- frameRes{frame: frame, err: err}:
			case <-done:
				return
			}
			// EOF and terminal transport/desync errors end input: Serve
			// is returning, so no further reads are issued. Successful
			// and over-cap frames recover, so keep framing.
			if err != nil && err != errFrameTooLarge {
				return
			}
		}
	}()
	fail := func(err error) error {
		unblock()
		return err
	}
	for {
		var fr frameRes
		select {
		case <-ctx.Done():
			return fail(ctx.Err())
		case res := <-frames:
			fr = res
		}
		frame, err := fr.frame, fr.err
		if err != nil {
			if err == io.EOF {
				return nil
			}
			if err == errFrameTooLarge || err == errFrameDesync {
				if werr := respond(rpcResponse{JSONRPC: "2.0", Error: &rpcErr{Code: -32700, Message: "parse error"}}); werr != nil {
					return fail(werr)
				}
				if err == errFrameDesync {
					return err
				}
				continue
			}
			// Terminal transport error: return it, never a
			// repeat-ParseError loop on an always-error reader.
			return err
		}
		if len(bytes.TrimSpace(frame)) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(frame, &req); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
			if werr := respond(rpcResponse{JSONRPC: "2.0", Error: &rpcErr{Code: -32700, Message: "parse error"}}); werr != nil {
				return fail(werr)
			}
			continue
		}
		if req.ID == nil {
			s.handleNotification(req.Method, req.Params)
			continue
		}
		var id any
		_ = json.Unmarshal(*req.ID, &id)
		res, rerr := s.handle(ctx, req.Method, req.Params)
		if rerr != nil {
			if werr := respond(rpcResponse{JSONRPC: "2.0", ID: id, Error: rerr}); werr != nil {
				return fail(werr)
			}
			continue
		}
		if werr := respond(rpcResponse{JSONRPC: "2.0", ID: id, Result: res}); werr != nil {
			return fail(werr)
		}
		if req.Method == "initialize" {
			// The session advances to awaiting-initialized only when the
			// initialize RESPONSE was actually sent: a failed encode
			// above returns, so this marks successful handshakes only.
			// A repeat initialize while ready stays ready (monotonic CAS:
			// uninitialized -> awaiting-initialized only).
			s.state.CompareAndSwap(sessionUninitialized, sessionAwaitInit)
		}
	}
}

func (s *Server) handleNotification(method string, _ json.RawMessage) {
	// Only the handshake notification advances the session, and only from
	// awaiting-initialized: an initialized notification with no prior
	// successful initialize RESPONSE is a no-op (stays uninitialized), a
	// repeat while ready stays ready, and every other notification is
	// ignored. Notifications carry no ID and get no reply by JSON-RPC rule.
	if method == "notifications/initialized" {
		if s.state.CompareAndSwap(sessionAwaitInit, sessionReady) {
			return
		}
	}
}

// negotiateVersion validates strict MCP initialize params and resolves the
// protocol version deterministically. Params must be a JSON object;
// protocolVersion must be a present non-empty string. clientInfo and
// capabilities, when present, must be JSON objects per the MCP contract
// (clientInfo carries string name/version when those keys appear). Any
// malformed shape — empty/absent params, a non-object payload, a
// missing/empty/non-string version, or a wrong-typed clientInfo/
// capabilities — rejects with invalid-params and advances nothing (the
// Serve loop only transitions on a sent success response). An unsupported
// but well-typed version string still negotiates the server default —
// never an error, never a widening echo of attacker-chosen text.
func negotiateVersion(params json.RawMessage) (string, *rpcErr) {
	invalid := func() (string, *rpcErr) { return "", &rpcErr{Code: -32602, Message: "invalid params"} }
	if len(bytes.TrimSpace(params)) == 0 {
		return invalid()
	}
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(params))
	if err := dec.Decode(&raw); err != nil || raw == nil {
		return invalid()
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return invalid()
	}
	vraw, ok := raw["protocolVersion"]
	if !ok {
		return invalid()
	}
	var v string
	if err := json.Unmarshal(vraw, &v); err != nil || v == "" {
		return invalid()
	}
	if craw, ok := raw["clientInfo"]; ok {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(craw, &obj); err != nil || obj == nil {
			return invalid()
		}
		for _, key := range []string{"name", "version"} {
			if fraw, ok := obj[key]; ok {
				var fs string
				if err := json.Unmarshal(fraw, &fs); err != nil {
					return invalid()
				}
			}
		}
	}
	if craw, ok := raw["capabilities"]; ok {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(craw, &obj); err != nil || obj == nil {
			return invalid()
		}
	}
	for _, s := range supportedVersions {
		if v == s {
			return v, nil
		}
	}
	return defaultProtocolVersion, nil
}
func (s *Server) handle(ctx context.Context, method string, params json.RawMessage) (any, *rpcErr) {
	switch method {
	case "initialize":
		// Idempotent: every VALID initialize request answers
		// deterministically. The lifecycle advance happens only in Serve
		// after the RESPONSE is sent, so a failed encode never advances
		// the session; a repeat while ready stays ready (the Serve
		// transition only moves uninitialized -> awaiting-initialized).
		// Malformed params reject with invalid-params and advance
		// nothing: the error return skips the Serve transition, so the
		// session stays uninitialized and tools stay gated with zero
		// dispatch. Notifications named "notifications/initialized"
		// carry no ID and never reach here.
		ver, rerr := negotiateVersion(params)
		if rerr != nil {
			return nil, rerr
		}
		return map[string]any{
			"protocolVersion": ver,
			"serverInfo":      map[string]any{"name": "odoo-broker", "version": Version},
			"capabilities":    map[string]any{"tools": map[string]any{}},
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		// Session gate before any listing: not-ready gets one
		// deterministic error and the broker sees zero requests.
		if !s.ready() {
			return nil, &rpcErr{Code: -32002, Message: errNotInitialized.Error()}
		}
		return map[string]any{"tools": Tools()}, nil
	case "tools/call":
		// Session gate comes before any params decode or dispatch: an
		// uninitialized caller gets one deterministic error and the
		// broker sees zero requests.
		if !s.ready() {
			return nil, &rpcErr{Code: -32002, Message: errNotInitialized.Error()}
		}
		var in struct {
			Name      string          `json:"name"`
			Arguments map[string]any  `json:"arguments"`
			Meta      json.RawMessage `json:"_meta"`
		}
		if len(params) > 0 {
			dec := json.NewDecoder(bytes.NewReader(params))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&in); err != nil {
				return nil, &rpcErr{Code: -32602, Message: "invalid params"}
			}
		}
		if strings.TrimSpace(in.Name) == "" {
			return nil, &rpcErr{Code: -32602, Message: "tool name is required"}
		}
		if in.Arguments == nil {
			in.Arguments = map[string]any{}
		}
		if verr := validateArgs(in.Name, in.Arguments); verr != nil {
			return nil, verr
		}
		out, toolErr, perr := s.callTool(ctx, in.Name, in.Arguments)
		if perr != nil {
			return nil, perr
		}
		if toolErr {
			return map[string]any{"content": []any{map[string]any{"type": "text", "text": out}}, "isError": true}, nil
		}
		return map[string]any{"content": []any{map[string]any{"type": "text", "text": out}}}, nil
	default:
		return nil, &rpcErr{Code: -32601, Message: fmt.Sprintf("unknown method %q", method)}
	}
}

// endpoint maps a typed tool name to its broker path and HTTP method.
// Every entry has a live broker counterpart in modelMux: search, read,
// count, aggregate, meta, companies, catalog, workspace.list,
// workspace.read, workspace.write, workspace.mkdir.
func endpoint(name string) (method, path string, ok bool) {
	switch name {
	case "search":
		return http.MethodPost, "/rpc/search", true
	case "read":
		return http.MethodPost, "/rpc/read", true
	case "count":
		return http.MethodPost, "/rpc/count", true
	case "aggregate":
		return http.MethodPost, "/rpc/aggregate", true
	case "meta":
		return http.MethodGet, "/rpc/meta", true
	case "companies":
		return http.MethodGet, "/rpc/companies", true
	case "catalog":
		return http.MethodGet, "/rpc/catalog", true
	case "workspace.list":
		return http.MethodPost, "/rpc/workspace/list", true
	case "workspace.read":
		return http.MethodPost, "/rpc/workspace/read", true
	case "workspace.write":
		return http.MethodPost, "/rpc/workspace/write", true
	case "workspace.mkdir":
		return http.MethodPost, "/rpc/workspace/mkdir", true
	}
	return "", "", false
}

// toolArgTypes is the strict per-tool argument contract: allowed names and
// value kinds. Unknown or wrong-typed arguments are rejected with
// InvalidParams before any broker dispatch. Kinds: "string", "strings"
// (array of string), "int" (integral number), "ints" (array of integral
// numbers), "bool", "any" (the broker policy validates the shape, e.g.
// domain). GET tools take no body, so companies/catalog accept no arguments
// at all and meta accepts only its model query.
var toolArgTypes = map[string]map[string]string{
	"search":          {"model": "string", "domain": "any", "fields": "strings", "order": "string", "limit": "int", "offset": "int"},
	"read":            {"model": "string", "ids": "ints", "fields": "strings"},
	"count":           {"model": "string", "domain": "any"},
	"aggregate":       {"model": "string", "domain": "any", "groupby": "strings", "sum": "strings", "avg": "strings", "count": "bool", "limit": "int"},
	"meta":            {"model": "string"},
	"companies":       {},
	"catalog":         {},
	"workspace.list":  {"path": "string", "max_entries": "int"},
	"workspace.read":  {"path": "string"},
	"workspace.write": {"path": "string", "content": "string"},
	"workspace.mkdir": {"path": "string"},
}

// validateArgs rejects unknown or wrong-typed arguments before dispatch.
// Unknown tools report unknown-tool (matching endpoint); argument violations
// report invalid params.
func validateArgs(name string, args map[string]any) *rpcErr {
	spec, ok := toolArgTypes[name]
	if !ok {
		return &rpcErr{Code: -32601, Message: fmt.Sprintf("unknown tool %q", name)}
	}
	for key, val := range args {
		kind, ok := spec[key]
		if !ok {
			return &rpcErr{Code: -32602, Message: fmt.Sprintf("invalid params: unknown argument %q for tool %q", key, name)}
		}
		if !checkArgKind(kind, val) {
			return &rpcErr{Code: -32602, Message: fmt.Sprintf("invalid params: argument %q for tool %q must be %s", key, name, kind)}
		}
	}
	return nil
}

func checkArgKind(kind string, v any) bool {
	switch kind {
	case "any":
		return true
	case "string":
		_, ok := v.(string)
		return ok
	case "bool":
		_, ok := v.(bool)
		return ok
	case "int":
		return isIntegralNumber(v)
	case "strings":
		arr, ok := v.([]any)
		if !ok {
			return false
		}
		for _, e := range arr {
			if _, ok := e.(string); !ok {
				return false
			}
		}
		return true
	case "ints":
		arr, ok := v.([]any)
		if !ok {
			return false
		}
		for _, e := range arr {
			if !isIntegralNumber(e) {
				return false
			}
		}
		return true
	}
	return false
}

// isIntegralNumber reports whether v is an integral JSON number. MCP
// arguments arrive as float64; integral values pass while fractions,
// NaN/Inf, and non-numbers fail.
func isIntegralNumber(v any) bool {
	var f float64
	switch n := v.(type) {
	case float64:
		f = n
	case float32:
		f = float64(n)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	case json.Number:
		if _, err := n.Int64(); err == nil {
			return true
		}
		return false
	default:
		return false
	}
	if f != f || f > 9e15 || f < -9e15 {
		return false
	}
	return f == float64(int64(f))
}

// redactToken replaces the session token (raw and QueryEscape forms) with
// "***" so credential material can never echo in tool errors. The token
// travels in the Authorization header only; broker or transport text that
// repeats it is scrubbed before it reaches the model.
func (s *Server) redactToken(text string) string {
	tok := s.cfg.Token
	if tok == "" || text == "" {
		return text
	}
	out := strings.ReplaceAll(text, tok, "***")
	if enc := url.QueryEscape(tok); enc != tok {
		out = strings.ReplaceAll(out, enc, "***")
	}
	return out
}

// callTool forwards one typed tool call to the broker model listener
// with the bearer token, and maps the broker envelope to MCP content.
// Returns (text, isToolError, protocolError). Admin/raw names are unknown
// methods, never forwarded.
func (s *Server) callTool(ctx context.Context, name string, args map[string]any) (string, bool, *rpcErr) {
	method, path, ok := endpoint(name)
	if !ok {
		return "", false, &rpcErr{Code: -32601, Message: fmt.Sprintf("unknown tool %q", name)}
	}
	if strings.TrimSpace(s.cfg.Token) == "" {
		return "broker token is not configured", true, nil
	}
	if err := validateBaseURL(s.cfg.BaseURL); err != nil {
		return "broker URL must be a loopback http(s) URL", true, nil
	}
	var body io.Reader
	requestURL := strings.TrimRight(s.cfg.BaseURL, "/") + path
	if method == http.MethodGet {
		// GET tools take no body; meta's optional model query is set
		// through url.Values (QueryEscape) so no raw concatenation can
		// smuggle filter state.
		if name == "meta" {
			if m, _ := args["model"].(string); strings.TrimSpace(m) != "" {
				u, err := url.Parse(requestURL)
				if err != nil {
					return "building broker request failed", true, nil
				}
				q := u.Query()
				q.Set("model", strings.TrimSpace(m))
				u.RawQuery = q.Encode()
				requestURL = u.String()
			}
		}
	} else {
		b, err := json.Marshal(args)
		if err != nil {
			return "invalid arguments", true, nil
		}
		if len(b) > 1<<20 {
			return "arguments exceed 1 MiB", true, nil
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, requestURL, body)
	if err != nil {
		return "building broker request failed", true, nil
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Token travels only in the Authorization header; it is never logged,
	// never echoed in errors, and never placed in tool output.
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	client := s.cfg.HTTPClient
	if client == nil {
		client = loopbackClient()
	}
	res, err := client.Do(req)
	if err != nil {
		if errors.Is(err, errRedirectRefused) {
			return "broker refused redirect (redirects are not followed)", true, nil
		}
		return "broker unreachable", true, nil
	}
	defer res.Body.Close()
	// Whole-response bound, checked BEFORE any JSON decode: read cap+1 and
	// deny when the body exceeds the cap, so a valid-prefix-plus-trailing-
	// bytes over-cap body (success or error envelope) is rejected instead
	// of decoding its attacker-chosen prefix as valid.
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBrokerResponseBytes+1))
	if err != nil {
		return "reading broker response failed", true, nil
	}
	if len(raw) > maxBrokerResponseBytes {
		return "broker response exceeds 4 MiB", true, nil
	}
	var env struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
		Count   int             `json:"count"`
		Error   string          `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return "broker response is not valid", true, nil
	}
	if !env.Success {
		msg := strings.TrimSpace(env.Error)
		if msg == "" {
			msg = "broker denied the request"
		}
		return s.redactToken(msg), true, nil
	}
	out := strings.TrimSpace(string(env.Result))
	if out == "" || out == "null" {
		out = "{}"
	}
	return out, false, nil
}
