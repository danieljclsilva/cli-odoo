// Package odoo provides the Odoo RPC client used by every command.
//
// XML-RPC is the default and primary transport (Odoo 16/17 compatible).
// JSON-2 targets Odoo 19+ only and stays opt-in via transport=json2;
// it must never be required for Odoo 17 paths.
package odoo

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/kolo/xmlrpc"

	"github.com/danieljclsilva/cli-odoo/internal/config"
)

const (
	maxJSONResponseBytes = 10 << 20
	maxXMLResponseBytes  = 10 << 20
	maxServerErrorChars  = 500
)

// Client talks to one Odoo instance (read-only).
type Client struct {
	URL       string
	DB        string
	Username  string
	Password  string
	APIKey    string
	Transport string // xmlrpc (default) | json2
	Timeout   time.Duration
	VerifySSL bool
	Lang      string

	uid      int
	secret   string // password, API key fallback; never echoed in errors
	common   *xmlrpc.Client
	object   *xmlrpc.Client
	http     *http.Client
	jsonBase string // json2 endpoint root: {url}/api/v2
	// objectURL is the XML-RPC object endpoint for the context-aware
	// ExecuteContext path (raw POST via c.http with the request context,
	// so cancellation aborts the upstream call). Legacy Execute keeps
	// using c.object (kolo/xmlrpc, no context).
	objectURL string
}

// UID returns the authenticated user id.
func (c *Client) UID() int { return c.uid }

// IsReadOnlyMethod reports whether method is on the read-only allowlist.
// The client is read-only: only allowlisted methods may execute; everything
// else is refused before any RPC. Comparison is case-insensitive on the
// trimmed method name.
func IsReadOnlyMethod(method string) bool {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "search_read", "read", "search_count", "read_group", "fields_get",
		"name_search", "check_access_rights", "version", "context_get":
		return true
	default:
		return false
	}
}

// isValidModelName reports whether model is a safe Odoo technical name
// ([A-Za-z0-9._]+). Execute refuses anything else before any RPC so a
// malicious or mistyped model can never become an XML-RPC parameter or a
// json2 URL path segment.
func isValidModelName(model string) bool {
	if model == "" {
		return false
	}
	for i := range model {
		c := model[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' {
			continue
		}
		return false
	}
	return true
}

// isLoopbackHost reports whether host is a loopback address or name.
// Only loopback ever defaults to cleartext HTTP; every other bare host
// defaults to HTTPS (see normalizeURL).
func isLoopbackHost(host string) bool {
	h := strings.TrimSpace(host)
	// Strip an optional :port suffix, including bracketed IPv6 "[::1]:8069".
	if strings.HasPrefix(h, "[") {
		if i := strings.Index(h, "]:"); i >= 0 {
			h = h[:i+1]
		}
	} else if strings.Count(h, ":") == 1 {
		if i := strings.LastIndex(h, ":"); i >= 0 {
			h = h[:i]
		}
	}
	// Exact hostname match only: a remote DNS name that merely starts
	// with "127." (e.g. 127.erp.example.com) must NOT count as loopback.
	if strings.EqualFold(h, "localhost") {
		return true
	}
	addrStr := h
	if strings.HasPrefix(addrStr, "[") && strings.HasSuffix(addrStr, "]") {
		addrStr = addrStr[1 : len(addrStr)-1]
	}
	// Real IP-literal test: 127.0.0.0/8, ::1, and IPv4-in-IPv6 forms.
	if addr, err := netip.ParseAddr(addrStr); err == nil {
		return addr.WithZone("").Unmap().IsLoopback()
	}
	// Resolver-dependent shorthand is not a parsed IP literal: fail closed.
	return false
}

// warnCleartextHTTP warns when credentials are about to be sent over an
// explicit non-loopback http:// URL. Bare hostnames already default to
// https (see normalizeURL); only an explicit http:// scheme reaches here.
func warnCleartextHTTP(base string) {
	u, err := url.Parse(base)
	if err != nil || u == nil || !strings.EqualFold(u.Scheme, "http") {
		return
	}
	if isLoopbackHost(u.Host) {
		return
	}
	fmt.Fprintf(os.Stderr, "warning: Odoo URL %q uses cleartext HTTP; credentials are sent unencrypted (use https)\n", base)
}

// originKey identifies the exact configured Odoo origin (scheme, host,
// port) with equivalent representations normalized: letter case, default
// ports, IPv6 brackets, and trailing dots compare equal.
type originKey struct {
	scheme string
	host   string
	port   string
}

// originOf normalizes u for origin comparison. An empty port maps to the
// scheme default so https://host and https://host:443 are one origin.
func originOf(u *url.URL) originKey {
	if u == nil {
		return originKey{}
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	port := u.Port()
	if port == "" {
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	return originKey{scheme: scheme, host: host, port: port}
}

// checkRedirectToOrigin is the CheckRedirect policy for credential-bearing
// requests: same-origin redirects are followed (up to Go's default limit of
// 10 hops), anything else (cross-host, cross-port, or scheme downgrade) is
// refused before credentials move.
func checkRedirectToOrigin(origin originKey) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) == 0 {
			return nil
		}
		if originOf(req.URL) != origin {
			return fmt.Errorf("odoo: refusing redirect to %q: cross-origin redirects are blocked to protect credentials", req.URL.Redacted())
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
}

// originGuardRoundTripper is the shared redirect boundary for both
// transports. kolo/xmlrpc builds its own http.Client (default redirect
// policy) around the RoundTripper it is given, so origin enforcement here
// is what protects XML-RPC authenticate/execute_kw; the json2 client
// shares the same guard as its Transport plus checkRedirectToOrigin.
type originGuardRoundTripper struct {
	rt     http.RoundTripper
	origin originKey
}

func (g originGuardRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if originOf(r.URL) != g.origin {
		return nil, fmt.Errorf("odoo: refusing request to %q: off-origin requests are blocked to protect credentials", r.URL.Redacted())
	}
	rt := g.rt
	if rt == nil {
		rt = http.DefaultTransport
	}
	return rt.RoundTrip(r)
}

// New connects to inst and validates credentials.
// XML-RPC authenticates via /xmlrpc/2/common authenticate with
// db/username/password-or-API-key. JSON-2 validates via
// res.users/context_get with a Bearer token.
func New(inst *config.Instance) (*Client, error) {
	if inst == nil {
		return nil, errors.New("no Odoo instance configured")
	}
	base, err := normalizeURL(inst.URL)
	if err != nil {
		return nil, err
	}
	warnCleartextHTTP(base)
	if strings.TrimSpace(inst.DB) == "" {
		return nil, errors.New("no Odoo database configured (set ODOO_DB)")
	}
	if strings.TrimSpace(inst.Username) == "" {
		return nil, errors.New("no Odoo username configured (set ODOO_USERNAME)")
	}
	transport := strings.ToLower(strings.TrimSpace(inst.Transport))
	if transport == "" {
		transport = "xmlrpc"
	}
	if transport != "xmlrpc" && transport != "json2" {
		return nil, fmt.Errorf("unsupported transport %q (want xmlrpc|json2)", inst.Transport)
	}
	secret := inst.Password
	if secret == "" {
		secret = inst.APIKey
	}
	if secret == "" {
		return nil, errors.New("no Odoo credential in keychain (run: odoo login)")
	}
	timeout := time.Duration(inst.TimeoutSecs) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	baseTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !inst.VerifySSL}, //nolint:gosec // user-opt-in via verify_ssl=false
	}

	// Shared credential-redirect boundary: the exact configured origin.
	// Both transports enforce it — c.http via Transport+CheckRedirect,
	// the xmlrpc-owned client via the wrapped RoundTripper (it builds its
	// own http.Client with the default redirect policy).
	baseURL, err := url.Parse(base)
	if err != nil {
		return nil, errors.New("odoo: invalid URL (set ODOO_URL)")
	}
	origin := originOf(baseURL)
	redirectGuard := originGuardRoundTripper{rt: baseTransport, origin: origin}

	c := &Client{
		URL:       base,
		DB:        inst.DB,
		Username:  inst.Username,
		Password:  inst.Password,
		APIKey:    inst.APIKey,
		Transport: transport,
		Timeout:   timeout,
		VerifySSL: inst.VerifySSL,
		Lang:      inst.Lang,
		secret:    secret,
		http: &http.Client{
			Timeout:       timeout,
			Transport:     redirectGuard,
			CheckRedirect: checkRedirectToOrigin(origin),
		},
	}

	if transport == "json2" {
		c.jsonBase = base + "/api/v2"
		if _, err := c.jsonCall("/res.users/context_get", map[string]any{"args": []any{}, "kwargs": map[string]any{}}); err != nil {
			return nil, err
		}
		return c, nil
	}

	rt := timeoutRoundTripper{rt: redirectGuard, d: timeout}
	common, err := xmlrpc.NewClient(base+"/xmlrpc/2/common", rt)
	if err != nil {
		return nil, c.sanitizeErr(fmt.Errorf("odoo: dial common endpoint: %w", err))
	}
	object, err := xmlrpc.NewClient(base+"/xmlrpc/2/object", rt)
	if err != nil {
		return nil, c.sanitizeErr(fmt.Errorf("odoo: dial object endpoint: %w", err))
	}
	var raw any
	if err := common.Call("authenticate", []any{c.DB, c.Username, c.secret, map[string]any{}}, &raw); err != nil {
		return nil, c.sanitizeErr(fmt.Errorf("odoo: authenticate: %w", err))
	}
	uid, ok := coerceInt(raw)
	if !ok || uid == 0 {
		return nil, fmt.Errorf("odoo: authentication failed for user %q on database %q", c.Username, c.DB)
	}
	c.uid = uid
	c.common = common
	c.object = object
	c.objectURL = base + "/xmlrpc/2/object"
	return c, nil
}

// Execute calls model.method via execute_kw (xmlrpc) or POST
// {base}/{model}/{method} (json2). When Lang is configured it is injected
// as context.lang. Credentials are never included in returned errors.
// The client is read-only: only allowlisted read methods execute; any other
// method is refused before any RPC is sent. There is no write path.
// Execute uses context.Background: broker dispatches SHOULD prefer
// ExecuteContext so request cancellation aborts the upstream HTTP call.
func (c *Client) Execute(model, method string, args []any, kwargs map[string]any) (any, error) {
	return c.ExecuteContext(context.Background(), model, method, args, kwargs)
}

// ExecuteContext is the context-aware Execute: model/method validation,
// read-only gating, Lang injection, and response bounds are identical to
// Execute, but the upstream HTTP call carries ctx so cancellation and the
// broker RPC timeout abort the in-flight request instead of abandoning a
// goroutine. XML-RPC posts raw execute_kw via c.http (kolo/xmlrpc has no
// context API); json2 posts via c.http with the request attached to ctx.
func (c *Client) ExecuteContext(ctx context.Context, model, method string, args []any, kwargs map[string]any) (any, error) {
	model = strings.TrimSpace(model)
	method = strings.TrimSpace(method)
	if !isValidModelName(model) {
		return nil, fmt.Errorf("odoo: refusing model %q: must match [A-Za-z0-9._]+", model)
	}
	if !IsReadOnlyMethod(method) {
		return nil, fmt.Errorf("odoo: refusing %s.%s: CLI is read-only (no write request is ever sent)", model, method)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if args == nil {
		args = []any{}
	}
	kw := map[string]any{}
	for k, v := range kwargs {
		kw[k] = v
	}
	if c.Lang != "" {
		oc, ok := kw["context"].(map[string]any)
		if !ok {
			oc = map[string]any{}
		}
		cp := map[string]any{}
		for k, v := range oc {
			cp[k] = v
		}
		cp["lang"] = c.Lang
		kw["context"] = cp
	}

	if c.Transport == "json2" {
		return c.jsonCallContext(ctx, "/"+url.PathEscape(model)+"/"+url.PathEscape(method), map[string]any{"args": args, "kwargs": kw})
	}
	params := []any{c.DB, c.uid, c.secret, model, method, args, kw}
	return c.xmlExecuteContext(ctx, "execute_kw", params, model, method)
}

// ServerVersion returns the server version info (common.version on xmlrpc).
func (c *Client) ServerVersion() (any, error) {
	if c.Transport == "json2" {
		req, err := http.NewRequest("GET", c.jsonBase+"/version", nil)
		if err != nil {
			return nil, c.sanitizeErr(err)
		}
		req.Header.Set("X-Odoo-Database", c.DB)
		req.Header.Set("Authorization", "Bearer "+c.secret)
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, c.sanitizeErr(fmt.Errorf("odoo: version: %w", err))
		}
		defer resp.Body.Close()
		var out any
		if err := decodeJSONCapped(resp.Body, &out); err != nil {
			return nil, c.sanitizeErr(fmt.Errorf("odoo: version: %w", err))
		}
		return out, nil
	}
	var out any
	if err := c.common.Call("version", nil, &out); err != nil {
		return nil, c.sanitizeErr(fmt.Errorf("odoo: version: %w", err))
	}
	return out, nil
}

// UserContext returns res.users context_get for the authenticated user.
func (c *Client) UserContext() (any, error) {
	return c.Execute("res.users", "context_get", nil, nil)
}

// sanitizeErr redacts credentials that may leak into error text
// (URLs, server echoes) before the error reaches output.
func (c *Client) sanitizeErr(err error) error {
	if err == nil {
		return nil
	}
	s := err.Error()
	seen := map[string]struct{}{}
	var secrets []string
	add := func(v string) {
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		secrets = append(secrets, v)
		if dec, derr := url.QueryUnescape(v); derr == nil && dec != "" && dec != v {
			if _, ok := seen[dec]; !ok {
				seen[dec] = struct{}{}
				secrets = append(secrets, dec)
			}
		}
		if dec, derr := url.PathUnescape(v); derr == nil && dec != "" && dec != v {
			if _, ok := seen[dec]; !ok {
				seen[dec] = struct{}{}
				secrets = append(secrets, dec)
			}
		}
		if enc := url.QueryEscape(v); enc != "" && enc != v {
			if _, ok := seen[enc]; !ok {
				seen[enc] = struct{}{}
				secrets = append(secrets, enc)
			}
		}
	}
	for _, sec := range []string{c.Password, c.APIKey, c.secret} {
		add(sec)
	}
	if u, uerr := url.Parse(c.URL); uerr == nil && u != nil && u.User != nil {
		add(u.User.Username())
		if pw, ok := u.User.Password(); ok {
			add(pw)
		}
	}
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	for _, sec := range secrets {
		s = strings.ReplaceAll(s, sec, "***")
	}
	if s == err.Error() {
		return err
	}
	return errors.New(s)
}

// decodeJSONCapped decodes one JSON value while bounding how much of r
// the decoder may consume. Oversized bodies fail instead of allocating
// without bound.
func decodeJSONCapped(r io.Reader, dst any) error {
	lr := &io.LimitedReader{R: r, N: maxJSONResponseBytes + 1}
	if err := json.NewDecoder(lr).Decode(dst); err != nil {
		return err
	}
	if lr.N <= 0 {
		return fmt.Errorf("odoo: response exceeds %d bytes", maxJSONResponseBytes)
	}
	return nil
}

// truncateServerError renders a server-provided error value capped at
// maxServerErrorChars runes so error paths never echo unbounded bodies.
func truncateServerError(v any) string {
	s := fmt.Sprintf("%v", v)
	r := []rune(s)
	if len(r) > maxServerErrorChars {
		return string(r[:maxServerErrorChars]) + "... (truncated)"
	}
	return s
}

func (c *Client) jsonCall(path string, payload any) (any, error) {
	return c.jsonCallContext(context.Background(), path, payload)
}

// jsonCallContext is jsonCall with the request bound to ctx: broker RPC
// timeouts and client cancellations abort the in-flight POST (no orphan
// accumulation), and the response body stays capped by decodeJSONCapped.
func (c *Client) jsonCallContext(ctx context.Context, path string, payload any) (any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, c.sanitizeErr(fmt.Errorf("odoo: encode payload: %w", err))
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.jsonBase+path, bytes.NewReader(body))
	if err != nil {
		return nil, c.sanitizeErr(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.secret)
	req.Header.Set("X-Odoo-Database", c.DB)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, c.sanitizeErr(fmt.Errorf("odoo: %s: %w", path, err))
	}
	defer resp.Body.Close()
	var out any
	if err := decodeJSONCapped(resp.Body, &out); err != nil {
		return nil, c.sanitizeErr(fmt.Errorf("odoo: %s: bad status %d: %w", path, resp.StatusCode, err))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if m, ok := out.(map[string]any); ok {
			if e, ok := m["error"]; ok && e != nil {
				return nil, c.sanitizeErr(fmt.Errorf("odoo: %s: status %d: %s", path, resp.StatusCode, truncateServerError(e)))
			}
		}
		return nil, c.sanitizeErr(fmt.Errorf("odoo: %s: request failed with status %d", path, resp.StatusCode))
	}
	if m, ok := out.(map[string]any); ok {
		if e, ok := m["error"]; ok && e != nil {
			return nil, c.sanitizeErr(fmt.Errorf("odoo: %s: %s", path, truncateServerError(e)))
		}
		if r, ok := m["result"]; ok {
			return r, nil
		}
	}
	return out, nil
}

// xmlExecuteContext posts one XML-RPC method call with the request bound to
// ctx and decodes the response bounded by maxXMLResponseBytes. It mirrors
// kolo/xmlrpc execute_kw wire format (EncodeMethodCall) but bypasses the
// rpc.Client codec, which has no context API: cancellation aborts the HTTP
// round trip and the response read, so no goroutine outlives ctx. The
// origin guard still applies (c.http Transport wraps redirectGuard; the
// default client redirect policy is same-origin-only-safe because any
// cross-origin redirect would re-enter the guard on the next hop).
func (c *Client) xmlExecuteContext(ctx context.Context, rpcMethod string, params []any, model, method string) (any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	endpoint := c.objectURL
	if endpoint == "" {
		return nil, c.sanitizeErr(fmt.Errorf("odoo: %s.%s: xmlrpc object endpoint unavailable", model, method))
	}
	encoded, err := xmlrpc.EncodeMethodCall(rpcMethod, params...)
	if err != nil {
		return nil, c.sanitizeErr(fmt.Errorf("odoo: %s.%s: %w", model, method, err))
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(encoded))
	if err != nil {
		return nil, c.sanitizeErr(err)
	}
	req.Header.Set("Content-Type", "text/xml")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, c.sanitizeErr(fmt.Errorf("odoo: %s.%s: %w", model, method, err))
	}
	defer resp.Body.Close()
	lr := &io.LimitedReader{R: resp.Body, N: maxXMLResponseBytes + 1}
	raw, err := io.ReadAll(lr)
	if err != nil {
		return nil, c.sanitizeErr(fmt.Errorf("odoo: %s.%s: %w", model, method, err))
	}
	if lr.N <= 0 {
		return nil, c.sanitizeErr(fmt.Errorf("odoo: %s.%s: response exceeds %d bytes", model, method, maxXMLResponseBytes))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, c.sanitizeErr(fmt.Errorf("odoo: %s.%s: request error: bad status code - %d", model, method, resp.StatusCode))
	}
	xmlResp := xmlrpc.Response(raw)
	if err := xmlResp.Err(); err != nil {
		return nil, c.sanitizeErr(fmt.Errorf("odoo: %s.%s: %w", model, method, err))
	}
	var out any
	if err := xmlResp.Unmarshal(&out); err != nil {
		return nil, c.sanitizeErr(fmt.Errorf("odoo: %s.%s: %w", model, method, err))
	}
	return out, nil
}

// normalizeURL trims and ensures a scheme. Bare hosts default to https;
// only loopback names/addresses (localhost, 127.x, ::1) use http.
// LAN (.local/.internal) and extensionless names stay on https: sending
// credentials over cleartext outside loopback requires an explicit
// http:// scheme (warned about in New).
func normalizeURL(raw string) (string, error) {
	s := strings.TrimSuffix(strings.TrimSpace(raw), "/")
	if s == "" {
		return "", errors.New("no Odoo URL configured (set ODOO_URL)")
	}
	if !strings.Contains(s, "://") {
		host := s
		if i := strings.Index(host, "/"); i >= 0 {
			host = host[:i]
		}
		if isLoopbackHost(host) {
			s = "http://" + s
		} else {
			s = "https://" + s
		}
	}
	return strings.TrimSuffix(s, "/"), nil
}

func coerceInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case bool:
		return 0, false
	case nil:
		return 0, false
	default:
		return 0, false
	}
}

// timeoutRoundTripper bounds requests made through transports owned by
// third-party clients (kolo/xmlrpc builds its own http.Client).
// The context cancel is tied to the response body lifetime: canceling
// inside RoundTrip (defer cancel) aborts large/slow body reads with
// "context canceled" once headers arrive. Wrapping the body keeps the
// deadline for the full response while releasing resources on Close.
type timeoutRoundTripper struct {
	rt http.RoundTripper
	d  time.Duration
}

func (t timeoutRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(r.Context(), t.d)
	resp, err := t.rt.RoundTrip(r.WithContext(ctx))
	if err != nil {
		cancel()
		return nil, err
	}
	// Bound XML-RPC bodies like the json2 path: hostile or huge server
	// responses fail instead of decoding without bound.
	resp.Body = &cancelBody{ReadCloser: &maxBytesReader{R: resp.Body, N: maxXMLResponseBytes + 1}, cancel: cancel}
	return resp, nil
}

// maxBytesReader errors once more than N bytes are read.
type maxBytesReader struct {
	R io.ReadCloser
	N int64
}

func (r *maxBytesReader) Read(p []byte) (int, error) {
	if r.N <= 0 {
		return 0, fmt.Errorf("odoo: response exceeds %d bytes", maxXMLResponseBytes)
	}
	if int64(len(p)) > r.N {
		p = p[:r.N]
	}
	n, err := r.R.Read(p)
	r.N -= int64(n)
	return n, err
}

func (r *maxBytesReader) Close() error {
	return r.R.Close()
}

// cancelBody releases the request context once the body is consumed.
type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}
