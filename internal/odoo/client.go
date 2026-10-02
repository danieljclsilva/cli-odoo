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
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/kolo/xmlrpc"

	"github.com/danieljclsilva/cli-odoo/internal/config"
)

const (
	maxJSONResponseBytes = 10 << 20
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
			Timeout:   timeout,
			Transport: baseTransport,
		},
	}

	if transport == "json2" {
		c.jsonBase = base + "/api/v2"
		if _, err := c.jsonCall("/res.users/context_get", map[string]any{"args": []any{}, "kwargs": map[string]any{}}); err != nil {
			return nil, err
		}
		return c, nil
	}

	rt := timeoutRoundTripper{rt: baseTransport, d: timeout}
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
	return c, nil
}

// Execute calls model.method via execute_kw (xmlrpc) or POST
// {base}/{model}/{method} (json2). When Lang is configured it is injected
// as context.lang. Credentials are never included in returned errors.
// The client is read-only: only allowlisted read methods execute; any other
// method is refused before any RPC is sent. There is no write path.
func (c *Client) Execute(model, method string, args []any, kwargs map[string]any) (any, error) {
	if !IsReadOnlyMethod(method) {
		return nil, fmt.Errorf("odoo: refusing %s.%s: CLI is read-only (no write request is ever sent)", model, method)
	}
	if args == nil {
		args = []any{}
	}
	kw := map[string]any{}
	for k, v := range kwargs {
		kw[k] = v
	}
	if c.Lang != "" {
		ctx, ok := kw["context"].(map[string]any)
		if !ok {
			ctx = map[string]any{}
		}
		cp := map[string]any{}
		for k, v := range ctx {
			cp[k] = v
		}
		cp["lang"] = c.Lang
		kw["context"] = cp
	}

	if c.Transport == "json2" {
		return c.jsonCall("/"+model+"/"+method, map[string]any{"args": args, "kwargs": kw})
	}
	var out any
	params := []any{c.DB, c.uid, c.secret, model, method, args, kw}
	if err := c.object.Call("execute_kw", params, &out); err != nil {
		return nil, c.sanitizeErr(fmt.Errorf("odoo: %s.%s: %w", model, method, err))
	}
	return out, nil
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
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, c.sanitizeErr(fmt.Errorf("odoo: encode payload: %w", err))
	}
	req, err := http.NewRequest("POST", c.jsonBase+path, bytes.NewReader(body))
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

// normalizeURL trims and ensures a scheme. Bare hosts default to https,
// except local names (localhost, LAN, extensionless) which use http.
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
		h := strings.ToLower(host)
		if h == "localhost" || strings.HasPrefix(h, "127.") || h == "::1" ||
			strings.HasPrefix(h, "[::1]") || strings.HasSuffix(h, ".local") ||
			strings.HasSuffix(h, ".internal") || !strings.Contains(host, ".") {
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
	resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
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
