package odoo

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestIsLoopbackHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		// Acceptance cases.
		{"127.erp.example.com", false},
		{"127.0.0.1", true},
		{"127.1", true},
		{"[::1]", true},
		{"localhost", true},
		{"localhost:8069", true},
		{"garbage!!!", false},
		// Wider loopback coverage.
		{"127.0.0.2", true},
		{"127.255.255.255", true},
		{"127.0.0.1:8069", true},
		{"127.1:8069", true},
		{"LOCALHOST", true},
		{" Localhost ", true},
		{"::1", true},
		{"[::1]:8069", true},
		{"::ffff:127.0.0.1", true},
		{"0:0:0:0:0:0:0:1", true},
		{"127.0.0.0", true}, // network address is still a 127/8 literal
		// Must NOT be loopback.
		{"127.erp.example.com:8069", false},
		{"localhost.example.com", false},
		{"localhost.", false}, // trailing dot = DNS search path, not exact name
		{"127.", false},
		{"127.0.0.1.", false},
		{"example.com", false},
		{"10.0.0.1", false},
		{"192.168.1.1", false},
		{"8.8.8.8", false},
		{"", false},
		{"   ", false},
		{"999.999.999.999", false},
		{"256.1.1.1", false},
		{"127.0.0.1.5", false},
		{"1.2.3.4.5", false},
		{"12a.0.0.1", false},
		{"::2", false},
		{"::ffff:8.8.8.8", false},
		{"[::1", false},        // malformed bracket: fail closed
		{"01.02.03.04", false}, // leading zeros: ambiguous octal, fail closed
		{"0177.0.0.1", false},  // octal-looking 127: fail closed
	}
	for _, tc := range cases {
		if got := isLoopbackHost(tc.host); got != tc.want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestNormalizeURLLoopbackVsRemote(t *testing.T) {
	// Remote DNS that merely starts with "127." must default to HTTPS.
	got, err := normalizeURL("127.erp.example.com")
	if err != nil {
		t.Fatalf("normalizeURL: %v", err)
	}
	if got != "https://127.erp.example.com" {
		t.Errorf("normalizeURL(127.erp.example.com) = %q, want https default", got)
	}
	// True loopback still defaults to HTTP.
	for _, raw := range []string{"127.0.0.1:8069", "localhost:8069", "127.1", "[::1]:8069"} {
		got, err := normalizeURL(raw)
		if err != nil {
			t.Fatalf("normalizeURL(%q): %v", raw, err)
		}
		if !strings.HasPrefix(got, "http://") {
			t.Errorf("normalizeURL(%q) = %q, want http default", raw, got)
		}
	}
}

func TestOriginOfEquivalentForms(t *testing.T) {
	mustParse := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		return u
	}
	base := originOf(mustParse("https://ODOO.Example.com/api"))
	for _, same := range []string{
		"https://odoo.example.com:443/other",
		"https://odoo.example.com./x",
		"HTTPS://odoo.example.com/y",
	} {
		if originOf(mustParse(same)) != base {
			t.Errorf("originOf(%q) != origin of base", same)
		}
	}
	for _, diff := range []string{
		"http://odoo.example.com/x",       // downgrade
		"https://odoo.example.com:8443/x", // cross-port
		"https://evil.example.com/x",      // cross-host
		"https://sub.odoo.example.com/x",  // subdomain is a different origin
	} {
		if originOf(mustParse(diff)) == base {
			t.Errorf("originOf(%q) == base, want distinct", diff)
		}
	}
}

// guardedClient builds the same redirect boundary New wires into c.http:
// origin-guarding Transport plus same-origin-only CheckRedirect.
func guardedClient(originURL string) (*http.Client, originKey) {
	u, _ := url.Parse(originURL)
	origin := originOf(u)
	g := originGuardRoundTripper{origin: origin}
	return &http.Client{
		Timeout:       5 * time.Second,
		Transport:     g,
		CheckRedirect: checkRedirectToOrigin(origin),
	}, origin
}

func TestSameOriginRedirectFollowed(t *testing.T) {
	var sawAuthAtTarget bool
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/target", http.StatusFound)
	})
	mux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		sawAuthAtTarget = r.Header.Get("Authorization") == "Bearer s3cret"
		w.Write([]byte(`{}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cli, _ := guardedClient(srv.URL)
	req, _ := http.NewRequest("GET", srv.URL+"/start", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("same-origin redirect should be followed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if !sawAuthAtTarget {
		t.Error("same-origin redirect lost the Authorization header")
	}
}

func TestCrossOriginRedirectBlocked(t *testing.T) {
	var evilHits int
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evilHits++
		w.Write([]byte(`{}`))
	}))
	defer evil.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/steal", http.StatusFound)
	}))
	defer origin.Close()

	cli, _ := guardedClient(origin.URL)
	req, _ := http.NewRequest("GET", origin.URL+"/start", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	_, err := cli.Do(req)
	if err == nil || !strings.Contains(err.Error(), "refusing redirect") {
		t.Fatalf("cross-origin redirect must be refused, got err=%v", err)
	}
	if evilHits != 0 {
		t.Errorf("evil server hit %d times: credentials would have been sent", evilHits)
	}
}

func TestSchemeDowngradeRedirectBlocked(t *testing.T) {
	// No TLS servers needed: the policy compares normalized origins, so a
	// same-host http downgrade target is refused by construction.
	origin := originOf(mustURL(t, "https://odoo.example.com/api"))
	policy := checkRedirectToOrigin(origin)
	downgrade, _ := http.NewRequest("GET", "http://odoo.example.com/api", nil)
	via, _ := http.NewRequest("GET", "https://odoo.example.com/api", nil)
	if err := policy(downgrade, []*http.Request{via}); err == nil {
		t.Error("https -> http downgrade redirect must be refused")
	}
	upgrade, _ := http.NewRequest("GET", "https://odoo.example.com/other", nil)
	if err := policy(upgrade, []*http.Request{via}); err != nil {
		t.Errorf("same-origin redirect must be allowed: %v", err)
	}
}

func TestXMLRPCSharedBoundaryBlocksOffOrigin(t *testing.T) {
	// kolo/xmlrpc builds its own http.Client (default redirect policy)
	// around the RoundTripper New hands it, so enforcement must live in
	// the RoundTripper itself. Mirror that shape: default-policy client
	// over timeoutRoundTripper over the redirect guard.
	var evilHits int
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evilHits++
		w.Write([]byte(`<methodResponse/>`))
	}))
	defer evil.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 307 preserves method+body: the dangerous case for POST creds.
		http.Redirect(w, r, evil.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	ou, _ := url.Parse(origin.URL)
	rt := timeoutRoundTripper{rt: originGuardRoundTripper{origin: originOf(ou)}, d: 5 * time.Second}
	xmlStyle := &http.Client{Transport: rt} // no CheckRedirect, like kolo/xmlrpc

	body := strings.NewReader(`<methodCall><methodName>authenticate</methodName></methodCall>`)
	req, _ := http.NewRequest("POST", origin.URL+"/xmlrpc/2/common", body)
	req.Header.Set("Content-Type", "text/xml")
	_, err := xmlStyle.Do(req)
	if err == nil {
		t.Fatal("xmlrpc-shaped client must not follow cross-origin redirect")
	}
	if evilHits != 0 {
		t.Errorf("evil server hit %d times: credential body would have leaked", evilHits)
	}
}

func TestDirectOffOriginRequestBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	cli, _ := guardedClient("http://127.0.0.1:1")
	_, err := cli.Get(srv.URL + "/api")
	if err == nil || !strings.Contains(err.Error(), "refusing request") {
		t.Fatalf("off-origin direct request must be refused, got err=%v", err)
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return u
}

func TestSameOriginRedirectCycleBounded(t *testing.T) {
	// A same-origin redirect that points at itself must stop at the
	// redirect limit instead of following forever. Direct and single-hop
	// same-origin success stay covered by TestSameOriginRedirectFollowed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer srv.Close()

	cli, _ := guardedClient(srv.URL)
	_, err := cli.Get(srv.URL + "/loop")
	if err == nil || !strings.Contains(err.Error(), "stopped after 10 redirects") {
		t.Fatalf("redirect cycle must stop at the redirect limit, got err=%v", err)
	}
}

func TestCheckRedirectBlocks308OffOriginReplay(t *testing.T) {
	// 308 preserves method+body across the redirect, so a POST with a
	// replayable body is the dangerous case: the CheckRedirect path must
	// refuse before the evil server is ever hit.
	var evilHits int
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evilHits++
		w.Write([]byte(`{}`))
	}))
	defer evil.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/steal", http.StatusPermanentRedirect)
	}))
	defer origin.Close()

	cli, _ := guardedClient(origin.URL)
	body := strings.NewReader(`<methodCall><methodName>authenticate</methodName></methodCall>`)
	req, _ := http.NewRequest("POST", origin.URL+"/xmlrpc/2/common", body)
	req.Header.Set("Content-Type", "text/xml")
	_, err := cli.Do(req)
	if err == nil || !strings.Contains(err.Error(), "refusing redirect") {
		t.Fatalf("308 cross-origin redirect must be refused, got err=%v", err)
	}
	if evilHits != 0 {
		t.Errorf("evil server hit %d times: credential body would have leaked", evilHits)
	}
}

func TestOriginOfIPv6LoopbackForms(t *testing.T) {
	base := originOf(mustURL(t, "http://[::1]:8069/a"))
	for _, same := range []string{
		"http://[::1]:8069/other",
		"HTTP://[::1]:8069/other",
	} {
		if originOf(mustURL(t, same)) != base {
			t.Errorf("originOf(%q) != base, want same origin", same)
		}
	}
	// Hostname() strips brackets, so a bare-Host URL normalizes equal.
	if got := originOf(&url.URL{Scheme: "http", Host: "::1:8069"}); got != base {
		t.Errorf("unbracketed IPv6 host origin = %+v, want %+v", got, base)
	}
	for _, diff := range []string{
		"http://[::1]:8070/other",     // cross-port
		"http://127.0.0.1:8069/other", // different host
	} {
		if originOf(mustURL(t, diff)) == base {
			t.Errorf("originOf(%q) == base, want distinct", diff)
		}
	}
}
