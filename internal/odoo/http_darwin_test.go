//go:build darwin && cgo

package odoo

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Real local HTTP wire tests, with dummy secrets only. These prove transport
// contracts, not Odoo authentication, ORM, addon or ACL behavior.
func nativeTestClient(t *testing.T, target string, verify bool, timeout time.Duration) *http.Client {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	origin := originOf(u)
	return &http.Client{Transport: originGuardRoundTripper{rt: newHTTPTransport(verify, timeout), origin: origin}, CheckRedirect: checkRedirectToOrigin(origin)}
}

func TestNativeHTTPWireAndNoCookies(t *testing.T) {
	const body = `<methodCall>café 日本語 dummy-secret</methodCall>`
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		data, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || string(data) != body || r.Header.Get("Authorization") != "Bearer dummy" {
			t.Errorf("request wire differs")
		}
		if r.Header.Get("Cookie") != "" {
			t.Error("native session retained a cookie")
		}
		w.Header().Set("Set-Cookie", "session_id=must-not-persist")
		w.Header().Set("Content-Type", "text/xml")
		io.WriteString(w, `<methodResponse>café 日本語</methodResponse>`)
	}))
	defer srv.Close()
	client := nativeTestClient(t, srv.URL, true, time.Second)
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("POST", srv.URL, strings.NewReader(body))
		req.Header.Set("Content-Type", "text/xml")
		req.Header.Set("Authorization", "Bearer dummy")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil || res.StatusCode != 200 || string(got) != `<methodResponse>café 日本語</methodResponse>` {
			t.Fatalf("response differs: %d %v %q", res.StatusCode, err, got)
		}
	}
	if calls.Load() != 2 {
		t.Fatal("missing legitimate calls")
	}
}

func TestNativeRedirectsStayInGo(t *testing.T) {
	var stolen atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { stolen.Add(1) }))
	defer evil.Close()
	for _, code := range []int{301, 302, 303, 307, 308} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, evil.URL, code) }))
			defer origin.Close()
			// Also mirror kolo/xmlrpc: no CheckRedirect; RoundTripper alone
			// must block replay to a different origin.
			c := nativeTestClient(t, origin.URL, true, time.Second)
			c.CheckRedirect = nil
			req, _ := http.NewRequest("POST", origin.URL, strings.NewReader("dummy-secret"))
			req.Header.Set("Authorization", "Bearer dummy")
			res, err := c.Do(req)
			if res != nil {
				res.Body.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "off-origin") {
				t.Fatalf("cross-origin redirect not denied: %v", err)
			}
		})
	}
	if stolen.Load() != 0 {
		t.Fatalf("credentials moved: %d requests", stolen.Load())
	}
	var replayed atomic.Bool
	legit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/target", 307)
			return
		}
		data, _ := io.ReadAll(r.Body)
		replayed.Store(r.Method == "POST" && string(data) == "dummy-secret" && r.Header.Get("Authorization") == "Bearer dummy")
		io.WriteString(w, "ok")
	}))
	defer legit.Close()
	req, _ := http.NewRequest("POST", legit.URL+"/start", strings.NewReader("dummy-secret"))
	req.Header.Set("Authorization", "Bearer dummy")
	res, err := nativeTestClient(t, legit.URL, true, time.Second).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if !replayed.Load() {
		t.Fatal("legitimate same-origin replay broken")
	}
}

func TestNativeResponseLimit(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(map[bool]string{false: "content-length", true: "chunked"}[chunked], func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !chunked {
					w.Header().Set("Content-Length", "10485761")
				} else {
					w.(http.Flusher).Flush()
				}
				io.WriteString(w, strings.Repeat("x", maxXMLResponseBytes+1))
			}))
			defer srv.Close()
			res, err := nativeTestClient(t, srv.URL, true, 3*time.Second).Get(srv.URL)
			if res != nil {
				res.Body.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "exceeds") {
				t.Fatalf("oversize response accepted: %v", err)
			}
		})
	}
}

func TestNativeStalledRedirectIsBounded(t *testing.T) {
	release := make(chan struct{})
	closed := make(chan struct{})
	var replayed atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/target" {
			replayed.Add(1)
			io.WriteString(w, "ok")
			return
		}
		w.Header().Set("Location", "/target")
		w.Header().Set("Content-Length", "10485761")
		w.WriteHeader(http.StatusTemporaryRedirect)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			close(closed)
		case <-release:
		}
	}))
	defer func() { close(release); srv.Close() }()
	start := time.Now()
	req, _ := http.NewRequest("POST", srv.URL+"/start", strings.NewReader("dummy-secret"))
	res, err := nativeTestClient(t, srv.URL, true, 150*time.Millisecond).Do(req)
	if res != nil {
		res.Body.Close()
	}
	if err == nil || time.Since(start) > 2*time.Second || replayed.Load() != 0 {
		t.Fatalf("stalled redirect did not fail closed: %v; replayed=%d", err, replayed.Load())
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("stalled redirect request not cancelled")
	}
}

func TestNativeCancellationAndTimeout(t *testing.T) {
	for _, bodyBlocked := range []bool{false, true} {
		for _, cancel := range []bool{false, true} {
			t.Run(map[bool]string{false: "headers", true: "body"}[bodyBlocked]+map[bool]string{false: "-timeout", true: "-cancel"}[cancel], func(t *testing.T) {
				seen := make(chan struct{})
				closed := make(chan struct{})
				release := make(chan struct{})
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					io.Copy(io.Discard, r.Body)
					if bodyBlocked {
						w.WriteHeader(200)
						io.WriteString(w, "{")
						w.(http.Flusher).Flush()
					}
					close(seen)
					select {
					case <-r.Context().Done():
						close(closed)
					case <-release:
					}
				}))
				defer func() { close(release); srv.Close() }()
				ctx, stop := context.WithCancel(context.Background())
				defer stop()
				req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL, strings.NewReader("dummy"))
				timeout := 150 * time.Millisecond
				if cancel {
					timeout = time.Second
					go func() { <-seen; stop() }()
				}
				start := time.Now()
				res, err := nativeTestClient(t, srv.URL, true, timeout).Do(req)
				if res != nil {
					res.Body.Close()
				}
				if err == nil || time.Since(start) > 2*time.Second {
					t.Fatalf("request did not terminate: %v", err)
				}
				if cancel && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel error: %v", err)
				}
				select {
				case <-closed:
				case <-time.After(time.Second):
					t.Fatal("native upstream request not cancelled")
				}
			})
		}
	}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	ctx, stop := context.WithCancel(context.Background())
	stop()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	_, err := nativeTestClient(t, srv.URL, true, time.Second).Do(req)
	if !errors.Is(err, context.Canceled) || hits.Load() != 0 {
		t.Fatal("pre-cancelled request dispatched")
	}
}

func TestNativeTLSVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer srv.Close()
	res, err := nativeTestClient(t, srv.URL, true, time.Second).Get(srv.URL)
	if res != nil {
		res.Body.Close()
	}
	if err == nil {
		t.Fatal("untrusted TLS accepted by default")
	}
	res, err = nativeTestClient(t, srv.URL, false, time.Second).Get(srv.URL)
	if err != nil {
		t.Fatalf("explicit verify_ssl=false behavior changed: %v", err)
	}
	res.Body.Close()
}
