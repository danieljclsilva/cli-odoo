package odoo

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kolo/xmlrpc"
)

// testClientFor wires a Client at a local httptest server without dialing a
// real Odoo instance: the XML path needs only objectURL + c.http, the JSON
// path only jsonBase + c.http. Secrets are dummy; no credentials leave the
// test process.
func testClientFor(t *testing.T, srv *httptest.Server, transport string) *Client {
	t.Helper()
	var httpClient *http.Client
	if srv != nil {
		httpClient = srv.Client()
	} else {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	c := &Client{
		URL:       "http://127.0.0.1:1",
		DB:        "db",
		Username:  "user",
		Transport: transport,
		Timeout:   5 * time.Second,
		VerifySSL: true,
		secret:    "secret",
		http:      httpClient,
	}
	if srv != nil {
		if transport == "json2" {
			c.jsonBase = srv.URL + "/api/v2"
		} else {
			c.objectURL = srv.URL + "/xmlrpc/2/object"
		}
	}
	return c
}

func TestExecuteContextXMLRequestShape(t *testing.T) {
	// Contract: ExecuteContext over XML posts a valid execute_kw envelope
	// (kolo/xmlrpc wire format) with the exact DB/uid/model/method/args
	// params, and decodes the methodResponse result.
	var gotCT, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><methodResponse><params><param><value><array><data><value><int>7</int></value></data></array></value></param></params></methodResponse>`))
	}))
	defer srv.Close()
	c := testClientFor(t, srv, "xmlrpc")
	c.uid = 42

	out, err := c.ExecuteContext(context.Background(), "res.partner", "search_read", []any{[]any{}}, map[string]any{"limit": 5})
	if err != nil {
		t.Fatalf("ExecuteContext XML: %v", err)
	}
	rows, ok := out.([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("XML result = %#v, want one-element array", out)
	}
	if gotCT != "text/xml" {
		t.Fatalf("Content-Type = %q, want text/xml", gotCT)
	}
	// The envelope must carry execute_kw with DB, uid, model, method in
	// order: re-decode the posted body through the same codec shape by
	// checking the ordered param markers.
	for _, want := range []string{
		"<methodName>execute_kw</methodName>",
		"<string>db</string>",
		"<int>42</int>",
		"<string>res.partner</string>",
		"<string>search_read</string>",
	} {
		if !strings.Contains(gotBody, want) {
			t.Fatalf("XML request body missing %q:\n%s", want, gotBody)
		}
	}
	var probe any
	if err := xmlrpc.Response([]byte(gotBody)).Unmarshal(&probe); err != nil {
		t.Fatalf("posted body is not valid XML-RPC: %v", err)
	}
}

func TestExecuteContextXMLLangInjection(t *testing.T) {
	// Lang injection rides in kwargs context without changing the envelope
	// shape: the posted struct still decodes through the codec.
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><methodResponse><params><param><value><array><data></data></array></value></param></params></methodResponse>`))
	}))
	defer srv.Close()
	c := testClientFor(t, srv, "xmlrpc")
	c.uid = 1
	c.Lang = "fr_FR"
	if _, err := c.ExecuteContext(context.Background(), "res.partner", "search_read", nil, map[string]any{}); err != nil {
		t.Fatalf("ExecuteContext XML lang: %v", err)
	}
	if !strings.Contains(gotBody, "fr_FR") || !strings.Contains(gotBody, "context") || !strings.Contains(gotBody, "lang") {
		t.Fatalf("Lang injection missing from XML body:\n%s", gotBody)
	}
}

func TestExecuteContextJSONRequestShape(t *testing.T) {
	// Contract: ExecuteContext over json2 POSTs {base}/{model}/{method}
	// with the Bearer + database headers and an args/kwargs payload, and
	// returns the result member.
	var gotPath, gotAuth, gotDB, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotDB = r.Header.Get("X-Odoo-Database")
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result": [{"id": 3}]}`))
	}))
	defer srv.Close()
	c := testClientFor(t, srv, "json2")

	out, err := c.ExecuteContext(context.Background(), "res.partner", "search_read", []any{[]any{}}, map[string]any{"limit": 5})
	if err != nil {
		t.Fatalf("ExecuteContext JSON: %v", err)
	}
	rows, ok := out.([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("JSON result = %#v, want one-element array", out)
	}
	if gotPath != "/api/v2/res.partner/search_read" {
		t.Fatalf("JSON path = %q, want /api/v2/res.partner/search_read", gotPath)
	}
	if gotAuth != "Bearer secret" {
		t.Fatalf("Authorization = %q, want Bearer secret", gotAuth)
	}
	if gotDB != "db" {
		t.Fatalf("X-Odoo-Database = %q, want db", gotDB)
	}
	for _, want := range []string{`"args"`, `"kwargs"`, `"limit":5`} {
		if !strings.Contains(gotBody, want) {
			t.Fatalf("JSON body missing %q: %s", want, gotBody)
		}
	}
}

func TestExecuteContextWriteMethodRefusedBeforeRPC(t *testing.T) {
	// Read-only gating fires before any HTTP: a write method never reaches
	// the server on either transport.
	for _, transport := range []string{"xmlrpc", "json2"} {
		hits := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits++
			w.WriteHeader(http.StatusOK)
		}))
		c := testClientFor(t, srv, transport)
		c.uid = 1
		if _, err := c.ExecuteContext(context.Background(), "res.partner", "write", nil, nil); err == nil {
			srv.Close()
			t.Fatalf("%s: write executed, want refusal", transport)
		}
		srv.Close()
		if hits != 0 {
			t.Fatalf("%s: write reached server %d times, want 0", transport, hits)
		}
	}
}

func TestExecuteContextCancelUnblocksHeadersBlocked(t *testing.T) {
	// Cancellation while response headers are blocked unblocks promptly on
	// both transports: the in-flight HTTP call carries ctx. The handler
	// parks until release is closed (client cancel alone does not settle a
	// parked httptest handler, and srv.Close waits for it), so the test
	// closes release before srv.Close on every path.
	for _, transport := range []string{"xmlrpc", "json2"} {
		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			w.Header().Set("Content-Type", map[string]string{"xmlrpc": "text/xml", "json2": "application/json"}[transport])
			_, _ = w.Write([]byte(`{}`))
		}))
		c := testClientFor(t, srv, transport)
		c.uid = 1
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := c.ExecuteContext(ctx, "res.partner", "search_read", nil, nil)
			done <- err
		}()
		time.Sleep(50 * time.Millisecond)
		cancel()
		select {
		case err := <-done:
			if err == nil {
				close(release)
				srv.Close()
				t.Fatalf("%s: headers-blocked call succeeded after cancel", transport)
			}
		case <-time.After(5 * time.Second):
			close(release)
			srv.Close()
			t.Fatalf("%s: headers-blocked call did not unblock on cancel", transport)
		}
		close(release)
		srv.Close()
	}
}
func TestExecuteContextCancelUnblocksBodyBlocked(t *testing.T) {
	// Cancellation while the body is stalled mid-stream unblocks promptly:
	// headers flush, one chunk writes, then the handler parks on ctx.
	// The handler also watches release: srv.Close waits for parked handlers,
	// so the test closes release before srv.Close on every path.
	for _, transport := range []string{"xmlrpc", "json2"} {
		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", map[string]string{"xmlrpc": "text/xml", "json2": "application/json"}[transport])
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				_, _ = w.Write([]byte(`{"result": [`))
				f.Flush()
			}
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}))
		c := testClientFor(t, srv, transport)
		c.uid = 1
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := c.ExecuteContext(ctx, "res.partner", "search_read", nil, nil)
			done <- err
		}()
		time.Sleep(50 * time.Millisecond)
		cancel()
		select {
		case err := <-done:
			if err == nil {
				close(release)
				srv.Close()
				t.Fatalf("%s: body-blocked call succeeded after cancel", transport)
			}
		case <-time.After(5 * time.Second):
			close(release)
			srv.Close()
			t.Fatalf("%s: body-blocked call did not unblock on cancel", transport)
		}
		close(release)
		srv.Close()
	}
}

func TestExecuteContextPreCancelledDenied(t *testing.T) {
	// An already-cancelled context fails before any HTTP on both transports.
	for _, transport := range []string{"xmlrpc", "json2"} {
		hits := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits++
		}))
		c := testClientFor(t, srv, transport)
		c.uid = 1
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := c.ExecuteContext(ctx, "res.partner", "search_read", nil, nil); err == nil {
			srv.Close()
			t.Fatalf("%s: pre-cancelled call succeeded, want deny", transport)
		}
		srv.Close()
		if hits != 0 {
			t.Fatalf("%s: pre-cancelled call hit server %d times, want 0", transport, hits)
		}
	}
}

func TestExecuteContextMalformedResponseNoPanic(t *testing.T) {
	// Malformed bodies are errors, never panics, on both transports: junk
	// XML (XML path), junk JSON (JSON path), and an XML fault envelope.
	xmlJunk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<methodResponse><params><param><value><oops></methodResponse>`))
	}))
	defer xmlJunk.Close()
	c := testClientFor(t, xmlJunk, "xmlrpc")
	c.uid = 1
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("XML junk panicked: %v", r)
			}
		}()
		if _, err := c.ExecuteContext(context.Background(), "res.partner", "search_read", nil, nil); err == nil {
			t.Fatal("XML junk succeeded, want error")
		}
	}()

	xmlFault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><methodResponse><fault><value><struct><member><name>faultCode</name><value><int>1</int></value></member><member><name>faultString</name><value><string>boom</string></value></member></struct></value></fault></methodResponse>`))
	}))
	defer xmlFault.Close()
	cf := testClientFor(t, xmlFault, "xmlrpc")
	cf.uid = 1
	if _, err := cf.ExecuteContext(context.Background(), "res.partner", "search_read", nil, nil); err == nil {
		t.Fatal("XML fault succeeded, want error")
	}

	jsonJunk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result": `))
	}))
	defer jsonJunk.Close()
	cj := testClientFor(t, jsonJunk, "json2")
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("JSON junk panicked: %v", r)
			}
		}()
		if _, err := cj.ExecuteContext(context.Background(), "res.partner", "search_read", nil, nil); err == nil {
			t.Fatal("JSON junk succeeded, want error")
		}
	}()

	jsonErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error": "denied"}`))
	}))
	defer jsonErr.Close()
	ce := testClientFor(t, jsonErr, "json2")
	if _, err := ce.ExecuteContext(context.Background(), "res.partner", "search_read", nil, nil); err == nil {
		t.Fatal("JSON error envelope succeeded, want error")
	}
}
