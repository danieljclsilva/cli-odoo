//go:build darwin && cgo

package odoo

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework Security
#include <stdlib.h>
#include "http_darwin.h"
*/
import "C"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
	"unsafe"
)

const maxNativeRequestBytes = 32 << 20

type nativeHTTPTransport struct {
	verifySSL bool
	timeout   time.Duration
}

func newHTTPTransport(verifySSL bool, timeout time.Duration) http.RoundTripper {
	return nativeHTTPTransport{verifySSL: verifySSL, timeout: timeout}
}

// Foundation never follows redirects. Returning each original 3xx to Go
// preserves http.Client's replay semantics and our exact-origin guard for
// both XML-RPC authentication and JSON credentials. No cookies, cache,
// system credential storage, helper processes or persistent files are used.
func (t nativeHTTPTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
		return nil, errors.New("odoo: unsupported native HTTP URL scheme")
	}
	var body []byte
	if r.Body != nil {
		defer r.Body.Close()
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, maxNativeRequestBytes+1))
		if err != nil {
			return nil, errors.New("odoo: cannot read native HTTP request")
		}
		if len(body) > maxNativeRequestBytes {
			return nil, errors.New("odoo: native HTTP request exceeds 32 MiB")
		}
	}
	headers := r.Header.Clone()
	// Match native XML clients; Foundation supplies its own honest User-Agent.
	if headers.Get("Accept") == "" {
		headers.Set("Accept", headers.Get("Content-Type"))
	}
	hdr, err := json.Marshal(headers)
	if err != nil || len(hdr) > 64<<10 {
		return nil, errors.New("odoo: invalid or oversized native HTTP headers")
	}
	u, method, h := C.CString(r.URL.String()), C.CString(r.Method), C.CString(string(hdr))
	defer C.free(unsafe.Pointer(u))
	defer C.free(unsafe.Pointer(method))
	defer C.free(unsafe.Pointer(h))
	var ptr unsafe.Pointer
	if len(body) > 0 {
		ptr = unsafe.Pointer(&body[0])
	}
	timeout := t.timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	verify := C.int(0)
	if t.verifySSL {
		verify = 1
	}
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	// start copies the request synchronously; no Go pointer is retained by C.
	request := C.odoo_http_start(u, method, h, ptr, C.size_t(len(body)), C.double(timeout.Seconds()), C.size_t(maxXMLResponseBytes), verify)
	if request == nil {
		return nil, errors.New("odoo: cannot create native HTTP request")
	}
	defer C.odoo_http_release(request)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	poll := time.NewTicker(5 * time.Millisecond)
	defer poll.Stop()
	for C.odoo_http_finished(request) == 0 {
		select {
		case <-r.Context().Done():
			C.odoo_http_cancel(request)
			return nil, r.Context().Err()
		case <-timer.C:
			C.odoo_http_cancel(request)
			return nil, errors.New("odoo: native HTTP request timed out")
		case <-poll.C:
		}
	}
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	meta := C.odoo_http_metadata(request)
	if meta == nil {
		return nil, errors.New("odoo: invalid native HTTP response")
	}
	defer C.free(unsafe.Pointer(meta))
	var result struct {
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Error   string            `json:"error"`
	}
	if err := json.Unmarshal([]byte(C.GoString(meta)), &result); err != nil {
		return nil, errors.New("odoo: invalid native HTTP response metadata")
	}
	if result.Error != "" {
		return nil, fmt.Errorf("odoo: %s", result.Error)
	}
	if result.Status < 100 || result.Status > 599 {
		return nil, errors.New("odoo: invalid native HTTP status")
	}
	var size C.size_t
	data := C.odoo_http_body(request, &size)
	if size > maxXMLResponseBytes {
		return nil, errors.New("odoo: native HTTP response exceeds 10 MiB")
	}
	buf := C.GoBytes(data, C.int(size))
	resp := &http.Response{StatusCode: result.Status, Status: fmt.Sprintf("%d %s", result.Status, http.StatusText(result.Status)), Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(buf)), ContentLength: int64(len(buf)), Request: r}
	for key, value := range result.Headers {
		resp.Header.Set(key, value)
	}
	return resp, nil
}
