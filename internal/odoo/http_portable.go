//go:build !darwin || !cgo

package odoo

import (
	"crypto/tls"
	"net/http"
	"time"
)

// Portable builds, including explicitly CGO-disabled macOS builds, retain
// Go's transport. Native macOS builds use Foundation instead.
func newHTTPTransport(verifySSL bool, _ time.Duration) http.RoundTripper {
	return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifySSL}} //nolint:gosec // explicit human opt-in
}
