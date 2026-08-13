package dockerclient

import (
	"github.com/codeswhat/sockguard/internal/upstream"
	"net/http"
)

// NewWithRoundTripper returns an *http.Client whose transport is the shared
// upstream RoundTripper (typically an *upstream.Resolver). Routing, pooling,
// TLS, and failover all live in that transport. Callers must not mutate the
// returned client after construction.
func NewWithRoundTripper(rt http.RoundTripper) *http.Client {
	return &http.Client{Transport: rt}
}

// New returns an *http.Client that dials the Docker unix socket at path. It is
// the single-local-socket shorthand retained for callers and tests that have a
// plain socket path; it builds a one-endpoint resolver under the hood.
func New(socketPath string) *http.Client {
	return NewWithRoundTripper(upstream.NewSingleSocket(socketPath))
}
