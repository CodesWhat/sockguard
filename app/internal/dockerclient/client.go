// Package dockerclient provides a shared *http.Client for side-channel calls
// to the upstream Docker daemon (ownership inspection, client ACL resolution,
// visibility label look-ups). All callers route through the same upstream
// transport so idle connections are reused and — when the upstream is a
// failover set — so the side channels follow the same active endpoint as the
// main proxy (a split between the request path and its owner-label inspect
// would break owner isolation).
package dockerclient

import (
	"net/http"

	"github.com/codeswhat/sockguard/internal/upstream"
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
