// Package dockerclient provides a shared *http.Client for side-channel calls
// to the upstream Docker socket (ownership inspection, client ACL resolution,
// visibility label look-ups). All three callers use the same unix-socket
// transport configuration so idle connections are reused across requests.
package dockerclient

import (
	"context"
	"net"
	"net/http"
	"time"
)

// New returns an *http.Client that dials the Docker unix socket at path.
// The transport is tuned to match the main reverse-proxy transport:
//   - MaxIdleConnsPerHost: 10  — caps idle connections per host bucket
//   - IdleConnTimeout: 90s     — matches net/http DefaultTransport
//
// Callers must not mutate the returned client after construction.
func New(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}
