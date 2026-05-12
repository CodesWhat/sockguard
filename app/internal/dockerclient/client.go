package dockerclient

import (
	"context"
	"net"
	"net/http"
	"time"
)

const (
	defaultDialTimeout           = 5 * time.Second
	defaultResponseHeaderTimeout = 10 * time.Second
	defaultMaxIdleConnsPerHost   = 10
	defaultIdleConnTimeout       = 90 * time.Second
)

// Option customizes the http.Client returned by New.
type Option func(*config)

type config struct {
	dialTimeout           time.Duration
	responseHeaderTimeout time.Duration
	maxIdleConnsPerHost   int
	idleConnTimeout       time.Duration
}

func defaults() config {
	return config{
		dialTimeout:           defaultDialTimeout,
		responseHeaderTimeout: defaultResponseHeaderTimeout,
		maxIdleConnsPerHost:   defaultMaxIdleConnsPerHost,
		idleConnTimeout:       defaultIdleConnTimeout,
	}
}

// WithDialTimeout sets the maximum time to establish the Unix socket connection.
func WithDialTimeout(d time.Duration) Option {
	return func(c *config) { c.dialTimeout = d }
}

// WithResponseHeaderTimeout sets how long to wait for the Docker daemon to
// send response headers after the request is fully written.
func WithResponseHeaderTimeout(d time.Duration) Option {
	return func(c *config) { c.responseHeaderTimeout = d }
}

// New returns an *http.Client whose transport dials the Unix socket at
// socketPath. Requests should target "http://docker/<path>" — the host portion
// is ignored; the transport always connects to socketPath.
//
// Each call returns an independent client and transport; there is no global
// state and the returned client is safe for concurrent use.
func New(socketPath string, opts ...Option) (*http.Client, error) {
	cfg := defaults()
	for _, o := range opts {
		o(&cfg)
	}

	dialer := &net.Dialer{Timeout: cfg.dialTimeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		MaxIdleConnsPerHost:   cfg.maxIdleConnsPerHost,
		IdleConnTimeout:       cfg.idleConnTimeout,
		ResponseHeaderTimeout: cfg.responseHeaderTimeout,
	}
	return &http.Client{Transport: transport}, nil
}
