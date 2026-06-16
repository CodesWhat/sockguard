package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ErrNoEndpoints is returned by a Resolver that was constructed without any
// endpoints. Config validation prevents this in practice.
var ErrNoEndpoints = errors.New("upstream: no endpoints configured")

// Dialer is the raw-connection seam used by the hijack path, which bypasses the
// pooled HTTP transport and takes a net.Conn directly. *Resolver implements it.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

const (
	defaultMaxIdleConns          = 100
	defaultMaxIdleConnsPerHost   = 100
	defaultIdleConnTimeout       = 90 * time.Second
	defaultResponseHeaderTimeout = 30 * time.Second
	defaultProbeInterval         = 5 * time.Second
	defaultProbeTimeout          = 2 * time.Second
)

// dial establishes a connection to the endpoint. For a TLS endpoint it completes
// the TLS handshake inside the dialer and returns the wrapped *tls.Conn, so every
// consumer can treat the upstream as plain HTTP over an already-encrypted pipe —
// the ReverseProxy rewrites the request scheme to "http", which would otherwise
// suppress transport-level TLS.
func (e Endpoint) dial(ctx context.Context) (net.Conn, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, e.Network, e.Address)
	if err != nil {
		return nil, err
	}
	if e.TLSConfig == nil {
		return raw, nil
	}
	tconn := tls.Client(raw, e.TLSConfig)
	if err := tconn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tconn, nil
}

// newTransport builds the pooled HTTP transport for one endpoint. Pool settings
// match the historical single-socket proxy transport so per-endpoint behavior is
// identical to the pre-multi-host proxy. TLS is handled inside dial, so the
// transport itself carries no TLSClientConfig.
func (e Endpoint) newTransport() *http.Transport {
	ep := e
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return ep.dial(ctx)
		},
		MaxIdleConns:          defaultMaxIdleConns,
		MaxIdleConnsPerHost:   defaultMaxIdleConnsPerHost,
		IdleConnTimeout:       defaultIdleConnTimeout,
		ResponseHeaderTimeout: defaultResponseHeaderTimeout,
	}
}

type endpointState struct {
	ep        Endpoint
	transport *http.Transport
	// mu serializes setHealth's swap-and-notify so a flapping endpoint never
	// fires OnChange in an order that contradicts the final healthy value.
	// Routing reads (healthy/known Load) stay lock-free.
	mu      sync.Mutex
	healthy atomic.Bool
	known   atomic.Bool
	// reprobing gates the asynchronous re-probe demote() launches to at most one
	// in-flight goroutine per endpoint, so a dead endpoint under heavy traffic
	// cannot spawn a goroutine/FD storm.
	reprobing atomic.Bool
}

// Options configures a Resolver's health loop and observation hooks.
type Options struct {
	// Interval is the active health-probe period. Zero uses defaultProbeInterval;
	// negative disables continuous probing (a single startup probe still runs).
	Interval time.Duration
	// Timeout bounds each probe. Zero uses defaultProbeTimeout.
	Timeout time.Duration
	// Logger receives endpoint up/down transition logs. Nil disables logging.
	Logger *slog.Logger
	// OnChange is invoked on every endpoint health transition (and on the first
	// known result per endpoint), for metrics. It must be non-blocking.
	OnChange func(ep Endpoint, healthy bool)
	// Probe overrides the default connect-level probe. The default dials the
	// endpoint (completing the TLS handshake for TLS endpoints) and closes it.
	Probe func(ctx context.Context, ep Endpoint) error
}

// Resolver routes upstream connections to the first healthy endpoint in an
// ordered list, with automatic failover driven by a background health loop. A
// single-endpoint Resolver (the common case, including the legacy local socket)
// always routes to that endpoint; failover logic is inert.
//
// It implements http.RoundTripper for the reverse proxy and HTTP side channels,
// and exposes DialContext for the raw-conn hijack path. Both demote the active
// endpoint on a connection-level failure so the next request routes elsewhere;
// neither retries the in-flight request, because Docker writes are not idempotent.
type Resolver struct {
	states   []*endpointState
	interval time.Duration
	timeout  time.Duration
	logger   *slog.Logger
	onChange func(ep Endpoint, healthy bool)
	probe    func(ctx context.Context, ep Endpoint) error
	started  atomic.Bool
	// baseCtx is the Start context (nil until Start runs). demote's re-probe
	// goroutines derive from it so they unwind promptly on shutdown instead of
	// outliving the resolver by up to one probe timeout.
	baseCtx atomic.Pointer[context.Context]
}

// New builds a Resolver over the ordered endpoints. The first endpoint is the
// preferred primary; later endpoints are failover targets for the same logical
// daemon. It returns ErrNoEndpoints when endpoints is empty.
func New(endpoints []Endpoint, opts Options) (*Resolver, error) {
	if len(endpoints) == 0 {
		return nil, ErrNoEndpoints
	}
	states := make([]*endpointState, len(endpoints))
	for i, ep := range endpoints {
		states[i] = &endpointState{ep: ep, transport: ep.newTransport()}
	}

	interval := opts.Interval
	if interval == 0 {
		interval = defaultProbeInterval
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	probe := opts.Probe
	if probe == nil {
		probe = defaultProbe
	}

	return &Resolver{
		states:   states,
		interval: interval,
		timeout:  timeout,
		logger:   opts.Logger,
		onChange: opts.OnChange,
		probe:    probe,
	}, nil
}

// NewSingleSocket returns a Resolver with one local unix-socket endpoint and no
// continuous health probing — a drop-in for the historical single-socket dial
// path used by the legacy constructors and by tests. Its Active endpoint is
// always the socket, so failover logic stays inert.
func NewSingleSocket(socketPath string) *Resolver {
	r, _ := New([]Endpoint{{Name: socketPath, Network: "unix", Address: socketPath}}, Options{Interval: -1})
	return r
}

// defaultProbe verifies liveness by dialing the endpoint (and completing the TLS
// handshake for TLS endpoints) and closing the connection immediately.
func defaultProbe(ctx context.Context, ep Endpoint) error {
	conn, err := ep.dial(ctx)
	if err != nil {
		return err
	}
	return conn.Close()
}

// Endpoints returns the configured endpoints in preference order.
func (r *Resolver) Endpoints() []Endpoint {
	out := make([]Endpoint, len(r.states))
	for i, s := range r.states {
		out[i] = s.ep
	}
	return out
}

// CheckReachable probes every endpoint once, seeding their health state, and
// returns nil when at least one endpoint answers. When all endpoints fail it
// returns an aggregated error naming each unreachable endpoint. This lets a
// multi-endpoint failover set boot as long as one daemon responds, while a
// fully dark upstream still fails fast at startup.
func (r *Resolver) CheckReachable(ctx context.Context) error {
	if len(r.states) == 0 {
		return ErrNoEndpoints
	}
	reachable := false
	failures := make([]string, 0, len(r.states))
	for _, s := range r.states {
		pctx, cancel := context.WithTimeout(ctx, r.timeout)
		err := r.probe(pctx, s.ep)
		cancel()
		r.setHealth(s, err == nil)
		if err == nil {
			reachable = true
			continue
		}
		failures = append(failures, fmt.Sprintf("%s: %v", s.ep.String(), err))
	}
	if reachable {
		return nil
	}
	return fmt.Errorf("no upstream endpoint reachable: %s", strings.Join(failures, "; "))
}

// Active returns the endpoint requests currently route to: the first
// known-healthy endpoint, else the first not-yet-probed endpoint, else the
// primary as a last resort so a request is still attempted.
func (r *Resolver) Active() Endpoint {
	if s := r.activeState(); s != nil {
		return s.ep
	}
	return Endpoint{}
}

func (r *Resolver) activeState() *endpointState {
	var firstUnknown *endpointState
	for _, s := range r.states {
		if s.known.Load() && s.healthy.Load() {
			return s
		}
		if firstUnknown == nil && !s.known.Load() {
			firstUnknown = s
		}
	}
	if firstUnknown != nil {
		return firstUnknown
	}
	if len(r.states) > 0 {
		return r.states[0]
	}
	return nil
}

// RoundTrip implements http.RoundTripper, routing the request to the active
// endpoint's pooled transport. A request that fails for a request-scoped reason
// (client disconnect, or the per-request request_timeout deadline firing) does
// NOT demote the endpoint — those say nothing about upstream reachability, and
// demoting on them would flap a healthy primary on every long-running request.
func (r *Resolver) RoundTrip(req *http.Request) (*http.Response, error) {
	s := r.activeState()
	if s == nil {
		return nil, ErrNoEndpoints
	}
	resp, err := s.transport.RoundTrip(req)
	if err != nil && !isRequestScopedError(err) {
		r.demote(s)
	}
	return resp, err
}

// DialContext dials the active endpoint, returning a raw (TLS-wrapped where
// applicable) net.Conn for the hijack path. The network/address arguments are
// ignored; the endpoint is chosen by health. A dial that exceeds the caller's
// dial deadline DOES demote (a slow/dead endpoint is a reachability signal),
// but an explicit cancellation (context.Canceled) does not.
func (r *Resolver) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	s := r.activeState()
	if s == nil {
		return nil, ErrNoEndpoints
	}
	conn, err := s.ep.dial(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		r.demote(s)
	}
	return conn, err
}

// isRequestScopedError reports whether err originates from the request's own
// context (client cancellation or the per-request deadline) rather than an
// upstream-side failure. Such errors must not demote the active endpoint.
func isRequestScopedError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// demote marks an endpoint unhealthy after a live request/dial failure so the
// next request routes elsewhere. It is a no-op for a single-endpoint resolver
// (there is nowhere to fail over to, so flapping the only endpoint's state would
// just add noise) and triggers an asynchronous re-probe so a transient blip
// recovers without waiting a full interval. The re-probe is gated to one
// in-flight goroutine per endpoint (reprobing CAS) so a dead endpoint under
// heavy traffic cannot spawn a goroutine/FD storm, and it derives from the
// resolver's Start context so it unwinds on shutdown.
func (r *Resolver) demote(s *endpointState) {
	if len(r.states) < 2 {
		return
	}
	r.setHealth(s, false)
	if !s.reprobing.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer s.reprobing.Store(false)
		ctx, cancel := context.WithTimeout(r.reprobeBaseContext(), r.timeout)
		defer cancel()
		r.setHealth(s, r.probe(ctx, s.ep) == nil)
	}()
}

// reprobeBaseContext returns the resolver's Start context, or context.Background
// when Start has not run yet (the demote path can fire on a request that races
// startup, or in tests that never call Start).
func (r *Resolver) reprobeBaseContext() context.Context {
	if p := r.baseCtx.Load(); p != nil {
		return *p
	}
	return context.Background()
}

// Start launches the background health loop. It is idempotent; the loop exits
// when ctx is canceled.
func (r *Resolver) Start(ctx context.Context) {
	if !r.started.CompareAndSwap(false, true) {
		return
	}
	r.baseCtx.Store(&ctx)
	go r.loop(ctx)
}

func (r *Resolver) loop(ctx context.Context) {
	r.probeAll(ctx)
	if r.interval < 0 {
		return
	}
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.probeAll(ctx)
		}
	}
}

func (r *Resolver) probeAll(ctx context.Context) {
	for _, s := range r.states {
		if ctx.Err() != nil {
			return
		}
		pctx, cancel := context.WithTimeout(ctx, r.timeout)
		err := r.probe(pctx, s.ep)
		cancel()
		r.setHealth(s, err == nil)
	}
}

func (r *Resolver) setHealth(s *endpointState, healthy bool) {
	// Serialize the swap-and-notify so concurrent probes (background loop + a
	// demote re-probe) can't fire onChange in an order that contradicts the
	// final healthy value. Routing reads stay lock-free on the atomics.
	s.mu.Lock()
	defer s.mu.Unlock()
	was := s.healthy.Swap(healthy)
	first := !s.known.Swap(true)
	if !first && was == healthy {
		return
	}
	if r.logger != nil {
		level := slog.LevelInfo
		if !healthy {
			level = slog.LevelWarn
		}
		r.logger.LogAttrs(context.Background(), level, "upstream endpoint health changed",
			slog.String("endpoint", s.ep.String()),
			slog.Bool("healthy", healthy),
		)
	}
	if r.onChange != nil {
		r.onChange(s.ep, healthy)
	}
}
