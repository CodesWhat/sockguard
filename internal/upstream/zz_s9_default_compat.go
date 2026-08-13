package upstream

import (
	"context"
	"crypto/tls"

	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Endpoint is one resolved upstream target: either a local unix socket or a
// remote TCP daemon, optionally wrapped in client TLS.
type Endpoint struct {
	// Name is a stable identifier used for metrics labels and log fields. For a
	// unix socket it is the socket path; for TCP it is host:port. It is never
	// empty for a valid endpoint.
	Name string
	// Network is "unix" or "tcp" — the first argument to net.Dial.
	Network string
	// Address is the unix socket path or the TCP host:port. It is the second
	// argument to net.Dial.
	Address string
	// TLSConfig is non-nil only for TCP endpoints that negotiate TLS. It is nil
	// for unix sockets and for plain-TCP endpoints (which require an explicit
	// insecure acknowledgement to construct).
	TLSConfig *tls.Config
}

// IsTLS reports whether the endpoint dials over TLS.
func (e Endpoint) IsTLS() bool { return e.TLSConfig != nil }

// String renders the endpoint for logs: scheme://address, with a "+tls" suffix
// when TLS is in play.
func (e Endpoint) String() string {
	scheme := e.Network
	if e.IsTLS() {
		scheme += "+tls"
	}
	return scheme + "://" + e.Address
}

// EndpointSpec is the parsed, validated configuration for one endpoint before
// its TLS material is loaded. BuildEndpoint turns a spec into an Endpoint.
type EndpointSpec struct {
	// Address is a Docker-style upstream address: "unix:///var/run/docker.sock",
	// "tcp://host:2376", or a bare path (treated as a unix socket for backward
	// compatibility with the legacy upstream.socket field).
	Address string
	// CAFile verifies the remote daemon's server certificate. Empty falls back
	// to the system roots.
	CAFile string
	// CertFile and KeyFile present a client certificate to the remote daemon
	// (mutual TLS). Both must be set together or both empty.
	CertFile string
	KeyFile  string
	// ServerName overrides the SNI / certificate hostname verified against the
	// daemon's server cert. Empty derives it from the address host.
	ServerName string
	// InsecureAllowPlainTCP permits a tcp:// endpoint with no TLS material. A
	// remote daemon reached over plaintext TCP exposes the full Docker API to
	// anyone on the path; this must be set deliberately, mirroring the
	// listener-side insecure_allow_plain_tcp acknowledgement.
	InsecureAllowPlainTCP bool
	// InsecureSkipTLSVerify disables verification of the daemon's server
	// certificate. Useful for self-signed homelab daemons; dangerous in
	// production because it defeats authentication of the upstream.
	InsecureSkipTLSVerify bool
	// TLSSystemRoots requests verified TLS using the host's system root CA pool
	// and no client certificate — the server-authentication-only case produced
	// by DOCKER_TLS_VERIFY with no DOCKER_CERT_PATH. It makes a tcp:// endpoint
	// valid without any explicit CA/cert/key material (the CA defaults to the
	// system roots). Not exposed as a YAML knob; it only originates from the
	// DOCKER_* environment drop-in.
	TLSSystemRoots bool
}

// BuildEndpoint parses spec.Address, loads any TLS material, and returns a
// dialable Endpoint. It returns a descriptive error for every malformed or
// inconsistent spec so config validation can surface the exact problem.
func BuildEndpoint(spec EndpointSpec) (Endpoint, error) {
	network, address, err := parseAddress(spec.Address)
	if err != nil {
		return Endpoint{}, err
	}

	switch network {
	case "unix":

		if spec.CertFile != "" || spec.KeyFile != "" || spec.CAFile != "" {
			return Endpoint{}, fmt.Errorf("upstream endpoint %q: TLS settings are not valid for a unix socket", spec.Address)
		}
		return Endpoint{Name: address, Network: "unix", Address: address}, nil
	case "tcp":
		tlsConfig, err := buildClientTLS(spec, address)
		if err != nil {
			return Endpoint{}, err
		}
		return Endpoint{Name: address, Network: "tcp", Address: address, TLSConfig: tlsConfig}, nil
	default:
		return Endpoint{}, fmt.Errorf("upstream endpoint %q: unsupported scheme %q (use unix:// or tcp://)", spec.Address, network)
	}
}

// ValidateSpec checks a spec's address and TLS-field consistency WITHOUT
// touching the filesystem, so config validation (including the remote
// POST /admin/validate path, where cert files may not exist on the validating
// host) can reject a malformed endpoint without loading its TLS material.
// BuildEndpoint performs the same structural checks and additionally loads the
// referenced files.
func ValidateSpec(spec EndpointSpec) error {
	network, address, err := parseAddress(spec.Address)
	if err != nil {
		return err
	}
	switch network {
	case "unix":
		if spec.CertFile != "" || spec.KeyFile != "" || spec.CAFile != "" {
			return fmt.Errorf("upstream endpoint %q: TLS settings are not valid for a unix socket", spec.Address)
		}
		return nil
	case "tcp":
		if (spec.CertFile == "") != (spec.KeyFile == "") {
			return fmt.Errorf("upstream endpoint %q: tls.cert_file and tls.key_file must be set together", spec.Address)
		}
		hasAnyTLS := spec.CertFile != "" || spec.KeyFile != "" || spec.CAFile != "" || spec.InsecureSkipTLSVerify || spec.TLSSystemRoots
		if !hasAnyTLS && !spec.InsecureAllowPlainTCP {
			return fmt.Errorf("upstream endpoint %q: TCP requires TLS (set tls.ca_file/cert_file/key_file) or insecure_allow_plain_tcp: true", spec.Address)
		}
		_ = address
		return nil
	default:
		return fmt.Errorf("upstream endpoint %q: unsupported scheme %q (use unix:// or tcp://)", spec.Address, network)
	}
}

// parseAddress splits a Docker-style upstream address into a (network, address)
// pair. A bare path with no scheme is treated as a unix socket for backward
// compatibility with the legacy upstream.socket field.
func parseAddress(raw string) (network, address string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("upstream endpoint address is empty")
	}

	if !strings.Contains(raw, "://") {
		if strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../") {
			return "unix", raw, nil
		}
		return "", "", fmt.Errorf("upstream endpoint %q: address must be a unix path or a unix://, tcp:// URL", raw)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("upstream endpoint %q: %w", raw, err)
	}

	switch u.Scheme {
	case "unix":

		if u.Host != "" {
			return "", "", fmt.Errorf("upstream endpoint %q: unix sockets use an absolute path (unix:///var/run/docker.sock)", raw)
		}
		if u.Path == "" {
			return "", "", fmt.Errorf("upstream endpoint %q: missing socket path", raw)
		}
		return "unix", u.Path, nil
	case "tcp", "http", "https":
		if u.Host == "" {
			return "", "", fmt.Errorf("upstream endpoint %q: missing host:port", raw)
		}
		host := u.Host
		if u.Port() == "" {
			return "", "", fmt.Errorf("upstream endpoint %q: TCP address must include a port (e.g. tcp://host:2376)", raw)
		}
		return "tcp", host, nil
	default:
		return "", "", fmt.Errorf("upstream endpoint %q: unsupported scheme %q (use unix:// or tcp://)", raw, u.Scheme)
	}
}

// buildClientTLS constructs the *tls.Config used to dial a remote daemon. It
// returns nil only when plaintext TCP is explicitly acknowledged.
func buildClientTLS(spec EndpointSpec, address string) (*tls.Config, error) {
	hasCert := spec.CertFile != "" || spec.KeyFile != ""
	hasAnyTLS := hasCert || spec.CAFile != "" || spec.InsecureSkipTLSVerify || spec.TLSSystemRoots

	if !hasAnyTLS {
		if spec.InsecureAllowPlainTCP {
			return nil, nil
		}
		return nil, fmt.Errorf("upstream endpoint %q: TCP requires TLS (set tls.ca_file/cert_file/key_file) or insecure_allow_plain_tcp: true", spec.Address)
	}

	if (spec.CertFile == "") != (spec.KeyFile == "") {
		return nil, fmt.Errorf("upstream endpoint %q: tls.cert_file and tls.key_file must be set together", spec.Address)
	}

	serverName := spec.ServerName
	if serverName == "" {

		if host, _, ok := splitHostPort(address); ok {
			serverName = host
		} else {
			serverName = address
		}
	}

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: spec.InsecureSkipTLSVerify,
	}

	if hasCert {
		cert, err := tls.LoadX509KeyPair(spec.CertFile, spec.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("upstream endpoint %q: loading client certificate: %w", spec.Address, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if spec.CAFile != "" {
		pem, err := os.ReadFile(spec.CAFile)
		if err != nil {
			return nil, fmt.Errorf("upstream endpoint %q: reading tls.ca_file: %w", spec.Address, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("upstream endpoint %q: tls.ca_file %q contains no valid PEM certificates", spec.Address, spec.CAFile)
		}
		tlsConfig.RootCAs = pool
	}

	return tlsConfig, nil
}

// splitHostPort splits host:port without failing on IPv6 literals the way a
// naive strings.Split would. It returns ok=false when no port is present.
func splitHostPort(hostport string) (host, port string, ok bool) {
	i := strings.LastIndex(hostport, ":")
	if i < 0 {
		return hostport, "", false
	}
	host = hostport[:i]
	port = hostport[i+1:]

	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	return host, port, port != ""
}

// SpecsFromDockerEnv reads the standard Docker client environment variables
// (DOCKER_HOST, DOCKER_TLS_VERIFY, DOCKER_CERT_PATH) and returns a single
// EndpointSpec when DOCKER_HOST names a TCP daemon, so an operator with a
// working `docker -H tcp://…` setup can point sockguard at it with no YAML.
// It returns ok=false when DOCKER_HOST is unset or names a unix socket (the
// local-socket default already covers that case).
func SpecsFromDockerEnv(getenv func(string) string) (EndpointSpec, bool) {
	host := strings.TrimSpace(getenv("DOCKER_HOST"))
	if host == "" {
		return EndpointSpec{}, false
	}
	network, _, err := parseAddress(host)
	if err != nil || network != "tcp" {
		return EndpointSpec{}, false
	}

	spec := EndpointSpec{Address: host}
	tlsVerify := getenv("DOCKER_TLS_VERIFY") != ""
	certPath := strings.TrimSpace(getenv("DOCKER_CERT_PATH"))
	if certPath != "" {
		spec.CAFile = filepath.Join(certPath, "ca.pem")
		spec.CertFile = filepath.Join(certPath, "cert.pem")
		spec.KeyFile = filepath.Join(certPath, "key.pem")
	}
	switch {
	case tlsVerify && certPath == "":

		spec.TLSSystemRoots = true
	case !tlsVerify && certPath == "":

		spec.InsecureAllowPlainTCP = true
	case !tlsVerify && certPath != "":

		spec.InsecureSkipTLSVerify = true
	}

	return spec, true
}

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
	// baseCtx is the Start context (nil until Start runs; reprobeBaseContext
	// falls back to context.Background until then). demote's re-probe goroutines
	// derive from it so they unwind promptly on shutdown instead of outliving the
	// resolver by up to one probe timeout.
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
		r.setHealth(ctx, s, err == nil)
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
	r.setHealth(context.Background(), s, false)
	if !s.reprobing.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer s.reprobing.Store(false)
		ctx, cancel := context.WithTimeout(r.reprobeBaseContext(), r.timeout)
		defer cancel()
		r.setHealth(ctx, s, r.probe(ctx, s.ep) == nil)
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
	if ctx.Err() != nil {
		return
	}
	// Probe every endpoint concurrently so the tick's wall-clock cost is the
	// slowest single probe, not the sum across endpoints — a stalled daemon no
	// longer delays the health update for the others. setHealth is mutex-guarded,
	// so the concurrent result reporting is safe. Endpoint count is small (an HA
	// set), so this is a bounded fan-out, not an unbounded goroutine spawn.
	var wg sync.WaitGroup
	for _, s := range r.states {
		wg.Add(1)
		go func(s *endpointState) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, r.timeout)
			defer cancel()
			r.setHealth(pctx, s, r.probe(pctx, s.ep) == nil)
		}(s)
	}
	wg.Wait()
}

func (r *Resolver) setHealth(ctx context.Context, s *endpointState, healthy bool) {

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
		r.logger.LogAttrs(ctx, level, "upstream endpoint health changed",
			slog.String("endpoint", s.ep.String()),
			slog.Bool("healthy", healthy),
		)
	}
	if r.onChange != nil {
		r.onChange(s.ep, healthy)
	}
}
