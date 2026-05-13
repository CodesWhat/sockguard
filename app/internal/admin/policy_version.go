package admin

import (
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
)

// PolicySnapshot is the in-process record of a single active policy
// generation. It is published once at startup and replaced on every
// successful hot reload. Operators query it via GET <admin.policy_version_path>
// to confirm that a configuration change actually took effect.
//
// Version is a monotonic counter starting at 1 on the first publish; it
// only ticks on a successful apply, so a stable Version across two scrapes
// means the running policy genuinely did not move.
type PolicySnapshot struct {
	Version      int64     `json:"version"`
	LoadedAt     time.Time `json:"loaded_at"`
	Rules        int       `json:"rules"`
	Profiles     int       `json:"profiles"`
	CompatActive bool      `json:"compat_active"`
	Source       string    `json:"source"` // "startup" or "reload"
	ConfigSHA256 string    `json:"config_sha256,omitempty"`
	// BundleSource is the basename (filename only, no directory component) of
	// the sigstore bundle file that vouched for the running policy, or ""
	// when policy_bundle.enabled=false. The basename is sufficient to tell
	// operators which bundle was loaded without leaking the host's filesystem
	// layout to Docker API callers on the main listener.
	BundleSource string `json:"bundle_source,omitempty"`
	// BundleSigner is a stable identifier of the accepting trust path:
	// "keyed:<spki-fingerprint>" or "keyless:<issuer>:<san-pattern>".
	// Empty when policy_bundle is disabled.
	BundleSigner string `json:"bundle_signer,omitempty"`
	// BundleDigest is the sha256 hex digest of the YAML bytes verified
	// against the bundle. Empty when policy_bundle is disabled. This is the
	// same digest the bundle signs over, so it doubles as proof that the
	// YAML on disk matches what the operator published.
	BundleDigest string `json:"bundle_digest,omitempty"`
}

// PolicyVersioner publishes the active policy snapshot. The store side
// (Update) is serialized by an internal mutex so the counter can't drop an
// increment under concurrent callers — production traffic only ever comes
// from the reload coordinator, but the contract is "thread-safe", so we
// don't lean on the caller's serialization. The load side (Snapshot) uses
// atomic.Pointer for wait-free reads.
type PolicyVersioner struct {
	mu      sync.Mutex
	current atomic.Pointer[PolicySnapshot]
}

// NewPolicyVersioner returns a versioner with no snapshot yet. Callers
// must invoke Update at least once before HTTP queries can succeed; until
// then the endpoint returns 503.
func NewPolicyVersioner() *PolicyVersioner { return &PolicyVersioner{} }

// Update stamps the supplied snapshot as the active generation, assigning
// a fresh monotonic Version (prev+1, or 1 if this is the first call). The
// caller-supplied Version field on snap is ignored — the counter is owned
// by the versioner. Returns the assigned version so callers can mirror it
// into metrics / logs.
//
// Update is safe to call from any goroutine; the load-then-store on the
// counter happens under v.mu, so concurrent callers cannot collide on the
// same Version value.
func (v *PolicyVersioner) Update(snap PolicySnapshot) int64 {
	v.mu.Lock()
	defer v.mu.Unlock()

	prev := v.current.Load()
	var next int64 = 1
	if prev != nil {
		next = prev.Version + 1
	}
	snap.Version = next
	if snap.LoadedAt.IsZero() {
		snap.LoadedAt = time.Now()
	}
	v.current.Store(&snap)
	return next
}

// Snapshot returns the current active generation, or nil if Update has
// never been called. Callers must not mutate the returned pointer.
func (v *PolicyVersioner) Snapshot() *PolicySnapshot {
	return v.current.Load()
}

// PolicyVersionOptions configures NewPolicyVersionInterceptor.
//
// Path must start with "/". Source is the snapshot accessor — production
// wiring passes (*PolicyVersioner).Snapshot, tests pass a closure. A nil
// Source degrades to a 503 middleware so a wiring bug fails closed instead
// of returning bogus data.
type PolicyVersionOptions struct {
	Path   string
	Source func() *PolicySnapshot
	Logger *slog.Logger
}

// NewPolicyVersionInterceptor returns a middleware that short-circuits
// GET <path> with a JSON snapshot of the active policy generation. Any
// other method on <path> returns 405 Allow: GET. Requests for other
// paths fall through to next.
//
// The endpoint is intentionally read-only and does not accept a request
// body: it reports state, never mutates it.
func NewPolicyVersionInterceptor(opts PolicyVersionOptions) func(http.Handler) http.Handler {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Source == nil {
		return serviceUnavailableMiddleware(opts.Path, "admin policy versioner not configured", opts.Logger)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != opts.Path {
				next.ServeHTTP(w, r)
				return
			}
			if r.Method != http.MethodGet {
				logging.SetDeniedWithCode(w, r, "admin_method_not_allowed", "GET required", nil)
				w.Header().Set("Allow", http.MethodGet)
				_ = httpjson.Write(w, http.StatusMethodNotAllowed, httpjson.ErrorResponse{Message: "method not allowed"})
				return
			}
			snap := opts.Source()
			if snap == nil {
				logging.SetDeniedWithCode(w, r, "admin_policy_version_unavailable", "policy version not yet published", nil)
				_ = httpjson.Write(w, http.StatusServiceUnavailable, httpjson.ErrorResponse{Message: "policy version unavailable"})
				return
			}
			if err := httpjson.Write(w, http.StatusOK, snap); err != nil {
				opts.Logger.WarnContext(r.Context(), "admin policy version: failed to encode response", "error", err)
			}
		})
	}
}
