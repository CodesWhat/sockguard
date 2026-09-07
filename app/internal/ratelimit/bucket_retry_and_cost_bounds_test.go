package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/logging"
)

// Four mutants in this package stay alive on purpose, all verified by
// hand-applying the mutation and re-running it:
//
//   - ratelimit.go AllowN, `cost < 1`: at cost == 1 both arms leave cost at 1.
//   - ratelimit.go AllowN, `elapsedMS > 0`: elapsedMS is zero exactly when
//     nowMS == lastMS, and the refill branch then computes a zero refill and
//     stores the same timestamp the else branch keeps.
//   - ratelimit.go AllowN, `newTokenFP > b.burstFP`: at equality both arms
//     leave the bucket at the burst ceiling.
//   - middleware.go New, `globalMax <= 0` in the no-profiles early return:
//     with no profiles and no global limit, the later `!hasAny && globalMax
//     <= 0` return hands back the same noop pair.

// TestBucket_AllowN_GivesUpAfterExactlyMaxCASRetries pins the AllowN retry
// bound documented above maxCASRetries: when every single CAS attempt loses
// the race, the loop must retry exactly maxCASRetries times and then deny
// conservatively with retryAfter=1. This kills a mutant that widens the loop
// guard from `i < maxCASRetries` to `i <= maxCASRetries`, which would run one
// extra iteration (101 hook invocations instead of 100) before giving up.
//
// casFailHook fires immediately before the pending CompareAndSwap. Flipping
// the low bit of the packed state there invalidates the "old" value the CAS
// is about to compare against, so every attempt loses. Burst is set large
// enough (1000 tokens) that the ±1-unit perturbation from the flip never
// drops available tokens below the 1-unit cost, so the loop is exercised for
// its full width instead of bailing out early on the out-of-tokens path.
func TestBucket_AllowN_GivesUpAfterExactlyMaxCASRetries(t *testing.T) {
	// Deliberately not parallel: casFailHook is a package-level var (see
	// TestBucket_AllowN_RetriesAfterLostCAS for the same constraint).
	original := casFailHook
	t.Cleanup(func() { casFailHook = original })

	frozen := time.Now()
	b := newBucket(1, 1000, func() time.Time { return frozen })

	attempts := 0
	casFailHook = func(hooked *bucket, _ int) {
		attempts++
		hooked.state.Store(hooked.state.Load() ^ 1)
	}

	ok, retryAfter := b.AllowN(1)

	if ok || retryAfter != 1 {
		t.Fatalf("AllowN() after every CAS attempt lost = (%v, %d), want (false, 1) (the give-up path)", ok, retryAfter)
	}
	if attempts != maxCASRetries {
		t.Fatalf("CAS attempts = %d, want %d (loop bound i < maxCASRetries)", attempts, maxCASRetries)
	}
}

// TestCompileEndpointCosts_NoMethodsCompilesToNilMatchAll pins two contracts
// for an EndpointCost that declares no Methods. First, it must compile to a
// nil methods map, not an empty non-nil one: this kills a mutant that widens
// `len(ec.Methods) > 0` to `>= 0` in compileEndpointCosts, which is always
// true and so unconditionally allocates the map (make with zero entries)
// even when Methods was never set. Second, and independently of the map's
// nil-ness, a rule with no Methods must still apply its cost to every HTTP
// method on a path-matching request (costFor's own `len(ec.methods) > 0`
// guard treats nil and empty identically, so this half alone would not
// distinguish real code from the mutant — the nil check above is what does).
func TestCompileEndpointCosts_NoMethodsCompilesToNilMatchAll(t *testing.T) {
	t.Parallel()
	costs := []EndpointCost{{PathGlob: "/build", Cost: 5}}
	compiled := compileEndpointCosts(costs)
	if len(compiled) != 1 {
		t.Fatalf("compileEndpointCosts returned %d entries, want 1", len(compiled))
	}
	if compiled[0].methods != nil {
		t.Fatalf("methods = %#v, want nil for an EndpointCost with no Methods declared", compiled[0].methods)
	}

	cp := &compiledProfile{endpointCosts: compiled}
	for _, method := range []string{"GET", "POST", "DELETE"} {
		if got := cp.costFor(method, "/build"); got != 5 {
			t.Fatalf("costFor(%q, /build) = %g, want 5 (no Methods restriction must match every method)", method, got)
		}
	}
}

// TestMiddleware_UnmatchedProfileNoGlobalConcurrency_SkipsNormalization pins
// the pass-through contract for a request that resolves to no compiled
// profile when GlobalConcurrency is not configured. serve() must take the
// immediate `cp == nil && h.globalTracker == nil` branch and return without
// touching request meta at all.
//
// This kills a mutant that widens the `globalMax > 0` allocation guard in
// Middleware to `>= 0`. Since globalMax is 0 here (no GlobalConcurrency),
// that mutant would be true and allocate a GlobalInflightTracker anyway,
// making h.globalTracker non-nil and defeating the fast-path check — the
// handler would fall through into path normalization it has no configured
// reason to perform, which is observable via meta.NormPath ending up
// populated instead of left alone.
func TestMiddleware_UnmatchedProfileNoGlobalConcurrency_SkipsNormalization(t *testing.T) {
	t.Parallel()
	opts := MiddlewareOptions{
		Profiles: map[string]ProfileOptions{
			// Compiles to non-nil (hasAny=true) so Middleware does not take
			// the earlier "no profiles at all, no global gate" noop return;
			// the branch under test is the per-request nil cp lookup further
			// down in serve().
			"ci": {Rate: &RateOptions{TokensPerSecond: 1, Burst: 1}},
		},
		// No GlobalConcurrency: globalMax stays 0.
		ResolveProfile: resolveProfileFn("other"), // never a key in Profiles above
	}
	h := mustMiddleware(t, newTestLogger(), nil, nil, opts)(okHandler)

	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	req = req.WithContext(metaContext(req, meta))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (unmatched profile + no global gate must pass through)", rec.Code, http.StatusOK)
	}
	if meta.NormPath != "" {
		t.Fatalf("meta.NormPath = %q, want empty (the pass-through branch must return before any path normalization)", meta.NormPath)
	}
}
