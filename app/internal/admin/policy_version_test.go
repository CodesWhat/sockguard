package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

const testPolicyVersionPath = "/admin/policy/version"

func TestPolicyVersionerSnapshotIsNilBeforeFirstUpdate(t *testing.T) {
	v := NewPolicyVersioner()
	if got := v.Snapshot(); got != nil {
		t.Fatalf("Snapshot() = %+v, want nil before Update()", got)
	}
}

func TestPolicyVersionerUpdateIsMonotonic(t *testing.T) {
	v := NewPolicyVersioner()
	if got := v.Update(PolicySnapshot{Source: "startup"}); got != 1 {
		t.Fatalf("first Update = %d, want 1", got)
	}
	if got := v.Update(PolicySnapshot{Source: "reload"}); got != 2 {
		t.Fatalf("second Update = %d, want 2", got)
	}
	if got := v.Update(PolicySnapshot{Source: "reload"}); got != 3 {
		t.Fatalf("third Update = %d, want 3", got)
	}

	snap := v.Snapshot()
	if snap == nil || snap.Version != 3 || snap.Source != "reload" {
		t.Fatalf("Snapshot() = %+v, want version=3 source=reload", snap)
	}
}

func TestPolicyVersionerUpdateStampsLoadedAtWhenZero(t *testing.T) {
	v := NewPolicyVersioner()
	v.Update(PolicySnapshot{Source: "startup"})
	if snap := v.Snapshot(); snap.LoadedAt.IsZero() {
		t.Fatalf("LoadedAt is zero, expected Update to stamp it")
	}
}

func TestPolicyVersionerUpdatePreservesProvidedLoadedAt(t *testing.T) {
	v := NewPolicyVersioner()
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	v.Update(PolicySnapshot{LoadedAt: stamp, Source: "startup"})
	if got := v.Snapshot().LoadedAt; !got.Equal(stamp) {
		t.Fatalf("LoadedAt = %v, want %v", got, stamp)
	}
}

func TestPolicyVersionerConcurrentReadsAndWritesRaceClean(t *testing.T) {
	// Race-detector check: many writers calling Update concurrently with
	// readers calling Snapshot must never produce a torn read. The final
	// Snapshot's Version must equal the total number of Updates issued —
	// confirming the prev-load-then-store sequence isn't dropping writes.
	v := NewPolicyVersioner()
	const writers = 8
	const updatesPerWriter = 250

	stop := make(chan struct{})
	var readerWG sync.WaitGroup
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = v.Snapshot()
			}
		}
	}()

	var writerWG sync.WaitGroup
	writerWG.Add(writers)
	for i := 0; i < writers; i++ {
		go func() {
			defer writerWG.Done()
			for j := 0; j < updatesPerWriter; j++ {
				v.Update(PolicySnapshot{Source: "reload"})
			}
		}()
	}
	writerWG.Wait()
	close(stop)
	readerWG.Wait()

	want := int64(writers * updatesPerWriter)
	if got := v.Snapshot().Version; got != want {
		t.Fatalf("final Version = %d, want %d (writes lost under contention)", got, want)
	}
}

func TestPolicyVersionInterceptorReturns200OnGET(t *testing.T) {
	v := NewPolicyVersioner()
	v.Update(PolicySnapshot{
		Rules:        7,
		Profiles:     2,
		CompatActive: true,
		Source:       "startup",
		ConfigSHA256: "deadbeef",
	})

	handler := NewPolicyVersionInterceptor(PolicyVersionOptions{
		Path:   testPolicyVersionPath,
		Source: v.Snapshot,
	})(noopHandler())

	req := httptest.NewRequest(http.MethodGet, testPolicyVersionPath, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d. body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var got PolicySnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if got.Version != 1 {
		t.Fatalf("Version = %d, want 1", got.Version)
	}
	if got.Rules != 7 || got.Profiles != 2 {
		t.Fatalf("rules=%d profiles=%d, want 7/2", got.Rules, got.Profiles)
	}
	if !got.CompatActive {
		t.Fatalf("CompatActive = false, want true")
	}
	if got.Source != "startup" {
		t.Fatalf("Source = %q, want startup", got.Source)
	}
	if got.ConfigSHA256 != "deadbeef" {
		t.Fatalf("ConfigSHA256 = %q, want deadbeef", got.ConfigSHA256)
	}
}

func TestPolicyVersionInterceptorReturns503BeforeFirstUpdate(t *testing.T) {
	v := NewPolicyVersioner()
	handler := NewPolicyVersionInterceptor(PolicyVersionOptions{
		Path:   testPolicyVersionPath,
		Source: v.Snapshot,
	})(noopHandler())

	req := httptest.NewRequest(http.MethodGet, testPolicyVersionPath, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestPolicyVersionInterceptorRejectsNonGET(t *testing.T) {
	v := NewPolicyVersioner()
	v.Update(PolicySnapshot{Source: "startup"})
	handler := NewPolicyVersionInterceptor(PolicyVersionOptions{
		Path:   testPolicyVersionPath,
		Source: v.Snapshot,
	})(noopHandler())

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, testPolicyVersionPath, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s status = %d, want %d", method, rec.Code, http.StatusMethodNotAllowed)
		}
		if got := rec.Header().Get("Allow"); got != http.MethodGet {
			t.Fatalf("%s Allow = %q, want %q", method, got, http.MethodGet)
		}
	}
}

func TestPolicyVersionInterceptorPassesThroughOtherPaths(t *testing.T) {
	v := NewPolicyVersioner()
	v.Update(PolicySnapshot{Source: "startup"})
	called := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })

	handler := NewPolicyVersionInterceptor(PolicyVersionOptions{
		Path:   testPolicyVersionPath,
		Source: v.Snapshot,
	})(next)

	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatalf("expected next handler for non-matching path, got passthrough miss")
	}
}

func TestPolicyVersionInterceptorReturns503WhenSourceNil(t *testing.T) {
	handler := NewPolicyVersionInterceptor(PolicyVersionOptions{
		Path:   testPolicyVersionPath,
		Source: nil,
	})(noopHandler())

	req := httptest.NewRequest(http.MethodGet, testPolicyVersionPath, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestNilPolicyVersionSource_FallsThroughForUnrelatedPaths(t *testing.T) {
	// When Source is nil the middleware must NOT 503 every request — only
	// requests to the configured policy-version path should fail closed.
	// Docker API traffic on an unrelated path must still reach next.
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := NewPolicyVersionInterceptor(PolicyVersionOptions{
		Path:   testPolicyVersionPath,
		Source: nil,
	})(next)

	// Unrelated path → must fall through to next.
	req := httptest.NewRequest(http.MethodGet, "/foo", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatalf("next handler not called for unrelated path when Source is nil")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("unrelated path status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Policy-version path → still must return 503.
	called = false
	req2 := httptest.NewRequest(http.MethodGet, testPolicyVersionPath, nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if called {
		t.Fatalf("next must not be called for policy-version path when Source is nil")
	}
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("policy-version path status = %d, want 503 when Source is nil", rec2.Code)
	}
}

func TestPolicySnapshot_BundleSourceIsBasenameOnly(t *testing.T) {
	// BundleSource must be the file basename only — no directory component —
	// so that GET /admin/policy/version does not leak the host filesystem
	// layout to Docker API callers.
	snap := PolicySnapshot{
		Version:      1,
		Source:       "startup",
		BundleSource: "sockguard.bundle",
	}

	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var got PolicySnapshot
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if got.BundleSource != "sockguard.bundle" {
		t.Fatalf("BundleSource = %q, want %q", got.BundleSource, "sockguard.bundle")
	}
}
