package filter

import (
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// unsharedDockerBoolValue, unsharedServiceVersionQuery and
// unsharedServiceManualRollbackQuery are verbatim copies of what swarm.go and
// resource_limit_guard.go did before the shared parse landed. They exist only
// so the benchmarks below can measure both sides in one run instead of asking
// a reader to diff two `go test -bench` outputs across a checkout.
func unsharedDockerBoolValue(r *http.Request, name string) bool {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get(name))) {
	case "", "0", "no", "false", "none":
		return false
	default:
		return true
	}
}

func unsharedServiceVersionQuery(r *http.Request) (uint64, bool) {
	values := r.URL.Query()["version"]
	if len(values) != 1 {
		return 0, false
	}
	v, err := strconv.ParseUint(values[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func unsharedServiceManualRollbackQuery(r *http.Request) (manualRollback, valid bool) {
	values, present := r.URL.Query()["rollback"]
	if !present {
		return false, true
	}
	if len(values) != 1 {
		return false, false
	}
	return strings.EqualFold(values[0], "previous"), true
}

// BenchmarkSharedQuerySwarmUpdate covers the largest per-request repeat in this
// package: three rotate* flags read off one POST /swarm/update. Both arms build
// the same request with the same per-request state attached, so the delta is
// the parse the shared arm no longer repeats.
func BenchmarkSharedQuerySwarmUpdate(b *testing.B) {
	const target = "/swarm/update?version=11&rotateWorkerToken=0&rotateManagerToken=0&rotateManagerUnlockKey=0&registryAuthFrom=spec"

	b.Run("shared", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			r := newSharedQueryRequest(http.MethodPost, target, nil, true)
			_ = dockerBoolValue(r, "rotateWorkerToken")
			_ = dockerBoolValue(r, "rotateManagerToken")
			_ = dockerBoolValue(r, "rotateManagerUnlockKey")
		}
	})
	b.Run("unshared", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			r := newSharedQueryRequest(http.MethodPost, target, nil, true)
			_ = unsharedDockerBoolValue(r, "rotateWorkerToken")
			_ = unsharedDockerBoolValue(r, "rotateManagerToken")
			_ = unsharedDockerBoolValue(r, "rotateManagerUnlockKey")
		}
	})
}

// BenchmarkSharedQueryServiceUpdateGuard covers the resource-limit guard's two
// reads of one POST /services/{id}/update query.
func BenchmarkSharedQueryServiceUpdateGuard(b *testing.B) {
	const target = "/services/svc1/update?version=42&rollback=previous&registryAuthFrom=spec"

	b.Run("shared", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			r := newSharedQueryRequest(http.MethodPost, target, nil, true)
			_, _ = serviceVersionQuery(r)
			_, _ = serviceManualRollbackQuery(r)
		}
	})
	b.Run("unshared", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			r := newSharedQueryRequest(http.MethodPost, target, nil, true)
			_, _ = unsharedServiceVersionQuery(r)
			_, _ = unsharedServiceManualRollbackQuery(r)
		}
	})
}

// BenchmarkSharedQueryBuildRequest is the build-request case from the roadmap
// item, and it is the control rather than a win. buildPolicy.inspect is the
// only thing that reads the query of a POST /build anywhere in the chain — the
// proxy's deadline classifier exempts /build on the path alone, before it would
// look at one — so there is no second parse to collapse and this number is
// expected to sit level with the pre-change one. It is here to keep that "no
// repeat on this path" claim honest: add a second query reader to the build
// surface and the count moves, which is the signal to check that the two
// readers are sharing.
func BenchmarkSharedQueryBuildRequest(b *testing.B) {
	policy := newBuildPolicy(BuildOptions{AllowRemoteContext: true, AllowRunInstructions: true})
	target := "/build?t=app%3Alatest&dockerfile=Dockerfile&networkmode=bridge&nocache=1&rm=1&pull=1&buildargs=" +
		url.QueryEscape(`{"VERSION":"1.0","COMMIT":"abc"}`)
	logger := slog.New(slog.DiscardHandler)

	b.ReportAllocs()
	for b.Loop() {
		r := newSharedQueryRequest(http.MethodPost, target, nil, true)
		if _, err := policy.inspect(logger, r, NormalizePath(r.URL.Path)); err != nil {
			b.Fatalf("inspect() error = %v", err)
		}
	}
}
