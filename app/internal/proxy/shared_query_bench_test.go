package proxy

import (
	"net/http"
	"strings"
	"testing"
)

// unsharedDockerBoolValueOrDefault is a verbatim copy of what timeout.go did
// before the shared parse landed: one parse to test the key's presence and a
// second to read its value.
func unsharedDockerBoolValueOrDefault(r *http.Request, key string, def bool) bool {
	if _, ok := r.URL.Query()[key]; !ok {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get(key))) {
	case "", "0", "no", "false", "none":
		return false
	default:
		return true
	}
}

// BenchmarkSharedQueryStatsClassification covers this package's per-request
// repeat: classifying GET /containers/{id}/stats as finite or streaming reads
// ?stream= twice.
func BenchmarkSharedQueryStatsClassification(b *testing.B) {
	const target = "/containers/abc123/stats?stream=0&one-shot=1"

	b.Run("shared", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			r := sharedQueryRequest(http.MethodGet, target)
			_ = dockerBoolValueOrDefault(r, "stream", true)
		}
	})
	b.Run("unshared", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			r := sharedQueryRequest(http.MethodGet, target)
			_ = unsharedDockerBoolValueOrDefault(r, "stream", true)
		}
	})
}
