package upstream

import (
	"context"
	"testing"
)

func TestJoinPathSlashCombinations(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ base, request, want string }{
		{"/base/", "/x", "/base/x"},
		{"/base", "x", "/base/x"},
		{"/base", "/x", "/base/x"},
		{"/base/", "x", "/base/x"},
	} {
		if got := joinPath(tc.base, tc.request); got != tc.want {
			t.Fatalf("joinPath(%q, %q) = %q, want %q", tc.base, tc.request, got, tc.want)
		}
	}
}

func TestReprobeBaseContextFallsBackBeforeStart(t *testing.T) {
	t.Parallel()
	r, err := New([]Endpoint{{Name: "e", Network: "unix", Address: "/nonexistent/sockguard-reprobe-test.sock"}}, Options{Interval: -1})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := r.reprobeBaseContext(); got != context.Background() {
		t.Fatalf("reprobeBaseContext() before Start = %v, want context.Background()", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.baseCtx.Store(&ctx)
	if got := r.reprobeBaseContext(); got != ctx {
		t.Fatalf("reprobeBaseContext() after the base is stored = %v, want it", got)
	}
}
