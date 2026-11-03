package cmd

import (
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/upstream"
)

func TestUpstreamLabelShapes(t *testing.T) {
	t.Parallel()
	single, err := upstream.New([]upstream.Endpoint{{Name: "primary", Network: "unix", Address: "/nonexistent/a.sock"}}, upstream.Options{Interval: -1})
	if err != nil {
		t.Fatalf("upstream.New() error = %v", err)
	}
	if got := upstreamLabel(single); got != "primary" {
		t.Fatalf("upstreamLabel(single) = %q, want primary", got)
	}
	failover, err := upstream.New([]upstream.Endpoint{
		{Name: "primary", Network: "unix", Address: "/nonexistent/a.sock"},
		{Name: "backup", Network: "unix", Address: "/nonexistent/b.sock"},
	}, upstream.Options{Interval: -1})
	if err != nil {
		t.Fatalf("upstream.New() error = %v", err)
	}
	if got := upstreamLabel(failover); got != "primary (+failover)" {
		t.Fatalf("upstreamLabel(failover) = %q, want primary (+failover)", got)
	}
}

func TestEffectiveResponseHeaderTimeout(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		value string
		want  string
	}{
		{"off", "-1ns"},
		{"", "0s"},
		{"30s", "30s"},
		{"garbage", "0s"},
	} {
		cfg := &config.Config{}
		cfg.Upstream.ResponseHeaderTimeout = tc.value
		if got := effectiveResponseHeaderTimeout(cfg).String(); got != tc.want {
			t.Fatalf("effectiveResponseHeaderTimeout(%q) = %s, want %s", tc.value, got, tc.want)
		}
	}
}
