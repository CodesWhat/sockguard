package cmd

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/upstream"
)

// warnLabelACLOnce must fire only when container-label ACLs are enabled, and
// only once per Once even though the handler chain (and therefore the call
// site) is rebuilt on every config hot-reload.
func TestWarnLabelACLOnce(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var once sync.Once

	disabled := config.Defaults()
	warnLabelACLOnce(&disabled, logger, &once)
	if buf.Len() != 0 {
		t.Fatalf("disabled config logged: %q", buf.String())
	}

	enabled := config.Defaults()
	enabled.Clients.ContainerLabels.Enabled = true
	warnLabelACLOnce(&enabled, logger, &once)
	if got := strings.Count(buf.String(), "container-label ACLs are enabled"); got != 1 {
		t.Fatalf("warning count after first enabled build = %d, want 1; log: %q", got, buf.String())
	}

	// Simulate the chain rebuild a hot-reload performs: same process, same
	// Once, enabled again — must NOT log a second time.
	warnLabelACLOnce(&enabled, logger, &once)
	if got := strings.Count(buf.String(), "container-label ACLs are enabled"); got != 1 {
		t.Fatalf("warning count after reload rebuild = %d, want still 1; log: %q", got, buf.String())
	}

	// A fresh Once (fresh process) with the feature enabled warns again.
	var fresh sync.Once
	buf.Reset()
	warnLabelACLOnce(&enabled, logger, &fresh)
	if got := strings.Count(buf.String(), "container-label ACLs are enabled"); got != 1 {
		t.Fatalf("warning count with fresh Once = %d, want 1; log: %q", got, buf.String())
	}
}

// warnRulesVersionPrefixOnce must fire only when a rule pattern carries a Docker
// API version prefix, and only once per Once across reload chain rebuilds.
func TestWarnRulesVersionPrefixOnce(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var once sync.Once

	clean := config.Defaults()
	clean.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: "GET", Path: "/containers/json"}, Action: "allow"},
	}
	warnRulesVersionPrefixOnce(&clean, logger, &once)
	if buf.Len() != 0 {
		t.Fatalf("clean rules logged: %q", buf.String())
	}

	prefixed := config.Defaults()
	prefixed.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: "GET", Path: "/v1.45/containers/json"}, Action: "allow"},
	}
	warnRulesVersionPrefixOnce(&prefixed, logger, &once)
	if got := strings.Count(buf.String(), "Docker API version prefix"); got != 1 {
		t.Fatalf("warning count after first prefixed build = %d, want 1; log: %q", got, buf.String())
	}
	if !strings.Contains(buf.String(), "/v1.45/containers/json") {
		t.Fatalf("warning omitted the offending pattern; log: %q", buf.String())
	}

	// Reload chain rebuild with the same Once must not warn again.
	warnRulesVersionPrefixOnce(&prefixed, logger, &once)
	if got := strings.Count(buf.String(), "Docker API version prefix"); got != 1 {
		t.Fatalf("warning count after reload rebuild = %d, want still 1; log: %q", got, buf.String())
	}
}

func TestWarnInsecureUpstreamSpecs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec upstream.EndpointSpec
		want string // substring expected in the log, "" means no log
	}{
		{name: "plain tcp", spec: upstream.EndpointSpec{Address: "tcp://daemon:2375", InsecureAllowPlainTCP: true}, want: "plaintext TCP"},
		{name: "skip verify", spec: upstream.EndpointSpec{Address: "tcp://daemon:2376", InsecureSkipTLSVerify: true}, want: "skips TLS certificate verification"},
		{name: "secure", spec: upstream.EndpointSpec{Address: "tcp://daemon:2376", CertFile: "c", KeyFile: "k"}, want: ""},
		{name: "unix socket", spec: upstream.EndpointSpec{Address: "/var/run/docker.sock"}, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))
			warnInsecureUpstreamSpecs(logger, []upstream.EndpointSpec{tt.spec}, "test")
			if tt.want == "" {
				if buf.Len() != 0 {
					t.Fatalf("expected no log, got %q", buf.String())
				}
				return
			}
			if !strings.Contains(buf.String(), tt.want) {
				t.Fatalf("log = %q, want substring %q", buf.String(), tt.want)
			}
		})
	}

	// A nil logger must be a safe no-op.
	warnInsecureUpstreamSpecs(nil, []upstream.EndpointSpec{{Address: "tcp://x:1", InsecureAllowPlainTCP: true}}, "test")
}
