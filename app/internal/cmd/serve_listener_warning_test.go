package cmd

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
)

type listenerWarningBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *listenerWarningBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}

func (b *listenerWarningBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

func TestRunServeWarnsWhenDefaultProfileIsExcludedByListener(t *testing.T) {
	t.Parallel()

	cfg := testServeConfig()
	profileRules := []config.RuleConfig{{Match: config.MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"}}
	cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "ci", Rules: profileRules}, {Name: "ops", Rules: profileRules}}
	cfg.Clients.DefaultProfile = "ops"
	cfg.Listeners = []config.ListenerConfig{{
		Name:            "ci",
		ListenConfig:    config.ListenConfig{Address: "127.0.0.1:0"},
		AllowedProfiles: []string{"ci"},
	}}

	deps := newServeTestDeps()
	deps.loadConfig = func(string) (*config.Config, error) { return cfg, nil }
	var logs listenerWarningBuffer
	deps.newLogger = func(string, string, string) (*slog.Logger, io.Closer, error) {
		return slog.New(slog.NewTextHandler(&logs, nil)), nil, nil
	}
	deps.validateRules = func(*config.Config) ([]*filter.CompiledRule, error) { return stubCompiledRules(), nil }
	deps.dialUpstream = func(string, string, time.Duration) (net.Conn, error) { return &serveTestConn{}, nil }
	deps.createNamedListener = func(*config.Config, config.ListenerConfig) (net.Listener, error) { return &serveTestListener{}, nil }
	deps.startServing = func(*http.Server, net.Listener, chan<- error) {}
	deps.notifySignals = func(ch chan<- os.Signal, _ ...os.Signal) { ch <- os.Interrupt }
	deps.shutdownServer = func(*http.Server, context.Context) error { return nil }

	if err := runServeWithDeps(newServeCommand(), nil, deps); err != nil {
		t.Fatalf("runServeWithDeps() = %v, want nil", err)
	}
	got := logs.String()
	for _, want := range []string{"default profile is not allowed on listener", "listener=ci", "default_profile=ops"} {
		if !strings.Contains(got, want) {
			t.Fatalf("warning log missing %q: %s", want, got)
		}
	}
}

func TestRunServeDoesNotWarnForWildcardOrIncludedDefaultProfile(t *testing.T) {
	t.Parallel()

	for _, allowed := range [][]string{{config.WildcardProfile}, {"ops"}} {
		var logs listenerWarningBuffer
		cfg := testServeConfig()
		profileRules := []config.RuleConfig{{Match: config.MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"}}
		cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "ops", Rules: profileRules}}
		cfg.Clients.DefaultProfile = "ops"
		cfg.Listeners = []config.ListenerConfig{{Name: "ci", ListenConfig: config.ListenConfig{Address: "127.0.0.1:0"}, AllowedProfiles: allowed}}
		deps := newServeTestDeps()
		deps.loadConfig = func(string) (*config.Config, error) { return cfg, nil }
		deps.newLogger = func(string, string, string) (*slog.Logger, io.Closer, error) {
			return slog.New(slog.NewTextHandler(&logs, nil)), nil, nil
		}
		deps.validateRules = func(*config.Config) ([]*filter.CompiledRule, error) { return stubCompiledRules(), nil }
		deps.dialUpstream = func(string, string, time.Duration) (net.Conn, error) { return &serveTestConn{}, nil }
		deps.createNamedListener = func(*config.Config, config.ListenerConfig) (net.Listener, error) { return &serveTestListener{}, nil }
		deps.startServing = func(*http.Server, net.Listener, chan<- error) {}
		deps.notifySignals = func(ch chan<- os.Signal, _ ...os.Signal) { ch <- os.Interrupt }
		deps.shutdownServer = func(*http.Server, context.Context) error { return nil }
		if err := runServeWithDeps(newServeCommand(), nil, deps); err != nil {
			t.Fatalf("runServeWithDeps(allowed=%v) = %v", allowed, err)
		}
		if strings.Contains(logs.String(), "default profile is not allowed on listener") {
			t.Fatalf("unexpected exclusion warning for allowed=%v: %s", allowed, logs.String())
		}
	}
}
