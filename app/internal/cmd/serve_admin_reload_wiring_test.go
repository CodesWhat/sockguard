package cmd

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/filter"
	"github.com/codeswhat/sockguard/v3/app/internal/testhelp"
)

// TestRunServe_AdminListenerIsReloadedThroughItsSwappableHandler is the
// production-wiring test for the dedicated admin listener: it drives
// runServeWithDeps with a real admin listener, narrows clients.allowed_cidrs
// through a real file-triggered reload, and asserts the already-bound admin
// listener starts refusing the source. The unit tests in
// serve_reload_admin_test.go register the swappable handler themselves, so none
// of them would notice runServeWithDeps dropping setAdminSwappable or serving
// the admin chain without the swappable wrapper.
func TestRunServe_AdminListenerIsReloadedThroughItsSwappableHandler(t *testing.T) {
	tmpDir := t.TempDir()
	tmpCfg := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(tmpCfg, []byte("listen:\n  address: 127.0.0.1:0\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	originalCfgFile := cfgFile
	cfgFile = tmpCfg
	t.Cleanup(func() { cfgFile = originalCfgFile })

	var narrowed atomic.Bool
	deps := newServeTestDeps()
	deps.loadConfig = func(string) (*config.Config, error) {
		cfg := testServeConfig()
		cfg.Reload.Enabled = true
		cfg.Reload.Debounce = "10ms"
		cfg.Reload.PollInterval = "50ms"
		cfg.Admin.Enabled = true
		cfg.Admin.Listen.Address = "127.0.0.1:0"
		if narrowed.Load() {
			cfg.Clients.AllowedCIDRs = []string{"10.0.0.0/8"}
		} else {
			cfg.Clients.AllowedCIDRs = []string{"127.0.0.0/8"}
		}
		return cfg, nil
	}
	collector := &testhelp.CollectingHandler{}
	deps.newLogger = func(string, string, string) (*slog.Logger, io.Closer, error) {
		return collector.Logger(), nil, nil
	}
	deps.validateRules = func(*config.Config) ([]*filter.CompiledRule, error) {
		return stubCompiledRules(), nil
	}
	deps.dialUpstream = func(string, string, time.Duration) (net.Conn, error) {
		return &serveTestConn{}, nil
	}
	deps.createServeListener = func(*config.Config) (net.Listener, error) {
		return &serveTestListener{}, nil
	}

	// Only the admin listener serves for real: the main listener is a stub.
	var adminAddr atomic.Value
	createAdmin := deps.createAdminListener
	deps.createAdminListener = func(cfg *config.Config) (net.Listener, error) {
		ln, err := createAdmin(cfg)
		if err == nil {
			adminAddr.Store(ln.Addr().String())
		}
		return ln, err
	}
	serve := deps.startServing
	deps.startServing = func(srv *http.Server, ln net.Listener, errc chan<- error) {
		if _, stub := ln.(*serveTestListener); stub {
			return
		}
		serve(srv, ln, errc)
	}
	deps.removePath = func(string) error { return nil }

	adminStatus := func() int {
		addr, _ := adminAddr.Load().(string)
		client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
		resp, err := client.Get("http://" + addr + "/no-such-admin-path")
		if err != nil {
			t.Errorf("admin GET: %v", err)
			return 0
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	var before, after int
	deps.notifySignals = func(c chan<- os.Signal, _ ...os.Signal) {
		go func() {
			defer func() { c <- syscall.SIGINT }()
			if !collector.WaitForMessage("config hot-reload enabled", 5*time.Second) {
				return
			}
			before = adminStatus()
			narrowed.Store(true)
			if err := os.WriteFile(tmpCfg, []byte("listen:\n  address: 127.0.0.1:0\n# touched\n"), 0o600); err != nil {
				t.Errorf("touch config: %v", err)
				return
			}
			collector.WaitForMessage("config reload applied", 5*time.Second)
			after = adminStatus()
		}()
	}

	cmd := newServeCommand()
	if err := runServeWithDeps(cmd, nil, deps); err != nil {
		t.Fatalf("runServeWithDeps() error = %v", err)
	}

	if before != http.StatusNotFound {
		t.Fatalf("admin status before reload = %d, want 404 (127.0.0.1 admitted); records: %#v", before, collector.Records())
	}
	if after != http.StatusForbidden {
		t.Fatalf("admin status after the reload removed 127.0.0.0/8 = %d, want 403: the admin listener is not served through the reload coordinator's swappable handler; records: %#v", after, collector.Records())
	}
}
