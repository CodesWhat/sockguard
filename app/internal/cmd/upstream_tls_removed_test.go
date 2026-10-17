package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/testcert"
	"github.com/codeswhat/sockguard/v3/app/internal/testhelp"
	"github.com/codeswhat/sockguard/v3/app/internal/upstream"
	"github.com/spf13/cobra"
)

func TestValidateRejectsRemovedDockerTLSFallback(t *testing.T) {
	clearSockguardEnv(t)
	t.Setenv("DOCKER_HOST", "tcp://daemon:2376")
	t.Setenv("DOCKER_TLS", "1")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	previous := cfgFile
	cfgFile = path
	t.Cleanup(func() { cfgFile = previous })
	var output bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&output)
	command.SetErr(&output)
	err := runValidate(command, nil)
	if err == nil || !strings.Contains(err.Error(), "removed in v3.0.0") {
		t.Fatalf("validate error = %v, want removed Docker TLS fallback", err)
	}
	if strings.Contains(output.String(), "validation passed") {
		t.Fatal("reported success for removed fallback")
	}
	cfg := config.Defaults()
	if _, err := newServeRuntime(&cfg, newDiscardLogger(), newServeTestDeps()); err == nil || !strings.Contains(err.Error(), "removed in v3.0.0") {
		t.Fatalf("startup error = %v, want removed Docker TLS fallback", err)
	}
}

func TestStartupAndCLIRejectRemovedYAMLSetting(t *testing.T) {
	clearSockguardEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("upstream:\n  endpoints:\n    - address: unix:///run/docker.sock\n      insecure_skip_tls_verify: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := cfgFile
	cfgFile = path
	t.Cleanup(func() { cfgFile = previous })
	var output bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&output)
	command.SetErr(&output)
	for _, err := range []error{runValidate(command, nil), runServeWithDeps(command, nil, newServeDeps())} {
		if err == nil || !strings.Contains(err.Error(), "removed in v3.0.0") {
			t.Fatalf("command error = %v, want removed-key guidance", err)
		}
	}
}

func TestV3UpstreamTLSPrecedenceAndTransportWarnings(t *testing.T) {
	bundle, err := testcert.WriteMutualTLSBundle(t.TempDir(), "daemon.internal")
	if err != nil {
		t.Fatal(err)
	}
	certDir := t.TempDir()
	for name, source := range map[string]string{"ca.pem": bundle.CAFile, "cert.pem": bundle.ClientCertFile, "key.pem": bundle.ClientKeyFile} {
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(certDir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, verify := range []string{"0", "false", "1"} {
		env := map[string]string{"DOCKER_HOST": "tcp://daemon.internal:2376", "DOCKER_TLS": "1", "DOCKER_TLS_VERIFY": verify, "DOCKER_CERT_PATH": certDir}
		spec, ok, err := upstream.SpecsFromDockerEnv(func(key string) (string, bool) { value, present := env[key]; return value, present })
		if err != nil || !ok {
			t.Fatalf("verified environment: %v %v", ok, err)
		}
		endpoint, err := upstream.BuildEndpoint(spec)
		if err != nil {
			t.Fatal(err)
		}
		if endpoint.TLSConfig == nil || endpoint.TLSConfig.InsecureSkipVerify || len(endpoint.TLSConfig.Certificates) != 1 {
			t.Fatal("verified mutual TLS was not retained")
		}
	}
	for _, tc := range []struct {
		name     string
		endpoint config.UpstreamEndpoint
		warning  string
	}{
		{"verified", config.UpstreamEndpoint{Address: "tcp://daemon.internal:2376", TLS: config.UpstreamTLSConfig{CAFile: bundle.CAFile}}, ""},
		{"redundant plaintext grant", config.UpstreamEndpoint{Address: "tcp://daemon.internal:2376", TLS: config.UpstreamTLSConfig{CAFile: bundle.CAFile}, InsecureAllowPlainTCP: true}, "TLS is selected"},
		{"plain TCP", config.UpstreamEndpoint{Address: "tcp://daemon.internal:2375", InsecureAllowPlainTCP: true}, "uses plaintext TCP"},
		{"Unix", config.UpstreamEndpoint{Address: "unix:///run/docker.sock", InsecureAllowPlainTCP: true}, "has no effect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Upstream.Endpoints = []config.UpstreamEndpoint{tc.endpoint}
			collector := &testhelp.CollectingHandler{}
			specs, legacy, err := resolveUpstreamSpecs(&cfg, func(key string) (string, bool) {
				if key == "DOCKER_HOST" {
					return "tcp://ignored:2376", true
				}
				if key == "DOCKER_TLS" {
					return "1", true
				}
				return "", false
			}, collector.Logger())
			if err != nil || legacy || len(specs) != 1 || specs[0].Address != tc.endpoint.Address {
				t.Fatalf("explicit endpoint precedence: %v %v %v", specs, legacy, err)
			}
			if tc.warning != "" {
				found := false
				for _, record := range collector.Records() {
					if strings.Contains(record.Message, tc.warning) {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing %q warning: %#v", tc.warning, collector.Records())
				}
			}
			if tc.warning == "" && len(collector.Records()) != 0 {
				t.Fatal(collector.Records())
			}
		})
	}
}

func TestReloadRejectsRemovedTLSSettingAndKeepsServing(t *testing.T) {
	cfg := config.Defaults()
	fixture := newReloadCoordinatorFixture(t, &cfg)
	defer fixture.coordinator.stop()
	fixture.coordinator.deps.loadConfig = config.Load
	data := []byte("upstream:\n  endpoints:\n    - address: unix:///run/docker.sock\n      insecure_skip_tls_verify: false\n")
	if err := os.WriteFile(fixture.cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.coordinator.reload()
	if count, found := fixture.reloadCount("reject_load"); !found || count != 1 {
		t.Fatalf("reload reject_load = %d,%v; logs: %s", count, found, fixture.logBuf.String())
	}
	if !strings.Contains(fixture.logBuf.String(), "removed in v3.0.0") {
		t.Fatal(fixture.logBuf.String())
	}
	rec := httptest.NewRecorder()
	fixture.swappable.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Body.String() != "v1" {
		t.Fatalf("active handler changed: %s", rec.Body.String())
	}
}
