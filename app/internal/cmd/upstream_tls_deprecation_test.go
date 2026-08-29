package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/testhelp"
)

func TestResolveUpstreamSpecsWarnsAboutTLSVerificationDeprecation(t *testing.T) {
	tests := []struct {
		name                  string
		yaml                  string
		env                   map[string]string
		wantDeprecation       bool
		wantPlaintextWarning  bool
		wantSource            string
		wantDeprecatedSetting string
		wantReplacement       string
	}{
		{
			name: "explicit YAML",
			yaml: `
upstream:
  endpoints:
    - address: tcp://daemon.internal:2376
      insecure_skip_tls_verify: true
`,
			wantDeprecation:       true,
			wantSource:            "upstream.endpoints config",
			wantDeprecatedSetting: "upstream.endpoints[].insecure_skip_tls_verify",
			wantReplacement:       "upstream.endpoints[].tls.ca_file",
		},
		{
			name: "Docker environment fallback",
			env: map[string]string{
				"DOCKER_HOST":      "tcp://daemon.internal:2376",
				"DOCKER_CERT_PATH": "/certs",
			},
			wantDeprecation:       true,
			wantSource:            "DOCKER_HOST environment",
			wantDeprecatedSetting: "DOCKER_CERT_PATH without DOCKER_TLS_VERIFY",
			wantReplacement:       "DOCKER_TLS_VERIFY=1",
		},
		{
			name: "both insecure flags",
			yaml: `
upstream:
  endpoints:
    - address: tcp://daemon.internal:2376
      insecure_allow_plain_tcp: true
      insecure_skip_tls_verify: true
`,
			wantDeprecation:       true,
			wantPlaintextWarning:  true,
			wantSource:            "upstream.endpoints config",
			wantDeprecatedSetting: "upstream.endpoints[].insecure_skip_tls_verify",
			wantReplacement:       "upstream.endpoints[].tls.ca_file",
		},
		{
			name: "secure endpoint",
			yaml: `
upstream:
  endpoints:
    - address: tcp://daemon.internal:2376
      tls:
        ca_file: /certs/ca.pem
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			if tt.yaml != "" {
				path := filepath.Join(t.TempDir(), "sockguard.yaml")
				if err := os.WriteFile(path, []byte(tt.yaml), 0o600); err != nil {
					t.Fatalf("write config: %v", err)
				}
				loaded, err := config.Load(path)
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				cfg = *loaded
			}
			if err := config.Validate(&cfg); err != nil {
				t.Fatalf("Validate rejected v2.1-compatible config: %v", err)
			}

			collector := &testhelp.CollectingHandler{}
			getenv := func(key string) string { return tt.env[key] }
			_, legacy := resolveUpstreamSpecs(&cfg, getenv, collector.Logger())
			if legacy {
				t.Fatal("resolveUpstreamSpecs used the legacy socket, want remote endpoint")
			}

			var deprecationRecords, plaintextRecords []testhelp.LogRecord
			for _, record := range collector.Records() {
				if strings.Contains(record.Message, "deprecated") && strings.Contains(record.Message, "v3.0.0") {
					deprecationRecords = append(deprecationRecords, record)
				}
				if strings.Contains(record.Message, "plaintext TCP") {
					plaintextRecords = append(plaintextRecords, record)
				}
			}

			if got := len(deprecationRecords); got != warningCount(tt.wantDeprecation) {
				t.Fatalf("deprecation warning count = %d, want %d; records: %#v", got, warningCount(tt.wantDeprecation), collector.Records())
			}
			if got := len(plaintextRecords); got != warningCount(tt.wantPlaintextWarning) {
				t.Fatalf("plaintext warning count = %d, want %d; records: %#v", got, warningCount(tt.wantPlaintextWarning), collector.Records())
			}
			if !tt.wantDeprecation {
				return
			}

			record := deprecationRecords[0]
			for key, want := range map[string]string{
				"source":             tt.wantSource,
				"deprecated_setting": tt.wantDeprecatedSetting,
				"replacement":        tt.wantReplacement,
				"removal_version":    "v3.0.0",
			} {
				if got := record.Attrs[key]; got != want {
					t.Errorf("deprecation %s = %v, want %q; record: %#v", key, got, want, record)
				}
			}
		})
	}
}

func warningCount(value bool) int {
	if value {
		return 1
	}
	return 0
}
