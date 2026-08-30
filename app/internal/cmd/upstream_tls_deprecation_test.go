package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/testhelp"
	"github.com/codeswhat/sockguard/app/internal/upstream"
)

func TestResolveUpstreamSpecsWarnsAccuratelyAboutInsecureTransportSettings(t *testing.T) {
	tests := []struct {
		name                            string
		yaml                            string
		env                             map[string]string
		wantDeprecation                 bool
		wantPlaintextClaim              bool
		wantRedundantPlainTCPPermission bool
		wantSource                      string
		wantDeprecatedSetting           string
		wantReplacement                 string
		wantUnverifiedTLS               bool
		wantSkipVerificationClaim       bool
		wantUnixEndpoint                bool
		wantUnixInapplicableSettings    []string
	}{
		{
			name: "explicit YAML",
			yaml: `
upstream:
  endpoints:
    - address: tcp://daemon.internal:2376
      insecure_skip_tls_verify: true
`,
			wantDeprecation:           true,
			wantSource:                "upstream.endpoints config",
			wantDeprecatedSetting:     "upstream.endpoints[].insecure_skip_tls_verify",
			wantReplacement:           "upstream.endpoints[].tls.ca_file",
			wantSkipVerificationClaim: true,
		},
		{
			name: "Docker TLS environment fallback",
			env: map[string]string{
				"DOCKER_HOST": "tcp://daemon.internal:2376",
				"DOCKER_TLS":  "1",
			},
			wantDeprecation:           true,
			wantSource:                "DOCKER_HOST environment",
			wantDeprecatedSetting:     "DOCKER_TLS without DOCKER_TLS_VERIFY",
			wantReplacement:           "DOCKER_TLS_VERIFY=1",
			wantUnverifiedTLS:         true,
			wantSkipVerificationClaim: true,
		},
		{
			name: "Docker TLS zero is still enabled and deprecated",
			env: map[string]string{
				"DOCKER_HOST": "tcp://daemon.internal:2376",
				"DOCKER_TLS":  "0",
			},
			wantDeprecation:           true,
			wantSource:                "DOCKER_HOST environment",
			wantDeprecatedSetting:     "DOCKER_TLS without DOCKER_TLS_VERIFY",
			wantReplacement:           "DOCKER_TLS_VERIFY=1",
			wantUnverifiedTLS:         true,
			wantSkipVerificationClaim: true,
		},
		{
			name: "cert path alone remains plaintext and is not deprecated TLS",
			env: map[string]string{
				"DOCKER_HOST":      "tcp://daemon.internal:2376",
				"DOCKER_CERT_PATH": "/certs",
			},
			wantPlaintextClaim: true,
		},
		{
			name: "non-empty Docker TLS verify wins over Docker TLS",
			env: map[string]string{
				"DOCKER_HOST":       "tcp://daemon.internal:2376",
				"DOCKER_TLS":        "1",
				"DOCKER_TLS_VERIFY": "0",
			},
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
			wantDeprecation:                 true,
			wantRedundantPlainTCPPermission: true,
			wantSource:                      "upstream.endpoints config",
			wantDeprecatedSetting:           "upstream.endpoints[].insecure_skip_tls_verify",
			wantReplacement:                 "upstream.endpoints[].tls.ca_file",
			wantUnverifiedTLS:               true,
			wantSkipVerificationClaim:       true,
		},
		{
			name: "verified TLS with redundant plain TCP permission",
			yaml: `
upstream:
  endpoints:
    - address: tcp://daemon.internal:2376
      tls:
        ca_file: /certs/ca.pem
      insecure_allow_plain_tcp: true
`,
			wantRedundantPlainTCPPermission: true,
		},
		{
			name: "plain TCP endpoint",
			yaml: `
upstream:
  endpoints:
    - address: tcp://daemon.internal:2375
      insecure_allow_plain_tcp: true
`,
			wantPlaintextClaim: true,
		},
		{
			name: "Unix endpoint with plain TCP permission",
			yaml: `
upstream:
  endpoints:
    - address: unix:///var/run/docker.sock
      insecure_allow_plain_tcp: true
`,
			wantSource:                   "upstream.endpoints config",
			wantUnixEndpoint:             true,
			wantUnixInapplicableSettings: []string{"insecure_allow_plain_tcp"},
		},
		{
			name: "Unix endpoint with skip verification",
			yaml: `
upstream:
  endpoints:
    - address: unix:///var/run/docker.sock
      insecure_skip_tls_verify: true
`,
			wantDeprecation:              true,
			wantSource:                   "upstream.endpoints config",
			wantDeprecatedSetting:        "upstream.endpoints[].insecure_skip_tls_verify",
			wantReplacement:              "upstream.endpoints[].tls.ca_file",
			wantUnixEndpoint:             true,
			wantUnixInapplicableSettings: []string{"insecure_skip_tls_verify"},
		},
		{
			name: "Unix endpoint with both insecure flags",
			yaml: `
upstream:
  endpoints:
    - address: unix:///var/run/docker.sock
      insecure_allow_plain_tcp: true
      insecure_skip_tls_verify: true
`,
			wantDeprecation:              true,
			wantSource:                   "upstream.endpoints config",
			wantDeprecatedSetting:        "upstream.endpoints[].insecure_skip_tls_verify",
			wantReplacement:              "upstream.endpoints[].tls.ca_file",
			wantUnixEndpoint:             true,
			wantUnixInapplicableSettings: []string{"insecure_allow_plain_tcp", "insecure_skip_tls_verify"},
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
			specs, legacy := resolveUpstreamSpecs(&cfg, getenv, collector.Logger())
			if legacy {
				t.Fatal("resolveUpstreamSpecs used the legacy socket, want remote endpoint")
			}
			if tt.wantUnverifiedTLS {
				if len(specs) != 1 {
					t.Fatalf("resolved specs = %d, want 1", len(specs))
				}
				endpoint, err := upstream.BuildEndpoint(specs[0])
				if err != nil {
					t.Fatalf("BuildEndpoint: %v", err)
				}
				if !endpoint.IsTLS() {
					t.Error("endpoint expected to use unverified TLS")
				} else if !endpoint.TLSConfig.InsecureSkipVerify {
					t.Error("endpoint with both insecure flags must skip TLS verification")
				}
			}
			if tt.wantUnixEndpoint {
				if len(specs) != 1 {
					t.Fatalf("resolved specs = %d, want 1", len(specs))
				}
				endpoint, err := upstream.BuildEndpoint(specs[0])
				if err != nil {
					t.Fatalf("BuildEndpoint: %v", err)
				}
				if endpoint.Network != "unix" {
					t.Errorf("endpoint network = %q, want unix", endpoint.Network)
				}
				if endpoint.IsTLS() {
					t.Error("Unix endpoint must not use TLS when TCP-only insecure settings are configured")
				}
			}

			var deprecationRecords, plaintextClaimRecords, tlsSelectedClaimRecords, skipVerificationClaimRecords, redundantPlainTCPPermissionRecords []testhelp.LogRecord
			for _, record := range collector.Records() {
				if strings.Contains(record.Message, "deprecated") && strings.Contains(record.Message, "v3.0.0") {
					deprecationRecords = append(deprecationRecords, record)
				}
				if strings.Contains(record.Message, "uses plaintext TCP with no TLS") {
					plaintextClaimRecords = append(plaintextClaimRecords, record)
				}
				if strings.Contains(record.Message, "TLS is selected") {
					tlsSelectedClaimRecords = append(tlsSelectedClaimRecords, record)
				}
				if strings.Contains(record.Message, "skips TLS certificate verification") {
					skipVerificationClaimRecords = append(skipVerificationClaimRecords, record)
				}
				if strings.Contains(record.Message, "insecure_allow_plain_tcp enabled, but TLS is selected") {
					redundantPlainTCPPermissionRecords = append(redundantPlainTCPPermissionRecords, record)
				}
			}

			if got := len(deprecationRecords); got != warningCount(tt.wantDeprecation) {
				t.Fatalf("deprecation warning count = %d, want %d; records: %#v", got, warningCount(tt.wantDeprecation), collector.Records())
			}
			if got := len(plaintextClaimRecords); got != warningCount(tt.wantPlaintextClaim) {
				t.Errorf("plaintext usage claim count = %d, want %d; records: %#v", got, warningCount(tt.wantPlaintextClaim), collector.Records())
			}
			if got := len(redundantPlainTCPPermissionRecords); got != warningCount(tt.wantRedundantPlainTCPPermission) {
				t.Errorf("redundant plain-TCP permission warning count = %d, want %d; records: %#v", got, warningCount(tt.wantRedundantPlainTCPPermission), collector.Records())
			}
			if got := len(tlsSelectedClaimRecords); got != warningCount(tt.wantRedundantPlainTCPPermission) {
				t.Errorf("TLS-selected claim count = %d, want %d; records: %#v", got, warningCount(tt.wantRedundantPlainTCPPermission), collector.Records())
			}
			if got := len(skipVerificationClaimRecords); got != warningCount(tt.wantSkipVerificationClaim) {
				t.Errorf("skipped-verification claim count = %d, want %d; records: %#v", got, warningCount(tt.wantSkipVerificationClaim), collector.Records())
			}
			for _, setting := range tt.wantUnixInapplicableSettings {
				found := false
				for _, record := range collector.Records() {
					if strings.Contains(record.Message, setting) && strings.Contains(record.Message, "only applies to TCP endpoints") {
						found = true
						if got := record.Attrs["address"]; got != specs[0].Address {
							t.Errorf("%s Unix warning address = %v, want %q; record: %#v", setting, got, specs[0].Address, record)
						}
						if got := record.Attrs["source"]; got != tt.wantSource {
							t.Errorf("%s Unix warning source = %v, want %q; record: %#v", setting, got, tt.wantSource, record)
						}
					}
				}
				if !found {
					t.Errorf("no warning says %s only applies to TCP endpoints; records: %#v", setting, collector.Records())
				}
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
