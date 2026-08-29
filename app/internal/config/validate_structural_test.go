package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/testcert"
)

// tcpTLSConfig returns a config whose only listener is a TCP listener with a
// complete listen.tls block, which is the shape that reaches the TLS material
// load inside validateTCPListenerSecurity.
func tcpTLSConfig(tls ListenTLSConfig) Config {
	cfg := Defaults()
	cfg.Listen.Socket = ""
	cfg.Listen.Address = "127.0.0.1:2375"
	cfg.Listen.TLS = tls
	return cfg
}

// TestValidateStructuralDoesNotProbeTheFilesystem is the regression for the
// admin /validate oracle: a caller who supplies candidate YAML must not be
// able to tell one host path from another by reading the validation errors.
//
// The assertion that matters is indistinguishability, not merely "no error".
// A path that does not exist, a path that exists but is not PEM, and a path
// that exists and is a directory all have to produce the SAME structural
// verdict, because any difference between them is the oracle.
func TestValidateStructuralDoesNotProbeTheFilesystem(t *testing.T) {
	dir := t.TempDir()

	notPEM := filepath.Join(dir, "not-a-cert.txt")
	if err := os.WriteFile(notPEM, []byte("this is not a certificate\n"), 0o600); err != nil {
		t.Fatalf("write decoy file: %v", err)
	}
	subdir := filepath.Join(dir, "a-directory")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	missing := filepath.Join(dir, "definitely-absent.pem")

	probes := []struct {
		name string
		path string
	}{
		{"absent path", missing},
		{"present but not PEM", notPEM},
		{"present but a directory", subdir},
		{"absolute host path", "/etc/shadow"},
	}

	for _, probe := range probes {
		t.Run(probe.name, func(t *testing.T) {
			cfg := tcpTLSConfig(ListenTLSConfig{
				CertFile:     probe.path,
				KeyFile:      probe.path,
				ClientCAFile: probe.path,
			})
			if err := ValidateStructural(&cfg); err != nil {
				t.Fatalf("ValidateStructural() = %v, want nil; the error distinguishes %q from any other path", err, probe.path)
			}
		})
	}
}

// TestValidateStillLoadsTLSMaterial pins the other half: the operator-facing
// validator must keep failing fast on TLS material it cannot load, or a
// missing cert file would first surface at the initial client connection.
func TestValidateStillLoadsTLSMaterial(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.pem")
	cfg := tcpTLSConfig(ListenTLSConfig{
		CertFile:     missing,
		KeyFile:      missing,
		ClientCAFile: missing,
	})

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("Validate() = nil, want an error for unloadable TLS material")
	}
	if !strings.Contains(err.Error(), "listen.tls") {
		t.Fatalf("Validate() = %v, want an error naming listen.tls", err)
	}
}

// TestValidateStructuralStillCatchesPureTLSErrors proves the structural mode
// is not a blanket skip: every listen.tls check that needs no filesystem
// access still runs, so an operator using the admin endpoint to check a
// candidate still gets the errors that endpoint is for.
func TestValidateStructuralStillCatchesPureTLSErrors(t *testing.T) {
	bundle, err := testcert.WriteMutualTLSBundle(t.TempDir())
	if err != nil {
		t.Fatalf("WriteMutualTLSBundle: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*ListenTLSConfig)
		want   string
	}{
		{
			name:   "incomplete tls block",
			mutate: func(tls *ListenTLSConfig) { tls.ClientCAFile = "" },
			want:   "listen.tls",
		},
		{
			name:   "malformed ip address selector",
			mutate: func(tls *ListenTLSConfig) { tls.IPAddresses = []string{"not-an-ip"} },
			want:   "listen.tls.ip_addresses",
		},
		{
			name:   "empty common name selector",
			mutate: func(tls *ListenTLSConfig) { tls.CommonNames = []string{"  "} },
			want:   "listen.tls.common_names",
		},
		{
			name:   "malformed public key pin",
			mutate: func(tls *ListenTLSConfig) { tls.PublicKeySHA256Pins = []string{"zzzz"} },
			want:   "listen.tls.public_key_sha256_pins",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tls := ListenTLSConfig{
				CertFile:     bundle.ServerCertFile,
				KeyFile:      bundle.ServerKeyFile,
				ClientCAFile: bundle.CAFile,
			}
			tc.mutate(&tls)
			cfg := tcpTLSConfig(tls)

			err := ValidateStructural(&cfg)
			if err == nil {
				t.Fatalf("ValidateStructural() = nil, want an error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateStructural() = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// TestValidateStructuralAcceptsAValidConfig guards against the structural mode
// drifting into rejecting configs the full validator accepts.
func TestValidateStructuralAcceptsAValidConfig(t *testing.T) {
	bundle, err := testcert.WriteMutualTLSBundle(t.TempDir())
	if err != nil {
		t.Fatalf("WriteMutualTLSBundle: %v", err)
	}
	cfg := tcpTLSConfig(ListenTLSConfig{
		CertFile:     bundle.ServerCertFile,
		KeyFile:      bundle.ServerKeyFile,
		ClientCAFile: bundle.CAFile,
	})

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	if err := ValidateStructural(&cfg); err != nil {
		t.Fatalf("ValidateStructural() = %v, want nil", err)
	}

	defaults := Defaults()
	if err := ValidateStructural(&defaults); err != nil {
		t.Fatalf("ValidateStructural(Defaults()) = %v, want nil", err)
	}
}

// TestValidateStructuralCoversTheAdminAndListenersPaths reaches the other two
// call sites that load TLS material, so the fix cannot be partial: admin.listen
// and an explicit listeners[*] entry must be as filesystem-free as listen.
func TestValidateStructuralCoversTheAdminAndListenersPaths(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.pem")
	missingTLS := ListenTLSConfig{CertFile: missing, KeyFile: missing, ClientCAFile: missing}

	t.Run("admin.listen.tls", func(t *testing.T) {
		cfg := Defaults()
		cfg.Admin.Enabled = true
		cfg.Admin.Listen.Address = "127.0.0.1:2378"
		cfg.Admin.Listen.TLS = missingTLS

		err := Validate(&cfg)
		if err == nil {
			t.Fatal("Validate() = nil, want an error for unloadable admin TLS material")
		}
		if !strings.Contains(err.Error(), "admin.listen.tls") {
			t.Fatalf("Validate() = %v, want an error naming admin.listen.tls", err)
		}
		if err := ValidateStructural(&cfg); err != nil {
			t.Fatalf("ValidateStructural() = %v, want nil", err)
		}
	})

	t.Run("listeners[*].tls", func(t *testing.T) {
		cfg := Defaults()
		cfg.Listen = ListenConfig{}
		cfg.Listeners = []ListenerConfig{{
			Name:            "edge",
			AllowedProfiles: []string{"*"},
			ListenConfig:    ListenConfig{Address: "127.0.0.1:2379", TLS: missingTLS},
		}}

		err := Validate(&cfg)
		if err == nil {
			t.Fatal("Validate() = nil, want an error for unloadable listeners[*] TLS material")
		}
		if !strings.Contains(err.Error(), "listeners[edge].tls") {
			t.Fatalf("Validate() = %v, want an error naming listeners[edge].tls", err)
		}
		if err := ValidateStructural(&cfg); err != nil {
			t.Fatalf("ValidateStructural() = %v, want nil", err)
		}
	})
}
