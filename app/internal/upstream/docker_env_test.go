package upstream

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/testcert"
)

func TestSpecsFromDockerEnv_UsesDockerConfigCAWithOptionalClientPair(t *testing.T) {
	certDir := t.TempDir()
	installDockerCertificateFiles(t, certDir, true, false, false)

	spec := dockerEnvSpecForTest(t, map[string]string{
		"DOCKER_HOST":       "tcp://daemon.internal:2376",
		"DOCKER_TLS_VERIFY": "1",
		"DOCKER_CONFIG":     certDir,
	})

	if spec.CAFile != filepath.Join(certDir, "ca.pem") {
		t.Fatalf("CAFile = %q, want Docker config CA", spec.CAFile)
	}
	if spec.CertFile != "" || spec.KeyFile != "" {
		t.Fatalf("client files = (%q, %q), want optional pair omitted", spec.CertFile, spec.KeyFile)
	}
	endpoint, err := BuildEndpoint(spec)
	if err != nil {
		t.Fatalf("BuildEndpoint: %v", err)
	}
	if endpoint.TLSConfig == nil || endpoint.TLSConfig.RootCAs == nil {
		t.Fatal("Docker config CA was not loaded")
	}
	if len(endpoint.TLSConfig.Certificates) != 0 {
		t.Fatal("client certificate was loaded from a CA-only directory")
	}
}

func TestSpecsFromDockerEnv_ExplicitCertificatePathOverridesDockerConfig(t *testing.T) {
	configDir := t.TempDir()
	explicitDir := t.TempDir()
	installDockerCertificateFiles(t, configDir, true, false, false)
	installDockerCertificateFiles(t, explicitDir, true, true, true)

	spec := dockerEnvSpecForTest(t, map[string]string{
		"DOCKER_HOST":       "tcp://daemon.internal:2376",
		"DOCKER_TLS_VERIFY": "1",
		"DOCKER_CONFIG":     configDir,
		"DOCKER_CERT_PATH":  explicitDir,
	})

	if spec.CAFile != filepath.Join(explicitDir, "ca.pem") {
		t.Fatalf("CAFile = %q, want explicit certificate directory", spec.CAFile)
	}
	if spec.CertFile != filepath.Join(explicitDir, "cert.pem") || spec.KeyFile != filepath.Join(explicitDir, "key.pem") {
		t.Fatalf("client files = (%q, %q), want explicit mutual-TLS pair", spec.CertFile, spec.KeyFile)
	}
	endpoint, err := BuildEndpoint(spec)
	if err != nil {
		t.Fatalf("BuildEndpoint: %v", err)
	}
	if len(endpoint.TLSConfig.Certificates) != 1 {
		t.Fatalf("client certificate count = %d, want 1", len(endpoint.TLSConfig.Certificates))
	}
}

func TestSpecsFromDockerEnv_DefaultUserDockerDirectory(t *testing.T) {
	homeDir := t.TempDir()
	certDir := filepath.Join(homeDir, ".docker")
	if err := os.Mkdir(certDir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	installDockerCertificateFiles(t, certDir, true, false, false)
	t.Setenv("HOME", homeDir)

	spec := dockerEnvSpecForTest(t, map[string]string{
		"DOCKER_HOST": "tcp://daemon.internal:2376",
		"DOCKER_TLS":  "1",
	})

	if spec.CAFile != filepath.Join(certDir, "ca.pem") {
		t.Fatalf("CAFile = %q, want user Docker directory", spec.CAFile)
	}
	if !spec.InsecureSkipTLSVerify {
		t.Fatal("InsecureSkipTLSVerify = false, want DOCKER_TLS behavior")
	}
	if _, err := BuildEndpoint(spec); err != nil {
		t.Fatalf("BuildEndpoint: %v", err)
	}
}

func TestSpecsFromDockerEnv_IgnoresIncompleteOptionalClientPair(t *testing.T) {
	for _, files := range []struct {
		name     string
		certFile bool
		keyFile  bool
	}{
		{name: "certificate only", certFile: true},
		{name: "key only", keyFile: true},
	} {
		files := files
		t.Run(files.name, func(t *testing.T) {
			certDir := t.TempDir()
			installDockerCertificateFiles(t, certDir, true, files.certFile, files.keyFile)
			spec := dockerEnvSpecForTest(t, map[string]string{
				"DOCKER_HOST":       "tcp://daemon.internal:2376",
				"DOCKER_TLS_VERIFY": "1",
				"DOCKER_CERT_PATH":  certDir,
			})
			if spec.CertFile != "" || spec.KeyFile != "" {
				t.Fatalf("client files = (%q, %q), want incomplete pair omitted", spec.CertFile, spec.KeyFile)
			}
			if _, err := BuildEndpoint(spec); err != nil {
				t.Fatalf("BuildEndpoint: %v", err)
			}
		})
	}
}

func TestSpecsFromDockerEnv_ReportsUnreadableIncompleteClientFile(t *testing.T) {
	certDir := t.TempDir()
	installDockerCertificateFiles(t, certDir, true, false, false)
	if err := os.Mkdir(filepath.Join(certDir, "cert.pem"), 0o700); err != nil {
		t.Fatalf("Mkdir cert.pem: %v", err)
	}

	_, _, err := SpecsFromDockerEnv(func(key string) (string, bool) {
		env := map[string]string{
			"DOCKER_HOST":       "tcp://daemon.internal:2376",
			"DOCKER_TLS_VERIFY": "1",
			"DOCKER_CERT_PATH":  certDir,
		}
		value, present := env[key]
		return value, present
	})
	if err == nil {
		t.Fatal("SpecsFromDockerEnv ignored an unreadable lone cert.pem")
	}
}

func TestSpecsFromDockerEnv_TLSRequiresDockerCA(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{name: "DOCKER_TLS", key: "DOCKER_TLS"},
		{name: "DOCKER_TLS_VERIFY", key: "DOCKER_TLS_VERIFY"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			certDir := t.TempDir()
			env := map[string]string{
				"DOCKER_HOST":   "tcp://daemon.internal:2376",
				"DOCKER_CONFIG": certDir,
				tt.key:          "1",
			}
			spec := dockerEnvSpecForTest(t, env)
			if spec.CAFile != filepath.Join(certDir, "ca.pem") {
				t.Fatalf("CAFile = %q, want required Docker CA path", spec.CAFile)
			}
			if _, err := BuildEndpoint(spec); err == nil {
				t.Fatal("BuildEndpoint accepted TLS without ca.pem")
			}
		})
	}
}

func TestSpecsFromDockerEnv_UnverifiedTLSStillRejectsInvalidDockerCA(t *testing.T) {
	certDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(certDir, "ca.pem"), []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write invalid CA: %v", err)
	}
	spec := dockerEnvSpecForTest(t, map[string]string{
		"DOCKER_HOST":      "tcp://daemon.internal:2376",
		"DOCKER_TLS":       "1",
		"DOCKER_CERT_PATH": certDir,
	})
	if _, err := BuildEndpoint(spec); err == nil {
		t.Fatal("BuildEndpoint accepted invalid ca.pem for DOCKER_TLS")
	}
}

func TestSpecsFromDockerEnv_TLSDisabledIgnoresCertificateDirectories(t *testing.T) {
	spec := dockerEnvSpecForTest(t, map[string]string{
		"DOCKER_HOST":      "tcp://daemon.internal:2375",
		"DOCKER_CERT_PATH": filepath.Join(t.TempDir(), "missing"),
		"DOCKER_CONFIG":    filepath.Join(t.TempDir(), "also-missing"),
	})
	if spec.CAFile != "" || spec.CertFile != "" || spec.KeyFile != "" {
		t.Fatalf("TLS-disabled certificate files = (%q, %q, %q), want empty", spec.CAFile, spec.CertFile, spec.KeyFile)
	}
	if !spec.InsecureAllowPlainTCP {
		t.Fatal("InsecureAllowPlainTCP = false, want Docker plaintext behavior")
	}
	if _, err := BuildEndpoint(spec); err != nil {
		t.Fatalf("BuildEndpoint: %v", err)
	}
}

func TestSpecsFromDockerEnv_PortlessTCPUses2375WithTLS(t *testing.T) {
	certDir := t.TempDir()
	installDockerCertificateFiles(t, certDir, true, false, false)
	tests := []struct {
		name string
		key  string
	}{
		{name: "DOCKER_TLS", key: "DOCKER_TLS"},
		{name: "DOCKER_TLS_VERIFY", key: "DOCKER_TLS_VERIFY"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			env := map[string]string{
				"DOCKER_HOST":      "tcp://daemon.internal",
				"DOCKER_CERT_PATH": certDir,
				tt.key:             "1",
			}
			spec := dockerEnvSpecForTest(t, env)
			if spec.Address != "tcp://daemon.internal:2375" {
				t.Fatalf("Address = %q, want Docker's explicit-host default port 2375", spec.Address)
			}
		})
	}
}

func TestSpecsFromDockerEnv_WhitespaceTLSVerifyTakesPrecedence(t *testing.T) {
	certDir := t.TempDir()
	installDockerCertificateFiles(t, certDir, true, false, false)
	spec := dockerEnvSpecForTest(t, map[string]string{
		"DOCKER_HOST":       "tcp://daemon.internal:2376",
		"DOCKER_TLS":        " ",
		"DOCKER_TLS_VERIFY": " ",
		"DOCKER_CERT_PATH":  certDir,
	})
	if spec.InsecureSkipTLSVerify {
		t.Fatal("InsecureSkipTLSVerify = true, want non-empty DOCKER_TLS_VERIFY to win")
	}
	if spec.CAFile != filepath.Join(certDir, "ca.pem") {
		t.Fatalf("CAFile = %q, want Docker CA", spec.CAFile)
	}
}

func dockerEnvSpecForTest(t *testing.T, env map[string]string) EndpointSpec {
	t.Helper()
	spec, ok, err := SpecsFromDockerEnv(func(key string) (string, bool) {
		value, present := env[key]
		return value, present
	})
	if err != nil {
		t.Fatalf("SpecsFromDockerEnv: %v", err)
	}
	if !ok {
		t.Fatal("SpecsFromDockerEnv was inactive")
	}
	return spec
}

func installDockerCertificateFiles(t *testing.T, target string, ca, cert, key bool) {
	t.Helper()
	source := t.TempDir()
	bundle, err := testcert.WriteMutualTLSBundle(source, "daemon.internal")
	if err != nil {
		t.Fatalf("WriteMutualTLSBundle: %v", err)
	}
	files := []struct {
		install bool
		source  string
		target  string
	}{
		{install: ca, source: bundle.CAFile, target: "ca.pem"},
		{install: cert, source: bundle.ClientCertFile, target: "cert.pem"},
		{install: key, source: bundle.ClientKeyFile, target: "key.pem"},
	}
	for _, file := range files {
		if !file.install {
			continue
		}
		contents, err := os.ReadFile(file.source)
		if err != nil {
			t.Fatalf("read %s: %v", file.source, err)
		}
		if err := os.WriteFile(filepath.Join(target, file.target), contents, 0o600); err != nil {
			t.Fatalf("write %s: %v", file.target, err)
		}
	}
}
