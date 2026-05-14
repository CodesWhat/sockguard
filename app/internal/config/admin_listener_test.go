package config

import (
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/testcert"
)

func TestDefaultsAdminListenerIsUnconfigured(t *testing.T) {
	d := Defaults()
	if d.Admin.Listen.Configured() {
		t.Fatalf("Admin.Listen.Configured() = true in defaults, want false")
	}
	if d.Admin.Listen.SocketMode != HardenedListenSocketMode {
		t.Fatalf("Admin.Listen.SocketMode = %q, want %q", d.Admin.Listen.SocketMode, HardenedListenSocketMode)
	}
}

func TestValidateAdminListenSocketRequiresHardenedMode(t *testing.T) {
	cfg := Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Socket = "/tmp/sockguard-admin.sock"
	cfg.Admin.Listen.SocketMode = "0777"

	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "admin.listen.socket_mode") {
		t.Fatalf("Validate() = %v, want admin.listen.socket_mode error", err)
	}
}

func TestValidateAdminListenSocketAndAddressMutuallyExclusive(t *testing.T) {
	cfg := Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Socket = "/tmp/sockguard-admin.sock"
	cfg.Admin.Listen.Address = "127.0.0.1:2376"

	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("Validate() = %v, want mutually-exclusive error", err)
	}
}

func TestValidateAdminListenAddressMustDifferFromMainTCP(t *testing.T) {
	cfg := Defaults()
	cfg.Admin.Enabled = true
	cfg.Listen.Socket = ""
	cfg.Listen.Address = "127.0.0.1:2375"
	cfg.Admin.Listen.Address = "127.0.0.1:2375"

	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "admin.listen.address must differ from listen.address") {
		t.Fatalf("Validate() = %v, want collision error", err)
	}
}

func TestValidateAdminListenSocketMustDifferFromMainSocket(t *testing.T) {
	cfg := Defaults()
	cfg.Admin.Enabled = true
	cfg.Listen.Socket = "/tmp/sockguard.sock"
	cfg.Listen.SocketMode = HardenedListenSocketMode
	cfg.Listen.Address = ""
	cfg.Admin.Listen.Socket = "/tmp/sockguard.sock"

	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "admin.listen.socket must differ from listen.socket") {
		t.Fatalf("Validate() = %v, want collision error", err)
	}
}

func TestValidateAdminListenNonLoopbackRequiresTLSOrOptIn(t *testing.T) {
	cfg := Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Address = "0.0.0.0:9000"

	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "non-loopback TCP admin listener") {
		t.Fatalf("Validate() = %v, want non-loopback admin TCP error", err)
	}
}

func TestValidateAdminListenLoopbackPlaintextAccepted(t *testing.T) {
	cfg := Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Address = "127.0.0.1:9000"

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() = %v, want nil for loopback admin TCP", err)
	}
}

func TestValidateAdminListenAcceptsNonLoopbackWithExplicitOptIn(t *testing.T) {
	cfg := Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Address = "0.0.0.0:9000"
	cfg.Admin.Listen.InsecureAllowPlainTCP = true

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() = %v, want nil after opt-in", err)
	}
}

func TestValidateAdminListenRejectsPartialTLS(t *testing.T) {
	cfg := Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Address = "0.0.0.0:9000"
	cfg.Admin.Listen.TLS.CertFile = "/tmp/cert.pem"

	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "admin.listen.tls") {
		t.Fatalf("Validate() = %v, want partial admin TLS error", err)
	}
}

func TestValidateAdminListenAcceptsCompleteTLS(t *testing.T) {
	dir := t.TempDir()
	bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
	if err != nil {
		t.Fatalf("WriteMutualTLSBundle: %v", err)
	}

	cfg := Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Address = "0.0.0.0:9000"
	cfg.Admin.Listen.TLS.CertFile = bundle.ServerCertFile
	cfg.Admin.Listen.TLS.KeyFile = bundle.ServerKeyFile
	cfg.Admin.Listen.TLS.ClientCAFile = bundle.CAFile

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() = %v, want nil for complete admin mTLS", err)
	}
}

func TestValidateAdminListenSkipsWhenAdminDisabled(t *testing.T) {
	cfg := Defaults()
	cfg.Admin.Enabled = false
	cfg.Admin.Listen.Address = "0.0.0.0:9000" // would normally error

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() = %v, want nil when admin disabled", err)
	}
}

func TestLoadBytesParsesAdminListen(t *testing.T) {
	yaml := []byte(`
admin:
  enabled: true
  listen:
    address: 127.0.0.1:9000
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
`)
	cfg, err := LoadBytes(yaml)
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Admin.Listen.Address != "127.0.0.1:9000" {
		t.Fatalf("Admin.Listen.Address = %q, want 127.0.0.1:9000", cfg.Admin.Listen.Address)
	}
	if !cfg.Admin.Listen.Configured() {
		t.Fatalf("Admin.Listen.Configured() = false, want true after parse")
	}
}
