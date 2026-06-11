package config

import (
	"strings"
	"testing"
)

// wideOpenAdminConfig is a dedicated admin listener that has passed the
// two-flag plaintext opt-in but has no CIDR allowlist — the "wide open"
// shape that used to be a startup warning and is now a validation error.
func wideOpenAdminConfig() Config {
	cfg := Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Address = ":2376"
	cfg.Admin.Listen.InsecureAllowPlainTCP = true
	cfg.Admin.Listen.InsecureAllowUnauthenticatedClients = true
	return cfg
}

func TestValidateRejectsWideOpenAdminListener(t *testing.T) {
	t.Parallel()
	cfg := wideOpenAdminConfig()

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for non-loopback plaintext admin listener with no CIDR allowlist")
	}
	if !strings.Contains(err.Error(), "insecure_allow_wide_open") {
		t.Fatalf("expected acknowledgment hint in error, got: %v", err)
	}
}

func TestValidateAllowsWideOpenAdminListenerWithAcknowledgment(t *testing.T) {
	t.Parallel()
	cfg := wideOpenAdminConfig()
	cfg.Admin.Listen.InsecureAllowWideOpen = true

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() error = %v, want nil with insecure_allow_wide_open acknowledgment", err)
	}
}

func TestValidateAllowsPlaintextAdminListenerWithCIDRAllowlist(t *testing.T) {
	t.Parallel()
	cfg := wideOpenAdminConfig()
	cfg.Clients.AllowedCIDRs = []string{"10.0.0.0/8"}

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() error = %v, want nil when clients.allowed_cidrs guards the admin surface", err)
	}
}

func TestValidateAllowsLoopbackPlaintextAdminListener(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.Listen.Address = "127.0.0.1:2376"

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() error = %v, want nil for loopback plaintext admin listener", err)
	}
}
