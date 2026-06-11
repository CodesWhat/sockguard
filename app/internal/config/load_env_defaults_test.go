package config

import "testing"

// Viper only unmarshals keys it knows about (via SetDefault/BindEnv/pflags/file).
// A request_body field absent from setLoadDefaults is therefore silently
// dropped when configured purely through its SOCKGUARD_* env var. These guard
// the two fields that were missing their SetDefault registration.

func TestLoadHonorsAllowSysctlsEnvVar(t *testing.T) {
	t.Setenv("SOCKGUARD_REQUEST_BODY_CONTAINER_CREATE_ALLOW_SYSCTLS", "true")

	cfg, err := Load("/nonexistent-so-defaults-and-env-only.yaml")
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if !cfg.RequestBody.ContainerCreate.AllowSysctls {
		t.Fatal("AllowSysctls = false, want true from SOCKGUARD_REQUEST_BODY_CONTAINER_CREATE_ALLOW_SYSCTLS")
	}
}

func TestLoadHonorsServiceHardeningEnvVars(t *testing.T) {
	// The swarm-parity hardening rails are env-only unless registered in
	// setLoadDefaults; guard all four so a missing SetDefault can't silently
	// drop them.
	t.Setenv("SOCKGUARD_REQUEST_BODY_SERVICE_REQUIRE_NON_ROOT_USER", "true")
	t.Setenv("SOCKGUARD_REQUEST_BODY_SERVICE_REQUIRE_NO_NEW_PRIVILEGES", "true")
	t.Setenv("SOCKGUARD_REQUEST_BODY_SERVICE_REQUIRE_READONLY_ROOTFS", "true")
	t.Setenv("SOCKGUARD_REQUEST_BODY_SERVICE_REQUIRE_DROP_ALL_CAPABILITIES", "true")

	cfg, err := Load("/nonexistent-so-defaults-and-env-only.yaml")
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	svc := cfg.RequestBody.Service
	if !svc.RequireNonRootUser {
		t.Error("RequireNonRootUser = false, want true from env")
	}
	if !svc.RequireNoNewPrivileges {
		t.Error("RequireNoNewPrivileges = false, want true from env")
	}
	if !svc.RequireReadonlyRootfs {
		t.Error("RequireReadonlyRootfs = false, want true from env")
	}
	if !svc.RequireDropAllCapabilities {
		t.Error("RequireDropAllCapabilities = false, want true from env")
	}
}

func TestLoadHonorsImageTrustVerifyTimeoutEnvVar(t *testing.T) {
	t.Setenv("SOCKGUARD_REQUEST_BODY_CONTAINER_CREATE_IMAGE_TRUST_VERIFY_TIMEOUT", "30s")
	t.Setenv("SOCKGUARD_REQUEST_BODY_SERVICE_IMAGE_TRUST_VERIFY_TIMEOUT", "45s")

	cfg, err := Load("/nonexistent-so-defaults-and-env-only.yaml")
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if got := cfg.RequestBody.ContainerCreate.ImageTrust.VerifyTimeout; got != "30s" {
		t.Fatalf("container_create image_trust verify_timeout = %q, want 30s", got)
	}
	if got := cfg.RequestBody.Service.ImageTrust.VerifyTimeout; got != "45s" {
		t.Fatalf("service image_trust verify_timeout = %q, want 45s", got)
	}
}
