package config

import (
	"strings"
	"testing"
)

func TestLoadExecDigestPolicy(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	cfg, err := LoadBytes([]byte("request_body:\n  buildkit:\n    control:\n      solve:\n        allowed_exec_digests: [" + digest + "]\n"))
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.RequestBody.Buildkit.ToPolicy(cfg.RequestBody.Build)
	if _, ok := p.Control.Solve.AllowedExecDigests[digest]; !ok || !p.Configured() {
		t.Fatal("the configured ExecOp approval did not reach the runtime policy")
	}
	if p.Control.Solve.Allow || p.Control.Solve.AllowRunInstructions {
		t.Fatal("an operation approval implicitly enabled Solve or unrestricted RUN")
	}
	if err := Validate(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestExecDigestPolicyScopes(t *testing.T) {
	global := "sha256:" + strings.Repeat("a", 64)
	profile := "sha256:" + strings.Repeat("b", 64)
	cfg := Defaults()
	cfg.RequestBody.Buildkit.Control.Solve.AllowedExecDigests = []string{global}
	cfg.Clients.Profiles = []ClientProfileConfig{{
		Name: "builder",
		RequestBody: RequestBodyConfig{Buildkit: BuildkitRequestBodyConfig{Control: BuildkitControlRequestBodyConfig{
			Solve: BuildkitSolveRequestBodyConfig{AllowedExecDigests: []string{profile}},
		}}},
	}}
	p := cfg.Clients.Profiles[0].RequestBody
	runtime := p.Buildkit.ToPolicy(p.Build)
	if _, ok := runtime.Control.Solve.AllowedExecDigests[global]; ok {
		t.Fatal("profile inherited a global operation approval")
	}
	if _, ok := runtime.Control.Solve.AllowedExecDigests[profile]; !ok {
		t.Fatal("profile approval was lost")
	}
	runtime.Control.Solve.AllowedExecDigests[global] = struct{}{}
	if _, ok := p.Buildkit.ToPolicy(p.Build).Control.Solve.AllowedExecDigests[global]; ok {
		t.Fatal("runtime policy mutation changed the source config")
	}
	cfg.Clients.Profiles[0].RequestBody.Buildkit.Control.Solve.AllowedExecDigests = []string{"invalid"}
	if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "allowed_exec_digests") {
		t.Fatalf("invalid profile digest: %v", err)
	}
}

func TestLoadExecDigestEnvironment(t *testing.T) {
	digest := "sha256:" + strings.Repeat("c", 64)
	t.Setenv("SOCKGUARD_REQUEST_BODY_BUILDKIT_CONTROL_SOLVE_ALLOWED_EXEC_DIGESTS", digest)
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.RequestBody.Buildkit.ToPolicy(cfg.RequestBody.Build).Control.Solve.AllowedExecDigests[digest]; !ok {
		t.Fatal("environment approval was not loaded")
	}
}

func TestValidateExecDigests(t *testing.T) {
	for _, value := range []string{"", "sha256:abc", "sha512:" + strings.Repeat("a", 64), "sha512:" + strings.Repeat("a", 128), "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("g", 64)} {
		t.Run(value, func(t *testing.T) {
			cfg, err := LoadBytes([]byte("request_body:\n  buildkit:\n    control:\n      solve:\n        allowed_exec_digests: [\"" + value + "\"]\n"))
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "allowed_exec_digests") {
				t.Fatalf("Validate = %v, want an allowed_exec_digests error", err)
			}
		})
	}
}
