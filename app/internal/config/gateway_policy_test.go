package config

import "testing"

func TestFrontendGatewayConfiguration(t *testing.T) {
	cfg, err := LoadBytes([]byte("request_body:\n  buildkit:\n    control:\n      solve:\n        allow_frontend_gateway: true\nclients:\n  profiles:\n    - name: builder\n"))
	if err != nil {
		t.Fatal(err)
	}
	policy := cfg.RequestBody.Buildkit.ToPolicy(cfg.RequestBody.Build)
	if !policy.Configured() || !policy.Control.Solve.AllowFrontendGateway {
		t.Fatal("frontend gateway opt-in did not reach runtime policy")
	}
	if policy.Control.Solve.Allow || policy.Control.Solve.AllowRunInstructions {
		t.Fatal("gateway opt-in granted Solve or unrestricted execution")
	}
	profile := cfg.Clients.Profiles[0].RequestBody
	if profile.Buildkit.ToPolicy(profile.Build).Control.Solve.AllowFrontendGateway {
		t.Fatal("client profile inherited the global gateway grant")
	}
}

func TestFrontendGatewayEnvironment(t *testing.T) {
	t.Setenv("SOCKGUARD_REQUEST_BODY_BUILDKIT_CONTROL_SOLVE_ALLOW_FRONTEND_GATEWAY", "true")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RequestBody.Buildkit.ToPolicy(cfg.RequestBody.Build).Control.Solve.AllowFrontendGateway {
		t.Fatal("gateway environment opt-in was not loaded")
	}
}
