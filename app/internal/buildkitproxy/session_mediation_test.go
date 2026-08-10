package buildkitproxy

import (
	"net/http"
	"testing"

	"github.com/codeswhat/sockguard/internal/buildkitproto/auth"
	"github.com/codeswhat/sockguard/internal/buildkitproto/secrets"
	"github.com/codeswhat/sockguard/internal/buildkitproto/sshforward"
)

// TestEvaluateAuthHostOnlyRPCs table-drives Credentials/GetTokenAuthority/
// VerifyTokenAuthority — the three moby.filesync.v1.Auth RPCs whose only
// Phase 4 policy check is the Host allowlist (FetchToken additionally checks
// Realm/Scopes — see TestEvaluateFetchTokenRequest).
func TestEvaluateAuthHostOnlyRPCs(t *testing.T) {
	allowed := AuthPolicy{Allow: true, AllowedRegistries: []string{"registry-1.docker.io", "ghcr.io"}}

	type evalFunc func(payload []byte, policy AuthPolicy) *mediationDenial

	rpcs := []struct {
		name    string
		eval    evalFunc
		payload func(host string) []byte
	}{
		{
			name: "Credentials",
			eval: func(payload []byte, policy AuthPolicy) *mediationDenial {
				_, d := evaluateCredentialsRequest(payload, policy)
				return d
			},
			payload: func(host string) []byte { return mustMarshal(t, &auth.CredentialsRequest{Host: host}) },
		},
		{
			name: "GetTokenAuthority",
			eval: func(payload []byte, policy AuthPolicy) *mediationDenial {
				_, d := evaluateGetTokenAuthorityRequest(payload, policy)
				return d
			},
			payload: func(host string) []byte {
				return mustMarshal(t, &auth.GetTokenAuthorityRequest{Host: host, Salt: []byte("salt")})
			},
		},
		{
			name: "VerifyTokenAuthority",
			eval: func(payload []byte, policy AuthPolicy) *mediationDenial {
				_, d := evaluateVerifyTokenAuthorityRequest(payload, policy)
				return d
			},
			payload: func(host string) []byte {
				return mustMarshal(t, &auth.VerifyTokenAuthorityRequest{Host: host, Payload: []byte("p"), Salt: []byte("s")})
			},
		},
	}

	for _, rpc := range rpcs {
		t.Run(rpc.name, func(t *testing.T) {
			t.Run("malformed payload", func(t *testing.T) {
				d := rpc.eval(malformedPayload, allowed)
				if denyReason(d) != "buildkit_protocol_error" {
					t.Fatalf("reason = %q, want buildkit_protocol_error", denyReason(d))
				}
			})
			t.Run("host not allowed", func(t *testing.T) {
				d := rpc.eval(rpc.payload("evil.example.com"), allowed)
				if denyReason(d) != "buildkit_policy_denied" {
					t.Fatalf("reason = %q, want buildkit_policy_denied", denyReason(d))
				}
			})
			t.Run("empty host is denied", func(t *testing.T) {
				d := rpc.eval(rpc.payload(""), allowed)
				if denyReason(d) != "buildkit_policy_denied" {
					t.Fatalf("reason = %q, want buildkit_policy_denied", denyReason(d))
				}
			})
			t.Run("host allowed", func(t *testing.T) {
				if d := rpc.eval(rpc.payload("ghcr.io"), allowed); d != nil {
					t.Fatalf("denied: %+v, want admitted", d)
				}
			})
			t.Run("mixed-case host normalizes to match", func(t *testing.T) {
				if d := rpc.eval(rpc.payload("GHCR.IO"), allowed); d != nil {
					t.Fatalf("denied: %+v, want admitted (case-insensitive host match)", d)
				}
			})
			t.Run("index.docker.io normalizes to docker.io", func(t *testing.T) {
				policy := AuthPolicy{Allow: true, AllowedRegistries: []string{"docker.io"}}
				if d := rpc.eval(rpc.payload("index.docker.io"), policy); d != nil {
					t.Fatalf("denied: %+v, want admitted (index.docker.io -> docker.io alias)", d)
				}
			})
		})
	}

	t.Run("unknown fields anywhere in the message", func(t *testing.T) {
		req := &auth.CredentialsRequest{Host: "ghcr.io"}
		req.ProtoReflect().SetUnknown(unknownFieldBytes())
		payload := mustMarshal(t, req)
		if _, d := evaluateCredentialsRequest(payload, allowed); denyReason(d) != "buildkit_schema_unsupported" {
			t.Fatalf("reason = %q, want buildkit_schema_unsupported", denyReason(d))
		}
	})
}

func TestEvaluateFetchTokenRequest(t *testing.T) {
	fullyAllowed := AuthPolicy{
		Allow:             true,
		AllowedRegistries: []string{"registry-1.docker.io"},
		AllowedRealms:     []string{"https://auth.docker.io/token"},
		AllowedScopes:     []string{"repository:library/alpine:pull"},
	}

	cases := []struct {
		name       string
		payload    []byte
		policy     AuthPolicy
		wantReason string
	}{
		{
			name:       "malformed payload",
			payload:    malformedPayload,
			policy:     fullyAllowed,
			wantReason: "buildkit_protocol_error",
		},
		{
			name: "unknown fields",
			payload: func() []byte {
				req := &auth.FetchTokenRequest{Host: "registry-1.docker.io"}
				req.ProtoReflect().SetUnknown(unknownFieldBytes())
				return mustMarshal(t, req)
			}(),
			policy:     fullyAllowed,
			wantReason: "buildkit_schema_unsupported",
		},
		{
			name: "host not allowed",
			payload: mustMarshal(t, &auth.FetchTokenRequest{
				Host: "evil.example.com", Realm: "https://auth.docker.io/token",
			}),
			policy:     fullyAllowed,
			wantReason: "buildkit_policy_denied",
		},
		{
			name: "realm not allowed",
			payload: mustMarshal(t, &auth.FetchTokenRequest{
				Host: "registry-1.docker.io", Realm: "https://evil.example.com/token",
			}),
			policy:     fullyAllowed,
			wantReason: "buildkit_policy_denied",
		},
		{
			name: "scope not allowed",
			payload: mustMarshal(t, &auth.FetchTokenRequest{
				Host: "registry-1.docker.io", Realm: "https://auth.docker.io/token",
				Scopes: []string{"repository:library/alpine:pull", "repository:secret/repo:pull"},
			}),
			policy:     fullyAllowed,
			wantReason: "buildkit_policy_denied",
		},
		{
			name: "admitted with matching realm and scopes",
			payload: mustMarshal(t, &auth.FetchTokenRequest{
				Host: "registry-1.docker.io", Realm: "https://auth.docker.io/token",
				Scopes: []string{"repository:library/alpine:pull"},
			}),
			policy: fullyAllowed,
		},
		{
			name: "admitted with no requested scopes",
			payload: mustMarshal(t, &auth.FetchTokenRequest{
				Host: "registry-1.docker.io", Realm: "https://auth.docker.io/token",
			}),
			policy: fullyAllowed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, d := evaluateFetchTokenRequest(tc.payload, tc.policy)
			if tc.wantReason == "" {
				if d != nil {
					t.Fatalf("denied: %+v, want admitted", d)
				}
				if req == nil {
					t.Fatal("admitted but req is nil")
				}
				return
			}
			if denyReason(d) != tc.wantReason {
				t.Fatalf("reason = %q, want %q", denyReason(d), tc.wantReason)
			}
			if req != nil {
				t.Fatal("denied but req is non-nil")
			}
		})
	}
}

func TestEvaluateGetSecretRequest(t *testing.T) {
	policy := SecretsPolicy{Allow: true, AllowedIDs: []string{"my-secret"}}

	cases := []struct {
		name       string
		payload    []byte
		wantReason string
	}{
		{
			name:       "malformed payload",
			payload:    malformedPayload,
			wantReason: "buildkit_protocol_error",
		},
		{
			name: "unknown fields",
			payload: func() []byte {
				req := &secrets.GetSecretRequest{ID: "my-secret"}
				req.ProtoReflect().SetUnknown(unknownFieldBytes())
				return mustMarshal(t, req)
			}(),
			wantReason: "buildkit_schema_unsupported",
		},
		{
			name:       "non-empty annotations are denied",
			payload:    mustMarshal(t, &secrets.GetSecretRequest{ID: "my-secret", Annotations: map[string]string{"foo": "bar"}}),
			wantReason: "buildkit_policy_denied",
		},
		{
			name:       "empty ID is denied",
			payload:    mustMarshal(t, &secrets.GetSecretRequest{ID: ""}),
			wantReason: "buildkit_policy_denied",
		},
		{
			name:       "ID not in allowlist",
			payload:    mustMarshal(t, &secrets.GetSecretRequest{ID: "other-secret"}),
			wantReason: "buildkit_policy_denied",
		},
		{
			name:    "admitted",
			payload: mustMarshal(t, &secrets.GetSecretRequest{ID: "my-secret"}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, d := evaluateGetSecretRequest(tc.payload, policy)
			if tc.wantReason == "" {
				if d != nil {
					t.Fatalf("denied: %+v, want admitted", d)
				}
				if req.GetID() != "my-secret" {
					t.Fatalf("req.ID = %q, want my-secret", req.GetID())
				}
				return
			}
			if denyReason(d) != tc.wantReason {
				t.Fatalf("reason = %q, want %q", denyReason(d), tc.wantReason)
			}
		})
	}
}

func TestEvaluateCheckAgentRequest(t *testing.T) {
	policy := SSHPolicy{Allow: true, AllowedIDs: []string{"default"}}

	cases := []struct {
		name       string
		payload    []byte
		wantReason string
	}{
		{
			name:       "malformed payload",
			payload:    malformedPayload,
			wantReason: "buildkit_protocol_error",
		},
		{
			name: "unknown fields",
			payload: func() []byte {
				req := &sshforward.CheckAgentRequest{ID: "default"}
				req.ProtoReflect().SetUnknown(unknownFieldBytes())
				return mustMarshal(t, req)
			}(),
			wantReason: "buildkit_schema_unsupported",
		},
		{
			name:       "empty ID is denied",
			payload:    mustMarshal(t, &sshforward.CheckAgentRequest{ID: ""}),
			wantReason: "buildkit_policy_denied",
		},
		{
			name:       "ID not in allowlist",
			payload:    mustMarshal(t, &sshforward.CheckAgentRequest{ID: "other"}),
			wantReason: "buildkit_policy_denied",
		},
		{
			name:    "admitted",
			payload: mustMarshal(t, &sshforward.CheckAgentRequest{ID: "default"}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, d := evaluateCheckAgentRequest(tc.payload, policy)
			if tc.wantReason == "" {
				if d != nil {
					t.Fatalf("denied: %+v, want admitted", d)
				}
				if req.GetID() != "default" {
					t.Fatalf("req.ID = %q, want default", req.GetID())
				}
				return
			}
			if denyReason(d) != tc.wantReason {
				t.Fatalf("reason = %q, want %q", denyReason(d), tc.wantReason)
			}
		})
	}
}

func TestCheckSSHAgentID(t *testing.T) {
	allowed := []string{"default", "extra"}

	if d := checkSSHAgentID("", allowed); denyReason(d) != "buildkit_policy_denied" {
		t.Fatalf("empty ID: reason = %q, want buildkit_policy_denied", denyReason(d))
	}
	if d := checkSSHAgentID("not-listed", allowed); denyReason(d) != "buildkit_policy_denied" {
		t.Fatalf("unlisted ID: reason = %q, want buildkit_policy_denied", denyReason(d))
	}
	if d := checkSSHAgentID("default", allowed); d != nil {
		t.Fatalf("listed ID denied: %+v, want admitted", d)
	}
	if d := checkSSHAgentID("default", nil); denyReason(d) != "buildkit_policy_denied" {
		t.Fatalf("empty allowlist: reason = %q, want buildkit_policy_denied (empty allowlist = deny all)", denyReason(d))
	}
}

func TestNormalizeAuthHost(t *testing.T) {
	cases := []struct {
		name     string
		host     string
		wantHost string
		wantOK   bool
	}{
		{name: "empty is invalid", host: "", wantOK: false},
		{name: "whitespace-only is invalid", host: "   ", wantOK: false},
		{name: "plain host lowercased", host: "Registry-1.Docker.IO", wantHost: "registry-1.docker.io", wantOK: true},
		{name: "index.docker.io aliases to docker.io", host: "INDEX.DOCKER.IO", wantHost: "docker.io", wantOK: true},
		{name: "already canonical host passes through", host: "ghcr.io", wantHost: "ghcr.io", wantOK: true},
		{name: "host with port preserved", host: "Registry.Example.com:5000", wantHost: "registry.example.com:5000", wantOK: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := normalizeAuthHost(tc.host)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got != tc.wantHost {
				t.Fatalf("host = %q, want %q", got, tc.wantHost)
			}
		})
	}
}

func TestCheckAuthRegistryHost(t *testing.T) {
	allowed := []string{"docker.io", "ghcr.io"}

	if d := checkAuthRegistryHost("", allowed); denyReason(d) != "buildkit_policy_denied" {
		t.Fatalf("empty host: reason = %q, want buildkit_policy_denied", denyReason(d))
	}
	if d := checkAuthRegistryHost("evil.example.com", allowed); denyReason(d) != "buildkit_policy_denied" {
		t.Fatalf("unlisted host: reason = %q, want buildkit_policy_denied", denyReason(d))
	}
	if d := checkAuthRegistryHost("GHCR.IO", allowed); d != nil {
		t.Fatalf("listed host (mixed case) denied: %+v, want admitted", d)
	}
	if d := checkAuthRegistryHost("index.docker.io", allowed); d != nil {
		t.Fatalf("index.docker.io denied: %+v, want admitted (aliases to docker.io)", d)
	}
}

func TestEvaluateForwardAgentID(t *testing.T) {
	policy := SSHPolicy{Allow: true, AllowedIDs: []string{"default"}}

	newReq := func(values ...string) *http.Request {
		req, err := http.NewRequest(http.MethodPost, "http://buildkit-test/moby.sshforward.v1.SSH/ForwardAgent", http.NoBody)
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}
		for _, v := range values {
			req.Header.Add(sshForwardAgentIDMetadataKey, v)
		}
		return req
	}

	t.Run("missing metadata is a protocol error", func(t *testing.T) {
		id, d := evaluateForwardAgentID(newReq(), policy)
		if id != "" {
			t.Fatalf("id = %q, want empty", id)
		}
		if denyReason(d) != "buildkit_protocol_error" {
			t.Fatalf("reason = %q, want buildkit_protocol_error", denyReason(d))
		}
	})

	t.Run("empty metadata value is a protocol error", func(t *testing.T) {
		_, d := evaluateForwardAgentID(newReq(""), policy)
		if denyReason(d) != "buildkit_protocol_error" {
			t.Fatalf("reason = %q, want buildkit_protocol_error", denyReason(d))
		}
	})

	t.Run("more than one metadata value is a protocol error", func(t *testing.T) {
		_, d := evaluateForwardAgentID(newReq("default", "other"), policy)
		if denyReason(d) != "buildkit_protocol_error" {
			t.Fatalf("reason = %q, want buildkit_protocol_error", denyReason(d))
		}
	})

	t.Run("ID not in allowlist is a policy denial", func(t *testing.T) {
		_, d := evaluateForwardAgentID(newReq("not-listed"), policy)
		if denyReason(d) != "buildkit_policy_denied" {
			t.Fatalf("reason = %q, want buildkit_policy_denied", denyReason(d))
		}
	})

	t.Run("admitted", func(t *testing.T) {
		id, d := evaluateForwardAgentID(newReq("default"), policy)
		if d != nil {
			t.Fatalf("denied: %+v, want admitted", d)
		}
		if id != "default" {
			t.Fatalf("id = %q, want default", id)
		}
	})
}

func TestShortHash(t *testing.T) {
	a := shortHash("my-secret")
	b := shortHash("my-secret")
	c := shortHash("other-secret")

	if a != b {
		t.Fatalf("shortHash is not deterministic: %q != %q", a, b)
	}
	if a == c {
		t.Fatal("shortHash produced the same output for two different inputs")
	}
	if len(a) != 12 {
		t.Fatalf("len(shortHash(...)) = %d, want 12 hex characters", len(a))
	}
	if a == "my-secret" || a == "" {
		t.Fatalf("shortHash(%q) = %q, want a hash, not the raw input", "my-secret", a)
	}
}
