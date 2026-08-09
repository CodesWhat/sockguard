package buildkitproxy

import "testing"

// TestPolicyConfiguredZeroValue asserts a zero-value Policy — the "block was
// never written" case — is not Configured.
func TestPolicyConfiguredZeroValue(t *testing.T) {
	if (Policy{}).Configured() {
		t.Fatal("zero-value Policy.Configured() = true, want false")
	}
}

// TestPolicyConfiguredEmptyNonNilSlices pins the fix for CodeRabbit's
// finding: an explicitly written but empty allowlist (e.g.
// allowed_registries: []) parses to a non-nil empty slice. The old
// reflect.DeepEqual-against-zero-value implementation treated that as
// "configured" purely because the slice was non-nil, even though it denies
// everything exactly like an absent block does. Configured() must key off
// length, not nilness.
func TestPolicyConfiguredEmptyNonNilSlices(t *testing.T) {
	p := Policy{
		Session: SessionPolicy{
			Auth: AuthPolicy{
				AllowedRegistries: []string{},
				AllowedRealms:     []string{},
				AllowedScopes:     []string{},
			},
			Secrets: SecretsPolicy{AllowedIDs: []string{}},
			SSH:     SSHPolicy{AllowedIDs: []string{}},
		},
	}
	if p.Configured() {
		t.Fatal("Policy with only empty-but-non-nil slices: Configured() = true, want false")
	}
}

// TestPolicyConfiguredEachField enumerates every leaf field of Policy and
// asserts that setting it alone (all others left at zero value) makes
// Configured() report true — guarding against a future field being added to
// the struct without a matching clause in Configured().
func TestPolicyConfiguredEachField(t *testing.T) {
	cases := []struct {
		name   string
		policy Policy
	}{
		{"Control.AllowInfo", Policy{Control: ControlPolicy{AllowInfo: true}}},
		{"Control.AllowListWorkers", Policy{Control: ControlPolicy{AllowListWorkers: true}}},
		{"Control.AllowStatus", Policy{Control: ControlPolicy{AllowStatus: true}}},
		{"Control.Solve.Allow", Policy{Control: ControlPolicy{Solve: SolvePolicy{Allow: true}}}},
		{"Session.Health", Policy{Session: SessionPolicy{Health: true}}},
		{"Session.Auth.Allow", Policy{Session: SessionPolicy{Auth: AuthPolicy{Allow: true}}}},
		{"Session.Auth.AllowedRegistries", Policy{Session: SessionPolicy{Auth: AuthPolicy{AllowedRegistries: []string{"docker.io"}}}}},
		{"Session.Auth.AllowedRealms", Policy{Session: SessionPolicy{Auth: AuthPolicy{AllowedRealms: []string{"realm"}}}}},
		{"Session.Auth.AllowedScopes", Policy{Session: SessionPolicy{Auth: AuthPolicy{AllowedScopes: []string{"scope"}}}}},
		{"Session.Secrets.Allow", Policy{Session: SessionPolicy{Secrets: SecretsPolicy{Allow: true}}}},
		{"Session.Secrets.AllowedIDs", Policy{Session: SessionPolicy{Secrets: SecretsPolicy{AllowedIDs: []string{"id"}}}}},
		{"Session.SSH.Allow", Policy{Session: SessionPolicy{SSH: SSHPolicy{Allow: true}}}},
		{"Session.SSH.AllowedIDs", Policy{Session: SessionPolicy{SSH: SSHPolicy{AllowedIDs: []string{"id"}}}}},
		{"Session.FileSync.Allow", Policy{Session: SessionPolicy{FileSync: FileSyncPolicy{Allow: true}}}},
		{"Session.FileSend.Allow", Policy{Session: SessionPolicy{FileSend: FileSendPolicy{Allow: true}}}},
		{"Session.Upload.Allow", Policy{Session: SessionPolicy{Upload: UploadPolicy{Allow: true}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.policy.Configured() {
				t.Fatalf("Policy with only %s set: Configured() = false, want true", tc.name)
			}
		})
	}
}
