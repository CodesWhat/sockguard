package imagetrust

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/verify"
)

// alwaysPassVerifier is a test stub Verifier that always returns nil.
type alwaysPassVerifier struct{}

func (a *alwaysPassVerifier) Verify(_ context.Context, _, _ string, _ verify.SignedEntity) error {
	return nil
}

var _ Verifier = (*alwaysPassVerifier)(nil)

// countingVerifier records how many times Verify is called and delegates to
// the inner Verifier. Used to assert that ModeOff skips the verifier entirely.
type countingVerifier struct {
	calls int
	inner Verifier
}

func (c *countingVerifier) Verify(ctx context.Context, imageRef, digestHex string, entity verify.SignedEntity) error {
	c.calls++
	return c.inner.Verify(ctx, imageRef, digestHex, entity)
}

var _ Verifier = (*countingVerifier)(nil)

// minimalCfgForMode returns the smallest valid Config for the given mode.
// For modes that require verifiers it uses a freshly-generated ECDSA key.
func minimalCfgForMode(t *testing.T, mode Mode) Config {
	t.Helper()
	if mode == ModeOff {
		return Config{Mode: ModeOff}
	}
	pemStr, _ := generateECDSAKey(t)
	cfg, err := BuildConfig(RawConfig{
		Mode:               mode,
		AllowedSigningKeys: []SigningKeyConfig{{PEM: pemStr}},
	})
	if err != nil {
		t.Fatalf("minimalCfgForMode(%s): BuildConfig: %v", mode, err)
	}
	return cfg
}

// TestVerifyCandidatesWithMode_Off_AlwaysAllows verifies that ModeOff returns
// Allowed=true and never calls the verifier.
func TestVerifyCandidatesWithMode_Off_AlwaysAllows(t *testing.T) {
	t.Parallel()
	cfg := Config{Mode: ModeOff}
	cv := &countingVerifier{inner: &alwaysFailVerifier{}}

	outcome := VerifyCandidatesWithMode(context.Background(), cv, cfg, nil, "reg/img:tag", nil, errors.New("fetch error"))

	if !outcome.Allowed {
		t.Fatal("mode=off must return Allowed=true")
	}
	if outcome.Verifier != "off" {
		t.Fatalf("Verifier = %q, want off", outcome.Verifier)
	}
	if cv.calls != 0 {
		t.Fatalf("Verify was called %d time(s); must not be called in mode=off", cv.calls)
	}
}

// TestVerifyCandidatesWithMode_Enforce_AllFail_Denied verifies that when all
// candidates fail verification in enforce mode the request is denied with a
// descriptive failure message.
func TestVerifyCandidatesWithMode_Enforce_AllFail_Denied(t *testing.T) {
	t.Parallel()
	cfg := minimalCfgForMode(t, ModeEnforce)
	candidates := []Candidate{
		{DigestHex: "aaaa", Entity: nil},
		{DigestHex: "bbbb", Entity: nil},
	}

	outcome := VerifyCandidatesWithMode(context.Background(), &alwaysFailVerifier{}, cfg, nil, "reg/img:tag", candidates, nil)

	if outcome.Allowed {
		t.Fatal("mode=enforce with all-failing candidates must deny")
	}
	if outcome.Verifier != "denied" {
		t.Fatalf("Verifier = %q, want denied", outcome.Verifier)
	}
	if outcome.FailureMsg == "" {
		t.Fatal("FailureMsg must be non-empty on denial")
	}
	if !strings.Contains(outcome.FailureMsg, "reg/img:tag") {
		t.Fatalf("FailureMsg = %q; want image ref included", outcome.FailureMsg)
	}
}

// TestVerifyCandidatesWithMode_Warn_AllFail_Allowed verifies that when all
// candidates fail verification in warn mode the request is still allowed but
// FailureMsg and Verifier indicate the bypass.
func TestVerifyCandidatesWithMode_Warn_AllFail_Allowed(t *testing.T) {
	t.Parallel()
	cfg := minimalCfgForMode(t, ModeWarn)
	candidates := []Candidate{
		{DigestHex: "aaaa", Entity: nil},
	}

	outcome := VerifyCandidatesWithMode(context.Background(), &alwaysFailVerifier{}, cfg, slog.Default(), "reg/img:tag", candidates, nil)

	if !outcome.Allowed {
		t.Fatal("mode=warn must allow even when all candidates fail")
	}
	if outcome.Verifier != "warn-bypass" {
		t.Fatalf("Verifier = %q, want warn-bypass", outcome.Verifier)
	}
	if outcome.FailureMsg == "" {
		t.Fatal("FailureMsg must be populated on warn bypass")
	}
}

// TestVerifyCandidatesWithMode_FetchError_SurfacedInFailureMsg verifies that
// when candidates is nil and a fetchErr is provided the failure message
// contains the fetch error text (so operators can distinguish "no signatures"
// from "registry unreachable").
func TestVerifyCandidatesWithMode_FetchError_SurfacedInFailureMsg(t *testing.T) {
	t.Parallel()
	cfg := minimalCfgForMode(t, ModeEnforce)
	fetchErr := errors.New("registry unreachable: connection refused")

	outcome := VerifyCandidatesWithMode(context.Background(), &alwaysFailVerifier{}, cfg, nil, "reg/img:tag", nil, fetchErr)

	if outcome.Allowed {
		t.Fatal("mode=enforce with no candidates must deny")
	}
	if !strings.Contains(outcome.FailureMsg, "registry unreachable") {
		t.Fatalf("FailureMsg = %q; want fetch error text surfaced", outcome.FailureMsg)
	}
}

// TestVerifyCandidatesWithMode_FetchError_WarnMode_Allowed verifies that a
// fetch error in warn mode still allows the request but surfaces the fetch
// error in FailureMsg.
func TestVerifyCandidatesWithMode_FetchError_WarnMode_Allowed(t *testing.T) {
	t.Parallel()
	cfg := minimalCfgForMode(t, ModeWarn)
	fetchErr := errors.New("registry unreachable: timeout")

	outcome := VerifyCandidatesWithMode(context.Background(), &alwaysFailVerifier{}, cfg, nil, "reg/img:tag", nil, fetchErr)

	if !outcome.Allowed {
		t.Fatal("mode=warn must allow even on fetch error")
	}
	if outcome.Verifier != "warn-bypass" {
		t.Fatalf("Verifier = %q, want warn-bypass", outcome.Verifier)
	}
	if !strings.Contains(outcome.FailureMsg, "registry unreachable") {
		t.Fatalf("FailureMsg = %q; want fetch error text surfaced", outcome.FailureMsg)
	}
}

// TestVerifyCandidatesWithMode_FirstCandidateVerifies_Allowed verifies the
// "first candidate wins" path: when the first candidate passes verification
// the call succeeds immediately and VerifiedDigest is populated.
func TestVerifyCandidatesWithMode_FirstCandidateVerifies_Allowed(t *testing.T) {
	t.Parallel()
	cfg := minimalCfgForMode(t, ModeEnforce)
	const wantDigest = "sha256:cafebabe"
	candidates := []Candidate{
		{DigestHex: "cafebabe", Entity: nil, ImageDigest: wantDigest},
		// second candidate should never be reached
		{DigestHex: "deadbeef", Entity: nil, ImageDigest: "sha256:deadbeef"},
	}
	cv := &countingVerifier{inner: &alwaysPassVerifier{}}

	outcome := VerifyCandidatesWithMode(context.Background(), cv, cfg, nil, "reg/img:tag", candidates, nil)

	if !outcome.Allowed {
		t.Fatalf("expected Allowed=true, got false (FailureMsg=%q)", outcome.FailureMsg)
	}
	if outcome.Verifier != "verified" {
		t.Fatalf("Verifier = %q, want verified", outcome.Verifier)
	}
	if outcome.VerifiedDigest != wantDigest {
		t.Fatalf("VerifiedDigest = %q, want %q", outcome.VerifiedDigest, wantDigest)
	}
	// The alwaysPassVerifier succeeds on the first call, so Verify must have been
	// called exactly once.
	if cv.calls != 1 {
		t.Fatalf("Verify called %d time(s); want exactly 1 (first-wins)", cv.calls)
	}
}

// TestVerifyCandidatesWithMode_NilCandidatesNoFetchErr_Denied ensures that
// nil candidates with no fetch error produce a "no signatures found" message.
func TestVerifyCandidatesWithMode_NilCandidatesNoFetchErr_Denied(t *testing.T) {
	t.Parallel()
	cfg := minimalCfgForMode(t, ModeEnforce)

	outcome := VerifyCandidatesWithMode(context.Background(), &alwaysFailVerifier{}, cfg, nil, "reg/img:tag", nil, nil)

	if outcome.Allowed {
		t.Fatal("no candidates and no fetch error must deny in enforce mode")
	}
	if !strings.Contains(outcome.FailureMsg, "no signatures found") {
		t.Fatalf("FailureMsg = %q; want 'no signatures found'", outcome.FailureMsg)
	}
}

// TestVerifyCandidatesWithMode_TableDriven is a compact table-driven sweep over
// the (mode, candidates, fetchErr) → (Allowed, Verifier) matrix.
func TestVerifyCandidatesWithMode_TableDriven(t *testing.T) {
	t.Parallel()

	passingCandidate := Candidate{DigestHex: "aabbcc", Entity: nil, ImageDigest: "sha256:aabbcc"}
	failingCandidate := Candidate{DigestHex: "ddeeff", Entity: nil}
	fetchErr := errors.New("network error")

	tests := []struct {
		name          string
		mode          Mode
		verifier      Verifier
		candidates    []Candidate
		fetchErr      error
		wantAllowed   bool
		wantVerifier  string
		wantFailureIn string // non-empty: substring that must appear in FailureMsg
	}{
		{
			name:         "off / passing candidates",
			mode:         ModeOff,
			verifier:     &alwaysPassVerifier{},
			candidates:   []Candidate{passingCandidate},
			wantAllowed:  true,
			wantVerifier: "off",
		},
		{
			name:         "off / nil candidates + fetch error",
			mode:         ModeOff,
			verifier:     &alwaysFailVerifier{},
			candidates:   nil,
			fetchErr:     fetchErr,
			wantAllowed:  true,
			wantVerifier: "off",
		},
		{
			name:         "enforce / first candidate passes",
			mode:         ModeEnforce,
			verifier:     &alwaysPassVerifier{},
			candidates:   []Candidate{passingCandidate},
			wantAllowed:  true,
			wantVerifier: "verified",
		},
		{
			name:          "enforce / all fail",
			mode:          ModeEnforce,
			verifier:      &alwaysFailVerifier{},
			candidates:    []Candidate{failingCandidate},
			wantAllowed:   false,
			wantVerifier:  "denied",
			wantFailureIn: "no configured signer matched",
		},
		{
			name:          "enforce / nil candidates + fetch error",
			mode:          ModeEnforce,
			verifier:      &alwaysFailVerifier{},
			candidates:    nil,
			fetchErr:      fetchErr,
			wantAllowed:   false,
			wantVerifier:  "denied",
			wantFailureIn: "network error",
		},
		{
			name:         "warn / all fail → allowed",
			mode:         ModeWarn,
			verifier:     &alwaysFailVerifier{},
			candidates:   []Candidate{failingCandidate},
			wantAllowed:  true,
			wantVerifier: "warn-bypass",
		},
		{
			name:         "warn / nil candidates + fetch error → allowed",
			mode:         ModeWarn,
			verifier:     &alwaysFailVerifier{},
			candidates:   nil,
			fetchErr:     fetchErr,
			wantAllowed:  true,
			wantVerifier: "warn-bypass",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := minimalCfgForMode(t, tc.mode)
			outcome := VerifyCandidatesWithMode(context.Background(), tc.verifier, cfg, nil, "reg/img:tag", tc.candidates, tc.fetchErr)

			if outcome.Allowed != tc.wantAllowed {
				t.Fatalf("Allowed = %v, want %v (FailureMsg=%q)", outcome.Allowed, tc.wantAllowed, outcome.FailureMsg)
			}
			if outcome.Verifier != tc.wantVerifier {
				t.Fatalf("Verifier = %q, want %q", outcome.Verifier, tc.wantVerifier)
			}
			if tc.wantFailureIn != "" && !strings.Contains(outcome.FailureMsg, tc.wantFailureIn) {
				t.Fatalf("FailureMsg = %q; want substring %q", outcome.FailureMsg, tc.wantFailureIn)
			}
		})
	}
}
