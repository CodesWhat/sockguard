package config

// filter_options_coverage_gap_test.go covers the two translation functions that
// were absent from filter_options_test.go:
//
//   - ImageTrustConfig.toFilterOptions → filter.ImageTrustOptions round-trip
//   - toFilterAllowedDeviceRequests list translation

import (
	"reflect"
	"testing"

	"github.com/codeswhat/sockguard/internal/filter"
)

// TestImageTrustConfigToFilterOptionsRoundTrip verifies that every field in
// ImageTrustConfig (mode, allowed_signing_keys, allowed_keyless,
// require_rekor_inclusion, verify_timeout) is preserved through the
// toFilterOptions translation.
func TestImageTrustConfigToFilterOptionsRoundTrip(t *testing.T) {
	cfg := ImageTrustConfig{
		Mode: "enforce",
		AllowedSigningKeys: []SigningKeyConfig{
			{PEM: "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----"},
			{PEM: "-----BEGIN PUBLIC KEY-----\ndef\n-----END PUBLIC KEY-----"},
		},
		AllowedKeyless: []KeylessConfig{
			{Issuer: "https://accounts.google.com", SubjectPattern: ".*@example\\.com"},
			{Issuer: "https://token.actions.githubusercontent.com", SubjectPattern: "repo:owner/repo:.*"},
		},
		RequireRekorInclusion: true,
		VerifyTimeout:         "30s",
	}

	got := cfg.toFilterOptions()

	want := filter.ImageTrustOptions{
		Mode: "enforce",
		AllowedSigningKeys: []filter.SigningKeyOptions{
			{PEM: "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----"},
			{PEM: "-----BEGIN PUBLIC KEY-----\ndef\n-----END PUBLIC KEY-----"},
		},
		AllowedKeyless: []filter.KeylessOptions{
			{Issuer: "https://accounts.google.com", SubjectPattern: ".*@example\\.com"},
			{Issuer: "https://token.actions.githubusercontent.com", SubjectPattern: "repo:owner/repo:.*"},
		},
		RequireRekorInclusion: true,
		VerifyTimeout:         "30s",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ImageTrustConfig.toFilterOptions() =\n%#v\nwant\n%#v", got, want)
	}
}

// TestImageTrustConfigToFilterOptionsEmptySlicesProduceNil verifies that empty
// AllowedSigningKeys and AllowedKeyless slices translate to nil (not empty
// slices) so reflect.DeepEqual comparisons in the caller remain stable.
func TestImageTrustConfigToFilterOptionsEmptySlicesProduceNil(t *testing.T) {
	cfg := ImageTrustConfig{
		Mode: "warn",
	}
	got := cfg.toFilterOptions()
	if got.AllowedSigningKeys != nil {
		t.Fatalf("AllowedSigningKeys = %v, want nil for empty input", got.AllowedSigningKeys)
	}
	if got.AllowedKeyless != nil {
		t.Fatalf("AllowedKeyless = %v, want nil for empty input", got.AllowedKeyless)
	}
}

// TestToFilterAllowedDeviceRequestsPreservesAllFields verifies that a
// multi-entry allowed_device_requests list is translated to
// []filter.AllowedDeviceRequestEntry without dropping any entry or field.
func TestToFilterAllowedDeviceRequestsPreservesAllFields(t *testing.T) {
	maxOne := 1
	maxAll := -1

	input := []AllowedDeviceRequest{
		{
			Driver:              "nvidia",
			AllowedCapabilities: [][]string{{"gpu"}, {"gpu", "compute"}},
			MaxCount:            &maxOne,
		},
		{
			Driver:              "amd",
			AllowedCapabilities: [][]string{{"gpu"}},
			MaxCount:            &maxAll,
		},
		{
			Driver:              "generic",
			AllowedCapabilities: nil,
			MaxCount:            nil,
		},
	}

	got := toFilterAllowedDeviceRequests(input)

	if len(got) != 3 {
		t.Fatalf("len(got) = %d, want 3", len(got))
	}

	// Entry 0 — nvidia
	if got[0].Driver != "nvidia" {
		t.Fatalf("got[0].Driver = %q, want %q", got[0].Driver, "nvidia")
	}
	if !reflect.DeepEqual(got[0].AllowedCapabilities, [][]string{{"gpu"}, {"gpu", "compute"}}) {
		t.Fatalf("got[0].AllowedCapabilities = %v, want [[gpu] [gpu compute]]", got[0].AllowedCapabilities)
	}
	if got[0].MaxCount == nil || *got[0].MaxCount != 1 {
		t.Fatalf("got[0].MaxCount = %v, want *1", got[0].MaxCount)
	}

	// Entry 1 — amd
	if got[1].Driver != "amd" {
		t.Fatalf("got[1].Driver = %q, want %q", got[1].Driver, "amd")
	}
	if got[1].MaxCount == nil || *got[1].MaxCount != -1 {
		t.Fatalf("got[1].MaxCount = %v, want *-1", got[1].MaxCount)
	}

	// Entry 2 — generic (nil caps and nil max)
	if got[2].Driver != "generic" {
		t.Fatalf("got[2].Driver = %q, want %q", got[2].Driver, "generic")
	}
	if got[2].AllowedCapabilities != nil {
		t.Fatalf("got[2].AllowedCapabilities = %v, want nil", got[2].AllowedCapabilities)
	}
	if got[2].MaxCount != nil {
		t.Fatalf("got[2].MaxCount = %v, want nil", got[2].MaxCount)
	}
}

// TestToFilterAllowedDeviceRequestsEmptyReturnsNil verifies the nil-sentinel
// contract documented on toFilterAllowedDeviceRequests.
func TestToFilterAllowedDeviceRequestsEmptyReturnsNil(t *testing.T) {
	if got := toFilterAllowedDeviceRequests(nil); got != nil {
		t.Fatalf("toFilterAllowedDeviceRequests(nil) = %v, want nil", got)
	}
	if got := toFilterAllowedDeviceRequests([]AllowedDeviceRequest{}); got != nil {
		t.Fatalf("toFilterAllowedDeviceRequests([]) = %v, want nil", got)
	}
}
