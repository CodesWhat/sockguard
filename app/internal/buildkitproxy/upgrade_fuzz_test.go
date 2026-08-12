package buildkitproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzValidateUpgradeRequest fuzzes ValidateUpgradeRequest's strict h2c
// upgrade validation across arbitrary method/header/framing combinations.
// The upgrade string parameter packs multiple Upgrade header VALUES
// separated by "\x00" — Go's http.Header supports repeated header values
// (see TestValidateUpgradeRequest's "multiple Upgrade values" case), which a
// single fuzzed string can't represent directly, so a delimiter byte that
// never appears in a legitimate header token stands in for multiple
// Header.Add calls.
//
// Invariant: never panics, for any combination. And — "malformed input never
// yields an accepted upgrade" — whenever ValidateUpgradeRequest returns nil,
// every structural property it is documented to guarantee must actually
// hold on the request: this is checked directly below rather than asserted
// only implicitly, so a future change that returns nil too early (e.g. on a
// second, non-"h2c" Upgrade value) would fail this fuzz target even if no
// seed happens to hit that exact shape.
func FuzzValidateUpgradeRequest(f *testing.F) {
	f.Add(http.MethodPost, "Upgrade", "h2c", int64(0), "")
	f.Add(http.MethodPost, "keep-alive", "h2c", int64(0), "")
	f.Add(http.MethodGet, "Upgrade", "h2c", int64(0), "")
	f.Add(http.MethodPost, "Upgrade", "H2C", int64(0), "")
	f.Add(http.MethodPost, "Upgrade", "websocket", int64(0), "")
	f.Add(http.MethodPost, "Upgrade", "h2c", int64(10), "")
	f.Add(http.MethodPost, "Upgrade", "h2c", int64(0), "chunked")
	f.Add(http.MethodPost, "Upgrade, keep-alive", "h2c", int64(0), "")
	f.Add("", "", "", int64(0), "")
	f.Add(http.MethodPost, "upgrade", "h2c\x00websocket", int64(0), "")
	f.Add(http.MethodPost, "Upgrade", " h2c ", int64(0), "")
	f.Add(http.MethodPost, "Upgrade", "", int64(0), "")
	f.Add(http.MethodPut, "Upgrade", "h2c", int64(-1), "")

	f.Fuzz(func(t *testing.T, method, connection, upgrade string, contentLength int64, transferEncoding string) {
		r := httptest.NewRequest(http.MethodPost, "/session", nil)
		r.Method = method
		r.Header.Del("Connection")
		r.Header.Del("Upgrade")
		if connection != "" {
			r.Header.Set("Connection", connection)
		}
		if upgrade != "" {
			for _, v := range strings.Split(upgrade, "\x00") {
				r.Header.Add("Upgrade", v)
			}
		}
		r.ContentLength = contentLength
		if transferEncoding != "" {
			r.TransferEncoding = []string{transferEncoding}
		}

		err := ValidateUpgradeRequest(r)
		if err == nil {
			if r.Method != http.MethodPost {
				t.Fatalf("accepted upgrade with Method = %q, want POST", r.Method)
			}
			if !headerHasToken(r.Header, "Connection", "upgrade") {
				t.Fatalf("accepted upgrade whose Connection header %q does not carry the upgrade token", r.Header.Values("Connection"))
			}
			upgradeValues := r.Header.Values("Upgrade")
			if len(upgradeValues) != 1 || !strings.EqualFold(strings.TrimSpace(upgradeValues[0]), "h2c") {
				t.Fatalf("accepted upgrade whose Upgrade header is %v, want exactly one case-insensitive \"h2c\" value", upgradeValues)
			}
			if r.ContentLength > 0 {
				t.Fatalf("accepted upgrade with ContentLength = %d, want <= 0 (no body permitted)", r.ContentLength)
			}
			if len(r.TransferEncoding) > 0 {
				t.Fatalf("accepted upgrade with TransferEncoding = %v, want none", r.TransferEncoding)
			}
		}
	})
}

// fuzzAdvertisementPolicies parallels fuzzSolvePolicies for
// FuzzRewriteSessionAdvertisement: a fixed set of Policy fixtures a fuzzed
// index selects between, spanning fully-denied, fully-permissive, and one
// mixed profile that admits exactly one EndpointSession service
// (moby.filesync.v1.FileSync) so the subset-intersection invariant below has
// a genuinely partial case to exercise, not just "everything" or "nothing".
var fuzzAdvertisementPolicies = []Policy{
	{},
	allowAllPolicy,
	{Session: SessionPolicy{FileSync: FileSyncPolicy{Allow: true}}},
}

// FuzzRewriteSessionAdvertisement fuzzes rewriteSessionAdvertisement's
// narrowing of the client-advertised X-Docker-Expose-Session-Grpc-Method
// header. servicesJoined packs an arbitrary list of advertised service names
// as "\n"-separated values (mirroring FuzzValidateUpgradeRequest's "\x00"
// packing trick above) so a single fuzzed string can drive an arbitrary
// number of header entries.
//
// Invariant: never panics, and the header's value set AFTER rewriting is
// always a subset of (the trimmed, non-empty input set) INTERSECTED with
// "permitted by this policy" (ServiceAdmittedByPolicy) — rewriteSessionAdvertisement
// must never keep a value it wasn't given, and never keep one the policy
// doesn't actually admit.
func FuzzRewriteSessionAdvertisement(f *testing.F) {
	f.Add("moby.filesync.v1.FileSync\nmoby.buildkit.v1.frontend.LLBBridge\nmoby.filesync.v1.Auth", uint8(0))
	f.Add("", uint8(0))
	f.Add("   \n\n  ", uint8(1))
	f.Add("moby.notreal.v1.Bogus", uint8(2))
	f.Add(strings.Repeat("moby.filesync.v1.Auth\n", 50), uint8(2))
	f.Add("moby.filesync.v1.FileSync", uint8(2))
	f.Add("moby.filesync.v1.FileSync\nmoby.filesync.v1.FileSync", uint8(2)) // duplicate entries
	f.Add("\x00not-a-real-header-value\x00", uint8(1))

	f.Fuzz(func(t *testing.T, servicesJoined string, policyIdx uint8) {
		h := http.Header{}
		for _, s := range strings.Split(servicesJoined, "\n") {
			h.Add(sessionGRPCMethodHeader, s)
		}
		original := append([]string(nil), h.Values(sessionGRPCMethodHeader)...)
		p := fuzzAdvertisementPolicies[int(policyIdx)%len(fuzzAdvertisementPolicies)]

		rewriteSessionAdvertisement(h, p)

		originalTrimmed := map[string]bool{}
		for _, s := range original {
			if s = strings.TrimSpace(s); s != "" {
				originalTrimmed[s] = true
			}
		}

		for _, s := range h.Values(sessionGRPCMethodHeader) {
			if !originalTrimmed[s] {
				t.Fatalf("rewritten advertisement contains %q, which was never present (after trim) in the original advertisement %v", s, original)
			}
			if !ServiceAdmittedByPolicy(EndpointSession, s, p) {
				t.Fatalf("rewritten advertisement kept %q, which this policy does not permit", s)
			}
		}
	})
}
