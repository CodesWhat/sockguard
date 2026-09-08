package config

import "testing"

// The three `len(data) > 0` guards this test covers (explicitLegacyListenBytes,
// explicitEndpointConfigBytes and LoadBytes) are equivalent under `>= 0`,
// verified by hand-applying the mutation and re-running this package: viper's
// ReadConfig over an empty reader parses to no keys and returns no error, so
// running it is indistinguishable from skipping it. The test pins the contract
// the guards implement rather than the guards themselves.

// TestBytesReadersTreatAnEmptyDocumentAsNoDocument pins that the three
// LoadBytes-side readers answer the same way for an empty body as they would
// for a body that parses to nothing: no explicit legacy listen, no explicit
// endpoint config, and a config that is exactly Defaults(). An empty candidate
// body is what a signed-bundle verification path hands in when the bundle
// carries no YAML at all, so it has to be a clean "nothing was set" rather
// than a parse error.
func TestBytesReadersTreatAnEmptyDocumentAsNoDocument(t *testing.T) {
	for _, data := range [][]byte{nil, {}} {
		if got := explicitLegacyListenBytes(data); got {
			t.Fatalf("explicitLegacyListenBytes(%q) = true, want false", data)
		}
		if got := explicitEndpointConfigBytes(data); got.network || got.libpodNetwork || len(got.profiles) != 0 {
			t.Fatalf("explicitEndpointConfigBytes(%q) = %+v, want the zero provenance", data, got)
		}
		cfg, err := LoadBytes(data)
		if err != nil {
			t.Fatalf("LoadBytes(%q) error = %v", data, err)
		}
		if cfg == nil {
			t.Fatalf("LoadBytes(%q) returned a nil config", data)
		}
		defaults := Defaults()
		if cfg.Upstream.Socket != defaults.Upstream.Socket {
			t.Fatalf("LoadBytes(%q) upstream.socket = %q, want the default %q",
				data, cfg.Upstream.Socket, defaults.Upstream.Socket)
		}
		if cfg.Log.Format != defaults.Log.Format {
			t.Fatalf("LoadBytes(%q) log.format = %q, want the default %q",
				data, cfg.Log.Format, defaults.Log.Format)
		}
	}
}
