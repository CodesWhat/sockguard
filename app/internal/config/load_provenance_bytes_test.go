package config

import "testing"

// Provenance must come from the bytes LoadWithData already read, never from a
// second read of the path, so a file replaced between reads can't change it.
func TestFileProvenanceReadsTheGivenBytes(t *testing.T) {
	if explicitLegacyListenFile(nil) {
		t.Fatal("nil bytes must not mark listen explicit")
	}
	if !explicitLegacyListenFile([]byte("listen:\n  socket: /run/s.sock\n")) {
		t.Fatal("listen.socket in the bytes must mark listen explicit")
	}
	got := explicitEndpointConfigFile([]byte("request_body:\n  network:\n    endpoint_config:\n      allow_aliases: false\n"))
	if !got.network {
		t.Fatalf("endpoint_config in the bytes must mark network explicit, got %+v", got)
	}
	if got := explicitEndpointConfigFile(nil); got.network || got.libpodNetwork {
		t.Fatalf("nil bytes must give zero provenance, got %+v", got)
	}
}
