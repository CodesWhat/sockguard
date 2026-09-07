package config

import "testing"

// TestApplyEndpointConfigProvenanceToleratesFewerProvenanceEntries pins the
// index guard that pairs each client profile with its provenance record.
// Provenance is derived from the YAML document, so a config carrying more
// profiles than the document accounted for has to fall back to the zero
// record rather than read off the end of the slice.
func TestApplyEndpointConfigProvenanceToleratesFewerProvenanceEntries(t *testing.T) {
	tests := []struct {
		name       string
		profiles   int
		provenance endpointConfigProvenance
	}{
		{name: "no provenance records at all", profiles: 1, provenance: endpointConfigProvenance{}},
		{
			name:       "fewer records than profiles",
			profiles:   3,
			provenance: endpointConfigProvenance{profiles: []clientProfileEndpointConfigProvenance{{network: true}}},
		},
		{
			name:     "one record per profile",
			profiles: 2,
			provenance: endpointConfigProvenance{profiles: []clientProfileEndpointConfigProvenance{
				{network: true, networkAllowAliases: true},
				{libpodNetwork: true, libpodNetworkAllowAliases: true},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Clients.Profiles = make([]ClientProfileConfig, tt.profiles)

			applyEndpointConfigProvenance(cfg, tt.provenance)

			for i := range cfg.Clients.Profiles {
				profile := &cfg.Clients.Profiles[i]
				var want clientProfileEndpointConfigProvenance
				if i < len(tt.provenance.profiles) {
					want = tt.provenance.profiles[i]
				}
				if profile.explicitNetworkEndpointConfig != want.network {
					t.Fatalf("profile %d explicitNetworkEndpointConfig = %v, want %v",
						i, profile.explicitNetworkEndpointConfig, want.network)
				}
				if profile.explicitLibpodNetworkEndpointConfig != want.libpodNetwork {
					t.Fatalf("profile %d explicitLibpodNetworkEndpointConfig = %v, want %v",
						i, profile.explicitLibpodNetworkEndpointConfig, want.libpodNetwork)
				}
				// An unset allow_aliases defaults to true; only a record that
				// says the document spelled it out leaves it alone.
				if got, wantAliases := profile.RequestBody.Network.EndpointConfig.AllowAliases, !want.networkAllowAliases; got != wantAliases {
					t.Fatalf("profile %d network allow_aliases = %v, want %v", i, got, wantAliases)
				}
				if got, wantAliases := profile.RequestBody.LibpodNetwork.EndpointConfig.AllowAliases, !want.libpodNetworkAllowAliases; got != wantAliases {
					t.Fatalf("profile %d libpod network allow_aliases = %v, want %v", i, got, wantAliases)
				}
			}
		})
	}
}
