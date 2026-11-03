package filter

import "testing"

func TestImageLoadOCIIndexReferencesComparesANamedDigest(t *testing.T) {
	t.Parallel()
	const manifest = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const other = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	tests := []struct {
		name    string
		ref     string
		wantErr bool
	}{
		{name: "tag only", ref: "ghcr.io/acme/app:v1"},
		{name: "digest of its own manifest", ref: "ghcr.io/acme/app@" + manifest},
		{name: "tag and digest of its own manifest", ref: "ghcr.io/acme/app:v1@" + manifest},
		{name: "digest of another manifest", ref: "ghcr.io/acme/app@" + other, wantErr: true},
		{name: "tag and digest of another manifest", ref: "ghcr.io/acme/app:v1@" + other, wantErr: true},
		{name: "digest in another case", ref: "ghcr.io/acme/app@SHA256:" + manifest[len("sha256:"):], wantErr: true},
		{name: "empty digest", ref: "ghcr.io/acme/app@", wantErr: true},
	}
	for _, annotation := range []string{containerdImageNameAnnotation, ociImageRefNameAnnotation} {
		for _, tt := range tests {
			t.Run(annotation+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				refs, _, err := imageLoadOCIIndexReferences([]imageLoadOCIIndexDescriptor{{
					Digest:      manifest,
					Annotations: map[string]string{annotation: tt.ref},
				}})
				if (err != nil) != tt.wantErr {
					t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
				}
				if !tt.wantErr && (len(refs) != 1 || refs[0] != tt.ref) {
					t.Fatalf("refs = %q, want %q", refs, tt.ref)
				}
			})
		}
	}
}
