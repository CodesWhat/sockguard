package filter

import (
	"strings"
	"testing"
)

// TestValidatedImageLoadOCIBlobAcceptsAZeroSizeDescriptor pins the lower edge
// of the descriptor size check. Zero is a legal OCI descriptor size (an empty
// blob is what an image with no config data references), so only a negative
// size or a size that disagrees with the stored blob is a rejection. Every
// other case in the archive tests uses a non-empty blob, which leaves the
// zero-size case free to become a rejection.
func TestValidatedImageLoadOCIBlobAcceptsAZeroSizeDescriptor(t *testing.T) {
	const emptyDigest = "sha256:" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	path, _, _, ok := imageLoadOCIDigestDetails(emptyDigest)
	if !ok {
		t.Fatalf("imageLoadOCIDigestDetails(%q) rejected a well-formed digest", emptyDigest)
	}

	tests := []struct {
		name        string
		descriptor  imageLoadOCIIndexDescriptor
		blobs       map[string]imageLoadOCIBlob
		requireBody bool
		wantErr     string
	}{
		{
			name:       "zero size matching an empty blob",
			descriptor: imageLoadOCIIndexDescriptor{Digest: emptyDigest, Size: 0},
			blobs:      map[string]imageLoadOCIBlob{path: {size: 0, digestMatch: true, body: []byte{}}},
		},
		{
			name:       "negative size is rejected",
			descriptor: imageLoadOCIIndexDescriptor{Digest: emptyDigest, Size: -1},
			blobs:      map[string]imageLoadOCIBlob{path: {size: -1, digestMatch: true, body: []byte{}}},
			wantErr:    "has size",
		},
		{
			name:       "zero size disagreeing with the stored blob",
			descriptor: imageLoadOCIIndexDescriptor{Digest: emptyDigest, Size: 0},
			blobs:      map[string]imageLoadOCIBlob{path: {size: 3, digestMatch: true, body: []byte("abc")}},
			wantErr:    "has size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := validatedImageLoadOCIBlob(tt.descriptor, tt.blobs, tt.requireBody)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validatedImageLoadOCIBlob(size=%d) error = %v, want no error", tt.descriptor.Size, err)
				}
				if len(body) != 0 {
					t.Fatalf("validatedImageLoadOCIBlob(size=%d) body = %q, want empty", tt.descriptor.Size, body)
				}
				return
			}
			if err == nil {
				t.Fatalf("validatedImageLoadOCIBlob(size=%d) returned no error, want one containing %q", tt.descriptor.Size, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validatedImageLoadOCIBlob(size=%d) error = %v, want it to contain %q", tt.descriptor.Size, err, tt.wantErr)
			}
		})
	}
}
