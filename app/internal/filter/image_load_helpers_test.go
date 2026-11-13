package filter

import "testing"

func TestInferImageLoadOCIMediaType(t *testing.T) {
	t.Parallel()
	const (
		ociManifest    = "application/vnd.oci.image.manifest.v1+json"
		ociIndex       = "application/vnd.oci.image.index.v1+json"
		dockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
		dockerIndex    = "application/vnd.docker.distribution.manifest.list.v2+json"
	)
	tests := []struct {
		name    string
		body    string
		want    string
		wantErr bool
	}{
		{"declared oci manifest", `{"mediaType":"` + ociManifest + `"}`, ociManifest, false},
		{"declared docker index", `{"mediaType":"` + dockerIndex + `"}`, dockerIndex, false},
		{"inferred index from manifests", `{"manifests":[]}`, ociIndex, false},
		{"inferred manifest from config and layers", `{"config":{},"layers":[]}`, ociManifest, false},
		{"config without layers", `{"config":{}}`, "", true},
		{"unknown shape", `{"mediaType":"text/plain"}`, "", true},
		{"not json", `{`, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := inferImageLoadOCIMediaType([]byte(tc.body), ociManifest, ociIndex, dockerManifest, dockerIndex)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("got (%q, %v), want (%q, err=%v)", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestImageLoadOCIBlobHasher(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		wantSize int
	}{
		{"blobs/sha256/abc", 32},
		{"blobs/sha384/abc", 48},
		{"blobs/sha512/abc", 64},
	} {
		rest, h, size, ok := imageLoadOCIBlobHasher(tc.name)
		if !ok || rest != "abc" || h == nil || size != tc.wantSize {
			t.Fatalf("imageLoadOCIBlobHasher(%q) = (%q, %v, %d, %v)", tc.name, rest, h, size, ok)
		}
	}
	if _, h, _, ok := imageLoadOCIBlobHasher("blobs/md5/abc"); ok || h != nil {
		t.Fatal("an unsupported algorithm must not resolve a hasher")
	}
}

func TestIsLowerHex(t *testing.T) {
	t.Parallel()
	for value, want := range map[string]bool{
		"": true, "0123456789abcdef": true, "ABC": false, "abcg": false, "12 34": false, "/": false, ":": false, "`": false, "g": false,
	} {
		if got := isLowerHex(value); got != want {
			t.Fatalf("isLowerHex(%q) = %v, want %v", value, got, want)
		}
	}
}
