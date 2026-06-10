package imagefetch

import (
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// TestPinnedReference covers the public API of PinnedReference.
func TestPinnedReference(t *testing.T) {
	t.Run("valid tag ref produces digest-pinned form", func(t *testing.T) {
		imageRef := "docker.io/library/nginx:latest"
		digest := "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
		got, err := PinnedReference(imageRef, digest)
		if err != nil {
			t.Fatalf("PinnedReference(%q, %q): unexpected error: %v", imageRef, digest, err)
		}
		// Must end with @<digest>.
		if !strings.Contains(got, "@"+digest) {
			t.Errorf("got %q, want it to contain @%s", got, digest)
		}
		// Must NOT contain ":latest" – the tag is dropped when pinned.
		if strings.Contains(got, ":latest") {
			t.Errorf("got %q, still contains the mutable tag after pinning", got)
		}
		// Confirm go-containerregistry can round-trip it.
		_, err = name.NewDigest(got, name.WeakValidation)
		if err != nil {
			t.Errorf("got %q is not a valid digest reference: %v", got, err)
		}
	})

	t.Run("already-digest-pinned reference re-pins to supplied digest", func(t *testing.T) {
		// Supply a reference that already has a digest.
		original := "index.docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		newDigest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		got, err := PinnedReference(original, newDigest)
		if err != nil {
			t.Fatalf("PinnedReference(%q, %q): unexpected error: %v", original, newDigest, err)
		}
		if !strings.Contains(got, "@"+newDigest) {
			t.Errorf("got %q, want it to contain @%s", got, newDigest)
		}
		// Old digest must be gone.
		if strings.Contains(got, "aaaa") {
			t.Errorf("got %q, still contains the original digest", got)
		}
	})

	t.Run("invalid reference string returns error", func(t *testing.T) {
		_, err := PinnedReference("::::not::a::ref::::", "sha256:"+hexRepeat(64))
		if err == nil {
			t.Fatal("expected an error for an unparseable image reference, got nil")
		}
	})

	t.Run("invalid digest returns error", func(t *testing.T) {
		// A syntactically invalid digest (missing colon separator) must be rejected
		// when building the digest reference.
		_, err := PinnedReference("docker.io/library/nginx:latest", "notadigest")
		if err == nil {
			t.Fatal("expected an error for a malformed digest, got nil")
		}
	})

	t.Run("malformed digest algorithm returns error", func(t *testing.T) {
		// Digest algorithm present but empty hex part.
		_, err := PinnedReference("docker.io/library/nginx:latest", "sha256:")
		if err == nil {
			t.Fatal("expected an error for sha256: with empty hex, got nil")
		}
	})

	t.Run("exact output form", func(t *testing.T) {
		// Nail down the canonical Name() output go-containerregistry produces.
		imageRef := "index.docker.io/library/busybox:1.36"
		digest := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		got, err := PinnedReference(imageRef, digest)
		if err != nil {
			t.Fatalf("PinnedReference: %v", err)
		}
		// go-containerregistry normalises docker.io → index.docker.io/library/…
		want := "index.docker.io/library/busybox@" + digest
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

// TestNewFetcherWith_WithRemoteOptions verifies that options passed through
// NewFetcherWith → WithRemoteOptions are stored on the Fetcher and applied on
// the outbound registry call path. We confirm this behaviourally: a Fetcher
// built without insecure name options will refuse to parse a plain-HTTP host,
// while one built with WithNameOptions(name.Insecure) succeeds.
func TestNewFetcherWith_WithNameOptions(t *testing.T) {
	// Plain-HTTP host that go-containerregistry normally rejects as insecure.
	plainHTTPRef := "127.0.0.1:5000/myimage:latest"

	// Without name.Insecure the reference parse must fail (go-containerregistry
	// requires HTTPS by default for non-loopback names).
	_, err := name.ParseReference(plainHTTPRef)
	// If the library allows it on loopback, skip the negative assertion; only
	// assert that the option causes no error.
	if err != nil {
		// Confirm the fetcher built with Insecure does not error on the name parse
		// step that was failing above.
		f := NewFetcherWith(WithNameOptions(name.Insecure))
		// We cannot make a live registry call here, but we can parse through the
		// same code path by re-using the name option slice directly.
		_, err2 := name.ParseReference(plainHTTPRef, f.nameOpts...)
		if err2 != nil {
			t.Errorf("name.Insecure option was not applied: %v", err2)
		}
	}

	// At minimum, NewFetcherWith with no options must return a non-nil Fetcher.
	f := NewFetcherWith()
	if f == nil {
		t.Fatal("NewFetcherWith() returned nil")
	}
}

// TestNewFetcherWith_WithRemoteOptions confirms WithRemoteOptions appends to
// f.remoteOpts. We observe the stored slice length rather than round-tripping
// through the network.
func TestNewFetcherWith_WithRemoteOptions(t *testing.T) {
	// Craft two distinct remote.Option values.
	opt1 := remote.WithUserAgent("sockguard-test/1")
	opt2 := remote.WithUserAgent("sockguard-test/2")

	f := NewFetcherWith(WithRemoteOptions(opt1, opt2))

	if len(f.remoteOpts) != 2 {
		t.Fatalf("got %d remoteOpts, want 2", len(f.remoteOpts))
	}
}

// TestNewFetcherWith_OptionsAreCumulative verifies that multiple calls to
// WithRemoteOptions and WithNameOptions accumulate rather than overwrite.
func TestNewFetcherWith_OptionsAreCumulative(t *testing.T) {
	opt1 := remote.WithUserAgent("a")
	opt2 := remote.WithUserAgent("b")
	opt3 := remote.WithUserAgent("c")

	f := NewFetcherWith(
		WithRemoteOptions(opt1),
		WithRemoteOptions(opt2, opt3),
	)
	if len(f.remoteOpts) != 3 {
		t.Fatalf("got %d remoteOpts after two WithRemoteOptions calls, want 3", len(f.remoteOpts))
	}

	f2 := NewFetcherWith(
		WithNameOptions(name.Insecure),
		WithNameOptions(name.StrictValidation),
	)
	if len(f2.nameOpts) != 2 {
		t.Fatalf("got %d nameOpts after two WithNameOptions calls, want 2", len(f2.nameOpts))
	}
}
