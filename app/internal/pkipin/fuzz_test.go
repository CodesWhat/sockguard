package pkipin

import (
	"crypto/sha256"
	"strings"
	"testing"
)

// FuzzNormalizeSubjectPublicKeySHA256Pin feeds the operator pin string, which
// is re-read on every config hot-reload, to the normalizer. The output is
// compared against certificate digests, so an accepted pin must be exactly 64
// lowercase hex characters, normalizing must be idempotent, and every spelling
// that normalizes must agree with its canonical form.
func FuzzNormalizeSubjectPublicKeySHA256Pin(f *testing.F) {
	sum := sha256.Sum256([]byte("seed"))
	hexSum := ""
	for _, b := range sum {
		hexSum += string("0123456789abcdef"[b>>4]) + string("0123456789abcdef"[b&15])
	}
	f.Add(hexSum)
	f.Add("sha256:" + hexSum)
	f.Add("  SHA256:" + strings.ToUpper(hexSum) + "\n")
	f.Add("")
	f.Add("sha256:")
	f.Add(hexSum[:63])
	f.Add(hexSum + "00")
	f.Add("sha256:sha256:" + hexSum)
	f.Add(strings.Repeat("g", 64))
	f.Add("0x" + hexSum[:62])

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 1<<16 {
			t.Skip()
		}
		got, err := NormalizeSubjectPublicKeySHA256Pin(raw)
		if err != nil {
			if got != "" {
				t.Fatalf("value %q returned alongside error %v", got, err)
			}
			return
		}
		if len(got) != sha256.Size*2 {
			t.Fatalf("accepted %q as %q (len %d)", raw, got, len(got))
		}
		for i := 0; i < len(got); i++ {
			c := got[i]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				t.Fatalf("accepted %q as %q, non-lowercase-hex byte %q", raw, got, c)
			}
		}
		again, err := NormalizeSubjectPublicKeySHA256Pin(got)
		if err != nil || again != got {
			t.Fatalf("not idempotent: %q -> %q -> (%q, %v)", raw, got, again, err)
		}
		prefixed, err := NormalizeSubjectPublicKeySHA256Pin("sha256:" + strings.ToUpper(got))
		if err != nil || prefixed != got {
			t.Fatalf("prefixed uppercase form of %q normalizes to (%q, %v)", got, prefixed, err)
		}
	})
}
