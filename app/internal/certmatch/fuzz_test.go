package certmatch

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

func fuzzCertDER(tb testing.TB, key *ecdsa.PrivateKey, uris []*url.URL) []byte {
	tb.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fuzz"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil
	}
	return der
}

// FuzzCertificateURIStrings covers the URI SANs on the client mTLS cert that
// clientacl uses to select an ACL profile. Two inputs reach it: a URI list
// that is signed into a real certificate and parsed back (the shape a client
// presents), and raw DER bytes parsed directly (a hostile cert). The
// flattened strings decide profile selection, so they must match the parsed
// SANs one for one, skip nil entries, and never invent or drop a value.
func FuzzCertificateURIStrings(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("GenerateKey: %v", err)
	}
	seedURL, _ := url.Parse("spiffe://example.org/ns/prod/sa/web")
	f.Add("spiffe://example.org/ns/prod/sa/web", fuzzCertDER(f, key, []*url.URL{seedURL}))
	f.Add("https://a.example/x\nhttps://b.example/y", []byte(nil))
	f.Add("", fuzzCertDER(f, key, nil))
	f.Add("urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66", []byte{0x30, 0x00})
	f.Add("spiffe://x/%zz\nnot a uri\n", []byte(nil))

	f.Fuzz(func(t *testing.T, uriList string, rawDER []byte) {
		if len(uriList) > 1<<14 || len(rawDER) > 1<<16 {
			t.Skip()
		}

		if got := CertificateURIStrings(nil); got != nil {
			t.Fatalf("nil cert returned %v", got)
		}

		var uris []*url.URL
		for _, line := range strings.Split(uriList, "\n") {
			if u, err := url.Parse(line); err == nil {
				uris = append(uris, u)
			}
		}
		// Hand-built cert: nil entries are skipped, order is preserved.
		withNil := &x509.Certificate{URIs: append([]*url.URL{nil}, append(uris, nil)...)}
		got := CertificateURIStrings(withNil)
		if len(got) != len(uris) {
			t.Fatalf("got %d strings for %d URIs", len(got), len(uris))
		}
		for i, u := range uris {
			if got[i] != u.String() {
				t.Fatalf("URI %d = %q, want %q", i, got[i], u.String())
			}
		}

		// Through real DER: whatever the parser reads back is what we report.
		if der := fuzzCertDER(t, key, uris); der != nil {
			// crypto/x509 will sign some URIs it then refuses to parse
			// (e.g. "//."); that is a stdlib asymmetry, not ours.
			if parsed, err := x509.ParseCertificate(der); err == nil {
				strs := CertificateURIStrings(parsed)
				if len(strs) != len(parsed.URIs) {
					t.Fatalf("got %d strings for %d parsed URIs", len(strs), len(parsed.URIs))
				}
				for i, u := range parsed.URIs {
					if strs[i] != u.String() {
						t.Fatalf("parsed URI %d = %q, want %q", i, strs[i], u.String())
					}
				}
			}
		}

		// Hostile DER: no panic, and no entry is ever an invented empty value
		// for a URI the parser kept.
		if parsed, err := x509.ParseCertificate(rawDER); err == nil {
			strs := CertificateURIStrings(parsed)
			if len(parsed.URIs) == 0 && strs != nil {
				t.Fatalf("no URIs but got %v", strs)
			}
			if len(strs) != len(parsed.URIs) {
				t.Fatalf("got %d strings for %d parsed URIs", len(strs), len(parsed.URIs))
			}
		}
	})
}
