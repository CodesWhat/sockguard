package pkipin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestNormalizeSubjectPublicKeySHA256PinAcceptsSupportedForms(t *testing.T) {
	sum := sha256.Sum256([]byte("client public key"))
	lowerHex := hex.EncodeToString(sum[:])
	upperHex := strings.ToUpper(lowerHex)

	tests := []struct {
		name string
		raw  string
	}{
		{name: "raw lowercase hex", raw: lowerHex},
		{name: "raw uppercase hex", raw: upperHex},
		{name: "sha256 prefix", raw: "sha256:" + lowerHex},
		{name: "uppercase sha256 prefix", raw: "SHA256:" + upperHex},
		{name: "surrounding whitespace", raw: "\n\t sha256:" + upperHex + " \r\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeSubjectPublicKeySHA256Pin(tt.raw)
			if err != nil {
				t.Fatalf("NormalizeSubjectPublicKeySHA256Pin(%q) error = %v", tt.raw, err)
			}
			if got != lowerHex {
				t.Fatalf("NormalizeSubjectPublicKeySHA256Pin(%q) = %q, want %q", tt.raw, got, lowerHex)
			}
		})
	}
}

func TestNormalizeSubjectPublicKeySHA256PinRejectsInvalidPins(t *testing.T) {
	valid := strings.Repeat("a", sha256.Size*2)

	tests := []struct {
		name string
		raw  string
	}{
		{name: "empty", raw: ""},
		{name: "whitespace only", raw: " \n\t "},
		{name: "prefix without digest", raw: "sha256:"},
		{name: "too short", raw: valid[:len(valid)-1]},
		{name: "too long", raw: valid + "0"},
		{name: "invalid hex", raw: strings.Repeat("g", sha256.Size*2)},
		{name: "unsupported algorithm prefix", raw: "sha512:" + valid},
		{name: "embedded whitespace", raw: valid[:10] + " " + valid[11:]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := NormalizeSubjectPublicKeySHA256Pin(tt.raw); err == nil {
				t.Fatalf("NormalizeSubjectPublicKeySHA256Pin(%q) = %q, want error", tt.raw, got)
			}
		})
	}
}

func TestSubjectPublicKeySHA256HexReturnsSPKIDigest(t *testing.T) {
	cert := makeTestCertificate(t)
	wantSum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	want := hex.EncodeToString(wantSum[:])

	got := SubjectPublicKeySHA256Hex(cert)
	if got != want {
		t.Fatalf("SubjectPublicKeySHA256Hex() = %q, want %q", got, want)
	}
	if got != strings.ToLower(got) {
		t.Fatalf("SubjectPublicKeySHA256Hex() = %q, want lowercase hex", got)
	}
}

func TestSubjectPublicKeySHA256HexMatchesNormalizedConfiguredPin(t *testing.T) {
	cert := &x509.Certificate{RawSubjectPublicKeyInfo: []byte("allowed-client-key")}
	pin := "SHA256:" + strings.ToUpper(SubjectPublicKeySHA256Hex(cert))

	normalized, err := NormalizeSubjectPublicKeySHA256Pin(pin)
	if err != nil {
		t.Fatalf("NormalizeSubjectPublicKeySHA256Pin(%q) error = %v", pin, err)
	}

	if normalized != SubjectPublicKeySHA256Hex(cert) {
		t.Fatalf("normalized pin = %q, want certificate pin %q", normalized, SubjectPublicKeySHA256Hex(cert))
	}
}

func TestSubjectPublicKeySHA256HexHandlesNilAndMissingSPKI(t *testing.T) {
	if got := SubjectPublicKeySHA256Hex(nil); got != "" {
		t.Fatalf("SubjectPublicKeySHA256Hex(nil) = %q, want empty string", got)
	}

	wantSum := sha256.Sum256(nil)
	want := hex.EncodeToString(wantSum[:])
	if got := SubjectPublicKeySHA256Hex(&x509.Certificate{}); got != want {
		t.Fatalf("SubjectPublicKeySHA256Hex(empty SPKI) = %q, want %q", got, want)
	}
}

func makeTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pkipin-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	if len(cert.RawSubjectPublicKeyInfo) == 0 {
		t.Fatal("RawSubjectPublicKeyInfo is empty")
	}
	return cert
}
