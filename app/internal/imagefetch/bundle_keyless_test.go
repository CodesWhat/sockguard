package imagefetch

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// selfSignedCertPEM generates an ECDSA P-256 self-signed certificate and
// returns its PEM encoding plus the raw DER bytes.
func selfSignedCertPEM(t *testing.T) (pemStr string, der []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	pemStr = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return pemStr, der
}

// validRekorAnnotation builds a minimal valid cosign rekor bundle JSON
// annotation string.
func validRekorAnnotation(t *testing.T) string {
	t.Helper()
	body := []byte(`{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{}}`)
	logKeyHex := "c0ffee" + hexRepeat(58)
	annotation := map[string]any{
		"SignedEntryTimestamp": base64.StdEncoding.EncodeToString([]byte("set-bytes")),
		"Payload": map[string]any{
			"body":           base64.StdEncoding.EncodeToString(body),
			"integratedTime": 1700000000,
			"logIndex":       42,
			"logID":          logKeyHex,
		},
	}
	raw, err := json.Marshal(annotation)
	if err != nil {
		t.Fatalf("marshal annotation: %v", err)
	}
	return string(raw)
}

// --- buildBundle keyless tests ---

func TestBuildBundle_KeylessWithRekorAnnotation_HasCertChain(t *testing.T) {
	certPEM, wantDER := selfSignedCertPEM(t)
	rekorJSON := validRekorAnnotation(t)

	payload := []byte("keyless payload")
	pb, err := buildBundle(payload, []byte("rawsig"), certPEM, rekorJSON)
	if err != nil {
		t.Fatalf("buildBundle: %v", err)
	}

	chain := pb.GetVerificationMaterial().GetX509CertificateChain()
	if chain == nil {
		t.Fatal("expected X509CertificateChain, got nil")
	}
	if len(chain.Certificates) == 0 {
		t.Fatal("X509CertificateChain has no certificates")
	}
	if !bytes.Equal(chain.Certificates[0].RawBytes, wantDER) {
		t.Fatal("certificate DER bytes do not match the input cert")
	}

	// A valid rekor annotation means there should be at least one tlog entry.
	if len(pb.GetVerificationMaterial().TlogEntries) == 0 {
		t.Fatal("expected tlog entries from a valid rekor annotation, got none")
	}
}

func TestBuildBundle_KeylessWithoutRekorAnnotation_NoCertChainButNoError(t *testing.T) {
	certPEM, wantDER := selfSignedCertPEM(t)

	payload := []byte("keyless no-rekor payload")
	pb, err := buildBundle(payload, []byte("rawsig"), certPEM, "")
	if err != nil {
		t.Fatalf("buildBundle: %v", err)
	}

	chain := pb.GetVerificationMaterial().GetX509CertificateChain()
	if chain == nil {
		t.Fatal("expected X509CertificateChain, got nil")
	}
	if len(chain.Certificates) == 0 {
		t.Fatal("X509CertificateChain has no certificates")
	}
	if !bytes.Equal(chain.Certificates[0].RawBytes, wantDER) {
		t.Fatal("certificate DER bytes do not match the input cert")
	}

	// No rekor annotation — tlog entries must be absent.
	if len(pb.GetVerificationMaterial().TlogEntries) != 0 {
		t.Fatalf("expected 0 tlog entries, got %d", len(pb.GetVerificationMaterial().TlogEntries))
	}
}

func TestBuildBundle_MalformedPEM_ReturnsError(t *testing.T) {
	_, err := buildBundle([]byte("payload"), []byte("sig"), "not-valid-pem", "")
	if err == nil {
		t.Fatal("expected error for malformed PEM, got nil")
	}
}

// --- pemCertToDER tests ---

func TestPemCertToDER_ValidCert_ReturnsDER(t *testing.T) {
	certPEM, wantDER := selfSignedCertPEM(t)
	got, err := pemCertToDER(certPEM)
	if err != nil {
		t.Fatalf("pemCertToDER: %v", err)
	}
	if !bytes.Equal(got, wantDER) {
		t.Fatal("returned DER bytes do not match the original certificate")
	}
}

func TestPemCertToDER_NonCertificateBlock_ReturnsError(t *testing.T) {
	// A PUBLIC KEY block is valid PEM but not a CERTIFICATE.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pubKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	_, err = pemCertToDER(pubKeyPEM)
	if err == nil {
		t.Fatal("expected error for non-CERTIFICATE PEM block, got nil")
	}
}

func TestPemCertToDER_EmptyPEM_ReturnsError(t *testing.T) {
	_, err := pemCertToDER("")
	if err == nil {
		t.Fatal("expected error for empty PEM, got nil")
	}
}

func TestPemCertToDER_GarbagePEM_ReturnsError(t *testing.T) {
	_, err := pemCertToDER("this is not pem at all !!!")
	if err == nil {
		t.Fatal("expected error for garbage PEM input, got nil")
	}
}

// --- tlogEntryFromAnnotation error-branch tests ---

func TestTlogEntryFromAnnotation_InvalidBase64Body_ReturnsError(t *testing.T) {
	// The SET field is valid base64, but the body field is not.
	annotation := map[string]any{
		"SignedEntryTimestamp": base64.StdEncoding.EncodeToString([]byte("set-bytes")),
		"Payload": map[string]any{
			"body":           "!!not-valid-base64!!",
			"integratedTime": 1700000000,
			"logIndex":       0,
			"logID":          "00" + hexRepeat(62),
		},
	}
	raw, err := json.Marshal(annotation)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_, err = tlogEntryFromAnnotation(string(raw))
	if err == nil {
		t.Fatal("expected error for invalid base64 body, got nil")
	}
}

func TestTlogEntryFromAnnotation_InvalidHexLogID_ReturnsError(t *testing.T) {
	body := []byte(`{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{}}`)
	annotation := map[string]any{
		"SignedEntryTimestamp": base64.StdEncoding.EncodeToString([]byte("set-bytes")),
		"Payload": map[string]any{
			"body":           base64.StdEncoding.EncodeToString(body),
			"integratedTime": 1700000000,
			"logIndex":       0,
			"logID":          "!!not-valid-hex!!",
		},
	}
	raw, err := json.Marshal(annotation)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_, err = tlogEntryFromAnnotation(string(raw))
	if err == nil {
		t.Fatal("expected error for invalid hex logID, got nil")
	}
}

func TestTlogEntryFromAnnotation_InvalidBase64SET_ReturnsError(t *testing.T) {
	// SignedEntryTimestamp in the JSON is a raw []byte; encoding/json decodes it
	// from base64. Providing something that is not valid base64 causes the JSON
	// unmarshal itself to fail, which is the error branch we're targeting.
	invalidJSON := `{"SignedEntryTimestamp":"!!notbase64!!","Payload":{"body":"","integratedTime":0,"logIndex":0,"logID":""}}`
	_, err := tlogEntryFromAnnotation(invalidJSON)
	if err == nil {
		t.Fatal("expected error for invalid base64 SignedEntryTimestamp, got nil")
	}
}

func TestTlogEntryFromAnnotation_NonJSONBodyAfterDecode_ReturnsError(t *testing.T) {
	// The body decodes from base64 successfully but is not valid JSON, so
	// the rekorEntryBody unmarshal fails.
	notJSON := base64.StdEncoding.EncodeToString([]byte("this is not json"))
	logKeyHex := "c0ffee" + hexRepeat(58)
	annotation := map[string]any{
		"SignedEntryTimestamp": base64.StdEncoding.EncodeToString([]byte("set-bytes")),
		"Payload": map[string]any{
			"body":           notJSON,
			"integratedTime": 0,
			"logIndex":       0,
			"logID":          logKeyHex,
		},
	}
	raw, err := json.Marshal(annotation)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_, err = tlogEntryFromAnnotation(string(raw))
	if err == nil {
		t.Fatal("expected error when decoded body is not JSON, got nil")
	}
}
