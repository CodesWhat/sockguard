package imagefetch

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

func fuzzSeedCertPEM(f *testing.F) string {
	f.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fuzz"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		f.Fatalf("CreateCertificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func fuzzSeedRekorAnnotation() string {
	body := `{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{}}`
	return `{"SignedEntryTimestamp":"` + base64.StdEncoding.EncodeToString([]byte("set")) +
		`","Payload":{"body":"` + base64.StdEncoding.EncodeToString([]byte(body)) +
		`","integratedTime":1700000000,"logIndex":42,"logID":"c0ffee"}}`
}

// FuzzTlogEntryFromAnnotation feeds the registry-supplied Rekor bundle
// annotation through its four-stage decode chain (JSON, base64 body, hex logID,
// entry-body JSON). A registry controls this string, so beyond not panicking a
// success must carry exactly the fields the chain decoded, and a failure must
// never leave a half-built entry behind.
func FuzzTlogEntryFromAnnotation(f *testing.F) {
	f.Add(fuzzSeedRekorAnnotation())
	f.Add(``)
	f.Add(`{}`)
	f.Add(`{"SignedEntryTimestamp":"AA==","Payload":{"body":"e30=","logID":"zz"}}`)
	f.Add(`{"SignedEntryTimestamp":"AA==","Payload":{"body":"!!!","logID":"00"}}`)
	f.Add(`{"SignedEntryTimestamp":"AA==","Payload":{"body":"e30=","logID":"0"}}`)
	f.Add(`{"SignedEntryTimestamp":"AA==","Payload":{"body":"WzFd","logID":"00"}}`)
	f.Add(`  null  `)

	f.Fuzz(func(t *testing.T, annotation string) {
		if len(annotation) > 1<<20 {
			t.Skip()
		}
		entry, err := tlogEntryFromAnnotation(annotation)
		if err != nil {
			if entry != nil {
				t.Fatalf("entry returned alongside error %v", err)
			}
			return
		}
		if entry == nil || entry.InclusionPromise == nil || len(entry.InclusionPromise.SignedEntryTimestamp) == 0 {
			t.Fatalf("success without an inclusion promise: %+v", entry)
		}
		if len(entry.CanonicalizedBody) == 0 || entry.KindVersion == nil || entry.LogId == nil {
			t.Fatalf("success with missing body, kind/version or log id: %+v", entry)
		}

		var rb cosignRekorBundle
		if err := json.Unmarshal([]byte(strings.TrimSpace(annotation)), &rb); err != nil {
			t.Fatalf("accepted an annotation encoding/json rejects: %v", err)
		}
		body, err := base64.StdEncoding.DecodeString(rb.Payload.Body)
		if err != nil || !bytes.Equal(body, entry.CanonicalizedBody) {
			t.Fatalf("canonicalized body does not match the annotation body")
		}
		if want, err := hex.DecodeString(rb.Payload.LogID); err != nil || !bytes.Equal(want, entry.LogId.KeyId) {
			t.Fatalf("log id does not match the annotation")
		}
		if entry.LogIndex != rb.Payload.LogIndex || entry.IntegratedTime != rb.Payload.IntegratedTime {
			t.Fatalf("index/time drifted from the annotation")
		}
		var eb rekorEntryBody
		if err := json.Unmarshal(body, &eb); err != nil ||
			entry.KindVersion.Kind != eb.Kind || entry.KindVersion.Version != eb.APIVersion {
			t.Fatalf("kind/version do not match the entry body")
		}
	})
}

// FuzzPemCertToDER feeds registry-supplied PEM from signature-image
// annotations to the certificate extractor. Only a CERTIFICATE block may come
// back, and its bytes must be exactly the block's.
func FuzzPemCertToDER(f *testing.F) {
	certPEM := fuzzSeedCertPEM(f)
	f.Add(certPEM)
	f.Add("")
	f.Add("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
	f.Add("garbage before\n" + certPEM)
	f.Add("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n")
	f.Add(certPEM + certPEM)

	f.Fuzz(func(t *testing.T, in string) {
		if len(in) > 1<<20 {
			t.Skip()
		}
		der, err := pemCertToDER(in)
		if err != nil {
			if der != nil {
				t.Fatalf("bytes returned alongside error %v", err)
			}
			return
		}
		block, _ := pem.Decode([]byte(in))
		if block == nil || block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, der) {
			t.Fatalf("accepted input whose first PEM block is not that CERTIFICATE")
		}
		round, _ := pem.Decode(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		if round == nil || !bytes.Equal(round.Bytes, der) {
			t.Fatalf("DER does not survive a PEM round trip")
		}
	})
}

// FuzzBuildBundle assembles a sigstore bundle from a registry-supplied
// payload, signature, certificate and Rekor annotation. A bad Rekor
// annotation may only drop the tlog entry, never fail the bundle; a bad
// certificate must fail it; and every bundle returned must marshal and bind
// the digest of the payload it was built from.
func FuzzBuildBundle(f *testing.F) {
	certPEM := fuzzSeedCertPEM(f)
	f.Add([]byte(`{"critical":{}}`), []byte("sig"), "", "")
	f.Add([]byte(`{"critical":{}}`), []byte("sig"), certPEM, fuzzSeedRekorAnnotation())
	f.Add([]byte(`x`), []byte(nil), certPEM, "not json")
	f.Add([]byte(nil), []byte(nil), "  \n ", "ignored")
	f.Add([]byte(`x`), []byte("s"), "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----", "")

	f.Fuzz(func(t *testing.T, payload, sig []byte, certPEM, rekor string) {
		if len(payload)+len(sig)+len(certPEM)+len(rekor) > 1<<20 {
			t.Skip()
		}
		b, err := buildBundle(payload, sig, certPEM, rekor)
		trimmed := strings.TrimSpace(certPEM)
		if err != nil {
			if b != nil {
				t.Fatalf("bundle returned alongside error %v", err)
			}
			if trimmed == "" {
				t.Fatalf("keyed bundle must not fail, got %v", err)
			}
			if _, derr := pemCertToDER(trimmed); derr == nil {
				t.Fatalf("buildBundle failed on a certificate pemCertToDER accepts: %v", err)
			}
			return
		}
		if _, err := proto.Marshal(b); err != nil {
			t.Fatalf("bundle does not marshal: %v", err)
		}
		sum := sha256.Sum256(payload)
		ms := b.GetMessageSignature()
		if ms == nil || !bytes.Equal(ms.GetMessageDigest().GetDigest(), sum[:]) || !bytes.Equal(ms.GetSignature(), sig) {
			t.Fatalf("bundle does not bind the payload digest and signature")
		}
		vm := b.GetVerificationMaterial()
		if trimmed == "" {
			if vm.GetPublicKey() == nil || len(vm.GetTlogEntries()) != 0 || vm.GetX509CertificateChain() != nil {
				t.Fatalf("keyed bundle carries cert or tlog material")
			}
			return
		}
		chain := vm.GetX509CertificateChain()
		if chain == nil || len(chain.GetCertificates()) != 1 {
			t.Fatalf("keyless bundle without exactly one certificate")
		}
		wantTlog := 0
		if e, err := tlogEntryFromAnnotation(rekor); err == nil && e != nil {
			wantTlog = 1
		}
		if len(vm.GetTlogEntries()) != wantTlog {
			t.Fatalf("tlog entries = %d, want %d", len(vm.GetTlogEntries()), wantTlog)
		}
	})
}
