package pkipin

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

// NormalizeSubjectPublicKeySHA256Pin normalizes a configured SHA-256 SPKI pin.
// Pins are accepted as raw hex digests or with a sha256: prefix.
func NormalizeSubjectPublicKeySHA256Pin(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("empty pin")
	}
	normalized := strings.ToLower(trimmed)
	normalized = strings.TrimPrefix(normalized, "sha256:")
	if len(normalized) != sha256.Size*2 {
		return "", fmt.Errorf("invalid pin length")
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", err
	}
	return normalized, nil
}

// SubjectPublicKeySHA256Hex returns the lowercase hex SHA-256 digest of a
// certificate's DER-encoded SubjectPublicKeyInfo.
func SubjectPublicKeySHA256Hex(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}
