package policybundle

import (
	"encoding/pem"
	"testing"
)

// FuzzBuildConfig exercises the PEM-parsing and regex-compilation surface of
// BuildConfig. The goal is to ensure no input causes a panic — errors are
// expected and acceptable; panics are not.
//
// Seeds cover:
//   - valid keyed config (happy path)
//   - truncated PEM (parse failure)
//   - malformed regex pattern (regex.Compile failure)
//   - empty struct (disabled path)
//   - both keyed and keyless empty (no-trust-entries error)
func FuzzBuildConfig(f *testing.F) {
	// Seed: valid PEM block (synthesized — fuzz engine will mutate it).
	validPEMSeed := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte("fake-der-bytes"),
	}))

	// f.Add seeds: (pemOrKey string, subjectPattern string, issuer string, enabled bool)
	f.Add(validPEMSeed, "", "", true)          // keyed: valid-ish PEM, no keyless
	f.Add("-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n", "", "", true) // truncated PEM
	f.Add("", "(*invalid-regex", "https://accounts.google.com", true)                   // malformed regex
	f.Add("", "", "", false)                                                              // disabled (no panic expected)
	f.Add("", ".*", "https://accounts.google.com", true)                                 // keyless only, valid regex
	f.Add("", "", "", true)                                                               // enabled but empty (error, not panic)

	f.Fuzz(func(t *testing.T, pemKey string, subjectPattern string, issuer string, enabled bool) {
		// Build a RawConfig from the fuzz inputs. We populate both axes so that
		// the full parse path (PEM decode + regex compile) is exercised.
		raw := RawConfig{
			Enabled: enabled,
		}

		if pemKey != "" {
			raw.AllowedSigningKeys = []SigningKeyConfig{{PEM: pemKey}}
		}

		if issuer != "" || subjectPattern != "" {
			raw.AllowedKeyless = []KeylessConfig{{
				Issuer:         issuer,
				SubjectPattern: subjectPattern,
			}}
		}

		// Must not panic regardless of input.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("BuildConfig panicked with input pemKey=%q subjectPattern=%q issuer=%q enabled=%v: %v",
					pemKey, subjectPattern, issuer, enabled, r)
			}
		}()

		// Errors are expected and fine; panics are failures (caught above).
		_, _ = BuildConfig(raw)
	})
}
