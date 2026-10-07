package filter

import (
	"errors"
	"fmt"
	"net/http"
	"unicode/utf8"
)

// Sockguard reads a request body with encoding/json, and its gates are only
// sound if the engine behind it binds the same JSON object keys to the same
// fields. That holds for dockerd (httputils.ReadJSON and runconfig's loadJSON
// are encoding/json) and for Podman up to 5.x. Podman 6.0 moved its body
// decoding to utils.ReadJSONFromBody, which is json-iterator's
// ConfigCompatibleWithStandardLibrary (pkg/api/handlers/utils/handler.go), and
// that decoder doesn't match keys the way encoding/json does:
//
//   - encoding/json matches a key to a field under Unicode simple case
//     folding (bytes.EqualFold), so U+017F, the long s, matches "s" and
//     U+212A, the Kelvin sign, matches "k".
//   - json-iterator lowers the key with strings.ToLower and looks the result
//     up (reflect_struct_decoder.go, generalStructDecoder.decodeOneField).
//     strings.ToLower uses the simple lower-case mapping, which sends U+0130,
//     the capital I with a dot above, to "i" and U+212A to "k", and leaves
//     U+017F alone.
//
// So a body that spells `privileged` with U+0130 for each "i" holds an
// unknown key to sockguard and `privileged` to Podman 6: the gate saw the
// field as absent and the engine set it. The opposite split, a key only
// encoding/json matches, makes sockguard the stricter reader and is
// harmless, but it is the same ambiguity.
//
// isDecoderDivergentKeyRune names every character that can cause either one,
// and a body carrying one in any object key is refused before anything
// decodes it. See TestDecoderDivergentKeyRunesCoverBothDecoders, which scans
// every rune against both matching rules.

// isDecoderDivergentKeyRune reports whether r is a non-ASCII character that
// one of Go's case mappings relates to an ASCII letter. Those are the only
// characters that can make a key match an ASCII field name under one case
// rule and not under another, whichever rule an engine's decoder is built on:
//
//	U+0130  capital I with dot above  lowers to "i", folds to nothing  json-iterator only
//	U+0131  dotless i                 uppers to "I", folds to nothing  neither decoder today
//	U+017F  long s                    uppers and folds to "s"          encoding/json only
//	U+212A  Kelvin sign               lowers and folds to "k"          both decoders
//
// U+0131 and U+212A change nothing between today's two decoders. They are
// refused with the others so the rule doesn't depend on which case primitive
// a decoder happens to use.
func isDecoderDivergentKeyRune(r rune) bool {
	switch r {
	case 0x0130, 0x0131, 0x017F, 0x212A:
		return true
	default:
		return false
	}
}

// decoderDivergentKeyRune returns the first character of key that
// isDecoderDivergentKeyRune names. Every such character is two or three bytes
// of UTF-8, so an ASCII key, which is every key a real client sends as a
// field name, is settled by the byte test alone.
func decoderDivergentKeyRune(key string) (rune, bool) {
	for i := 0; i < len(key); i++ {
		if key[i] < utf8.RuneSelf {
			continue
		}
		for _, r := range key[i:] {
			if isDecoderDivergentKeyRune(r) {
				return r, true
			}
		}
		return 0, false
	}
	return 0, false
}

// refusedKeyEchoLimit bounds how much of a refused key an error repeats. The
// key is client data of any length up to the body cap, and the error ends up
// in a denial response and the audit log.
const refusedKeyEchoLimit = 64

// echoRefusedKey returns key cut to refusedKeyEchoLimit bytes on a rune
// boundary, for quoting in an error.
func echoRefusedKey(key string) string {
	if len(key) <= refusedKeyEchoLimit {
		return key
	}
	cut := refusedKeyEchoLimit
	for cut > 0 && !utf8.RuneStart(key[cut]) {
		cut--
	}
	return key[:cut] + "..."
}

// errDecoderDivergentKey marks the error decoderDivergentKeyError builds, so
// a test can tell it from the duplicate-key verdict.
var errDecoderDivergentKey = errors.New("ambiguous JSON object key")

// decoderDivergentKeyError quotes the key with %+q, which keeps the reason
// ASCII: the character that looks like a plain letter in a terminal is
// spelled as the escape it is.
func decoderDivergentKeyError(key string, r rune) error {
	return fmt.Errorf("%w %+q: %U matches a field name in some JSON decoders and not in others", errDecoderDivergentKey, echoRefusedKey(key), r)
}

// rejectAmbiguousBodyKeys is the check every inspected request body goes
// through before an inspector decodes it. It refuses a body that
// RejectDuplicateCaseVariantJSONKeys refuses: one with a decoder-divergent
// character in an object key at any depth, or with a struct-level key that
// repeats.
//
// The repeat is refused here, and not only where a body is rewritten, for
// two reasons. Sockguard's struct decode merges the objects under a repeated
// key while the ownership layer's map decode keeps the last one, so with
// owner isolation on the engine was sent a body the gates never judged:
// {"HostConfig":{"Memory":N},"HostConfig":{}} passed require_memory_limit and
// arrived with no limit. And the decoders disagree on what a null does to a
// string that was already set: encoding/json leaves it, json-iterator clears
// it, so {"user":"1000","user":null} is user 1000 to sockguard and the
// image's default user to Podman 6. Neither split exists without the repeat.
//
// A body the scan can't parse is left for the inspector's own decode, which
// denies it under that inspector's name. The scan walks every body
// encoding/json accepts, so nothing that decodes gets past it that way.
func rejectAmbiguousBodyKeys(body []byte) error {
	err := RejectDuplicateCaseVariantJSONKeys(body)
	if err == nil ||
		errors.Is(err, errCaseVariantScanSyntax) ||
		errors.Is(err, errCaseVariantScanTruncated) ||
		errors.Is(err, errCaseVariantScanTooDeep) {
		return nil
	}
	return newRequestRejectionErrorWithCode(http.StatusBadRequest, reasonCodeRequestBodyAmbiguous, "request body denied: "+err.Error())
}
