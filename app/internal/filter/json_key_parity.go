package filter

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
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
// encoding/json matches, gets past a gate that requires a field instead of
// refusing one: `{"u\u017fer":"1000"}` satisfied require_non_root_user here
// with a `user` Podman 6 never bound, and the container ran as the image's
// default user.
//
// isDecoderDivergentKeyRune names every character that can cause either one,
// and a body carrying one in any object key is refused before anything
// decodes it. See TestDecoderDivergentKeyRunesCoverBothDecoders, which scans
// every rune against both matching rules.

// isDecoderDivergentKeyRune reports whether r is a non-ASCII character that
// lowercases or case-folds to an ASCII letter. Those are the two ways the
// engines' decoders match a key to a field name, json-iterator by lowering
// and encoding/json by folding, so they are the only characters that can
// make a key match an ASCII field name in one decoder and not in the other:
//
//	U+0130  capital I with dot above  lowers to "i", folds to nothing  json-iterator only
//	U+017F  long s                    folds to "s", lowers to itself   encoding/json only
//	U+212A  Kelvin sign               lowers and folds to "k"          both decoders
//
// U+212A changes nothing between the two decoders. It is refused with the
// others so the rule is "lowers or folds to an ASCII letter" and not a list
// of which decoder does which today.
//
// U+0131, the dotless i, is left out. It uppercases to "I" and neither
// lowers nor folds to an ASCII letter, so it binds to no field in either
// decoder, and it is an everyday Turkish letter a label key can well hold.
func isDecoderDivergentKeyRune(r rune) bool {
	switch r {
	case 0x0130, 0x017F, 0x212A:
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

// loweredSiblingKeys reports two of one object's keys that strings.ToLower
// sends to the same string, the first two in sorted order. json-iterator
// binds a key by lowering it, so a decoder built on it reads the pair as one
// field given twice and keeps whichever comes later in the body.
//
// The caller has already refused keys that case-fold together, so a pair
// found here differs only by U+0130 standing where its sibling has an "i",
// `privileged` beside `pr\u0130v\u0130leged`. Those are the only characters
// that lower together and don't fold together; see
// TestLoweredSiblingKeysDifferOnlyByTheDottedCapitalI. keys is sorted in
// place.
func loweredSiblingKeys(keys []string) (first, second string, found bool) {
	slices.Sort(keys)
	lowered := make(map[string]string, len(keys))
	for _, key := range keys {
		lower := strings.ToLower(key)
		if prev, repeated := lowered[lower]; repeated {
			return prev, key, true
		}
		lowered[lower] = key
	}
	return "", "", false
}

// loweredSiblingKeysError quotes the keys with %+q for the reason
// decoderDivergentKeyError does: the two look alike in a terminal.
func loweredSiblingKeysError(first, second string) error {
	return fmt.Errorf("JSON object keys %+q and %+q lowercase to the same name, which some JSON decoders read as one key given twice", echoRefusedKey(first), echoRefusedKey(second))
}

// ReasonCodeRequestBodyAmbiguous is the reason code a body is refused under
// for a key the engines' decoders could read two ways. Exported for the
// owner isolation layer, which finds such a key in the body it decodes and
// reports it the way the inspectors do.
const ReasonCodeRequestBodyAmbiguous = reasonCodeRequestBodyAmbiguous

// AmbiguousRequestBodyReason words that refusal for err, the error one of
// the key checks returned.
func AmbiguousRequestBodyReason(err error) string {
	return "request body denied: " + err.Error()
}

// ambiguousRequestBodyStaticReason is the same refusal from a layer whose
// reasons never repeat anything the client sent: the admission-mutation
// engine and the resource-limit guard. subject is what that layer calls the
// request.
func ambiguousRequestBodyStaticReason(subject string) string {
	return subject + " denied: request body holds a JSON object key the engines could read two ways"
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
	return newRequestRejectionErrorWithCode(http.StatusBadRequest, reasonCodeRequestBodyAmbiguous, AmbiguousRequestBodyReason(err))
}
