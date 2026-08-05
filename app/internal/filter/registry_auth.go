package filter

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// maxRegistryAuthHeaderBytes bounds both the base64-encoded and decoded form
// of the X-Registry-Auth / X-Registry-Config headers Docker accepts on image
// pull/push and build requests. A genuine AuthConfig or per-registry
// AuthConfig map is at most a few KiB even with a long identity token; the
// cap exists to defuse an oversized header being used to make Sockguard
// allocate or spend CPU decoding attacker-controlled data before the request
// is otherwise denied or forwarded.
const maxRegistryAuthHeaderBytes = 8 << 10 // 8 KiB

// registryAuthHeader is the subset of Docker's AuthConfig object
// (X-Registry-Auth) the policy inspects.
type registryAuthHeader struct {
	ServerAddress string `json:"serveraddress"`
}

// decodeRegistryAuthHeaderBytes bounded-decodes a base64 header value,
// accepting both standard and URL-safe alphabets (the Docker CLI and SDKs
// have used both historically). Returns an error suitable for a
// "<subject> denied: ..." deny reason on any failure.
func decodeRegistryAuthHeaderBytes(headerValue, headerName, subject string) ([]byte, error) {
	trimmed := strings.TrimSpace(headerValue)
	if len(trimmed) > maxRegistryAuthHeaderBytes {
		return nil, fmt.Errorf("%s denied: %s header exceeds %d byte limit", subject, headerName, maxRegistryAuthHeaderBytes)
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(trimmed)
	}
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(trimmed)
	}
	if err != nil {
		decoded, err = base64.RawURLEncoding.DecodeString(trimmed)
	}
	if err != nil {
		return nil, fmt.Errorf("%s denied: %s header is not valid base64", subject, headerName)
	}
	if len(decoded) > maxRegistryAuthHeaderBytes {
		return nil, fmt.Errorf("%s denied: %s header exceeds %d byte limit", subject, headerName, maxRegistryAuthHeaderBytes)
	}
	return decoded, nil
}

// denyRegistryAuthHeaderReason bounded-decodes the base64 X-Registry-Auth
// header (a single Docker AuthConfig JSON object) that POST /images/create
// (pull) and POST /images/{name}/push accept. An empty header is a no-op
// (anonymous pull/push, unaffected). A present header that is oversized,
// non-base64, or non-JSON is denied fail-closed rather than forwarded
// unexamined. When a registry allowlist is configured (allowAll is false and
// allowed is non-empty), the decoded ServerAddress must canonicalize to an
// allowlisted host; an empty ServerAddress or no allowlist configured passes
// through unchanged, preserving prior behavior for operators who haven't
// opted into registry allowlisting. The decoded credential fields
// (username/password/identitytoken) are never inspected, logged, or
// reflected.
func denyRegistryAuthHeaderReason(headerValue string, allowAll bool, allowed []string, subject string) string {
	trimmed := strings.TrimSpace(headerValue)
	if trimmed == "" {
		return ""
	}
	decoded, err := decodeRegistryAuthHeaderBytes(trimmed, "X-Registry-Auth", subject)
	if err != nil {
		return err.Error()
	}
	var auth registryAuthHeader
	if err := json.Unmarshal(decoded, &auth); err != nil {
		return fmt.Sprintf("%s denied: X-Registry-Auth header is not valid JSON", subject)
	}
	if allowAll || len(allowed) == 0 {
		return ""
	}
	server := strings.TrimSpace(auth.ServerAddress)
	if server == "" {
		return ""
	}
	host, ok := normalizeRegistryHost(stripRegistryHeaderScheme(server))
	if !ok || !slices.Contains(allowed, host) {
		return fmt.Sprintf("%s denied: X-Registry-Auth serveraddress is not allowlisted", subject)
	}
	return ""
}

// denyRegistryConfigHeaderReason bounded-decodes the base64 X-Registry-Config
// header POST /build accepts: a JSON object mapping registry host to
// AuthConfig, used by multi-registry builds that pull FROM images from more
// than one private registry. Sockguard's build policy has no registry
// allowlist of its own (BuildOptions carries none), so this only rejects
// oversized or malformed values fail-closed; it does not cross-check hosts.
// Decoded credential material is never inspected, logged, or reflected.
func denyRegistryConfigHeaderReason(headerValue, subject string) string {
	trimmed := strings.TrimSpace(headerValue)
	if trimmed == "" {
		return ""
	}
	decoded, err := decodeRegistryAuthHeaderBytes(trimmed, "X-Registry-Config", subject)
	if err != nil {
		return err.Error()
	}
	var registryConfig map[string]json.RawMessage
	if err := json.Unmarshal(decoded, &registryConfig); err != nil {
		return fmt.Sprintf("%s denied: X-Registry-Config header is not valid JSON", subject)
	}
	return ""
}

// stripRegistryHeaderScheme normalizes a ServerAddress value
// ("https://myregistry.example.com/v2/", "myregistry.example.com:5000") down
// to a bare host[:port] by removing a leading scheme and any path segment.
func stripRegistryHeaderScheme(value string) string {
	v := strings.TrimSpace(value)
	if idx := strings.Index(v, "://"); idx >= 0 {
		v = v[idx+3:]
	}
	if idx := strings.Index(v, "/"); idx >= 0 {
		v = v[:idx]
	}
	return v
}
