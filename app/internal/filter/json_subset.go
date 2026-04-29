package filter

import "encoding/json"

// decodePolicySubsetJSON decodes only the subset of a Docker write payload
// that Sockguard currently enforces. These inspectors are intentionally not
// full-schema validators: many legitimate Docker request bodies carry fields
// that Sockguard does not inspect, so unknown fields remain Docker's job.
// Callers must therefore treat decode errors as "defer to Docker validation"
// rather than as a policy deny on their own.
func decodePolicySubsetJSON(body []byte, dst any) error {
	return json.Unmarshal(body, dst)
}
