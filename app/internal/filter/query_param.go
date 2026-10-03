package filter

import "fmt"

// ambiguousQueryReason is the denial for a policy-relevant query parameter
// that queryparam reports ambiguous: repeated under some spelling, or sent in
// a letter case other than the documented one. dockerd and Podman read such a
// parameter differently, so whichever value sockguard checked could be the one
// the daemon ignores. See package queryparam.
func ambiguousQueryReason(subject, name string) string {
	return fmt.Sprintf("%s denied: ambiguous %s query parameter (repeated, or not spelled %q)", subject, name, name)
}
