// Package queryparam reads the query parameters a policy decision depends on.
//
// The engines behind the proxy don't read a query parameter the same way.
// dockerd takes the first value under the exact key (net/http's
// Request.FormValue). Podman decodes most of its query structs with
// gorilla/schema v1.4.1, which matches a key to a field with strings.EqualFold
// and keeps the last value, and with two spellings of one key present the
// winner depends on map iteration order. A few Podman handlers read a
// parameter with url.Values.Get instead (the build's `dockerfile` and
// `remote`), so even one engine isn't consistent from one parameter to the
// next. Read from moby 28.5.1, Podman 5.8.6 and gorilla/schema v1.4.1.
//
// The one shape every one of those readers agrees on is a parameter sent once,
// spelled exactly as documented, so that is the only shape these functions
// return a value for. A parameter repeated under any spelling, or sent in any
// other letter case, is reported ambiguous, and the caller refuses the request
// instead of guessing which engine reads which value. Spellings are compared
// with strings.EqualFold because that is what gorilla/schema uses, so the
// Unicode simple folds count too: U+017F (ſ) matches s and the Kelvin sign
// U+212A matches k.
//
// The Docker CLI, the Go SDK, Compose, docker-py, dockerode and Podman's own
// bindings all send each scalar parameter once, under its documented
// spelling, so a refusal here only meets a request built by hand.
package queryparam

import (
	"net/url"
	"strings"
)

// Scalar returns the value of the single-valued parameter name.
//
// present reports whether name occurs under any spelling. ok is false when
// the request is ambiguous: name occurs more than once across every spelling,
// or its only occurrence is spelled other than exactly name. An absent
// parameter is ("", false, true).
func Scalar(query url.Values, name string) (value string, present, ok bool) {
	for key, values := range query {
		if !strings.EqualFold(key, name) {
			continue
		}
		if present || key != name || len(values) > 1 {
			return "", true, false
		}
		present = true
		if len(values) == 1 {
			value = values[0]
		}
	}
	return value, present, true
}

// Present reports whether name occurs under any spelling, with any value.
//
// It is for a parameter whose presence alone is what a policy refuses, such
// as a Podman build's host `volume`. Refusing every spelling there is already
// the strictest reading, so there is nothing ambiguous to report.
func Present(query url.Values, name string) bool {
	for key := range query {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

// List returns every value of the list parameter name, in the order the
// request carried them.
//
// Clients send a list by repeating the key (`t` on a build, `volume` on a
// Podman build, `changes` on a commit) and both engines read every value of
// it, so a repeat is not ambiguous here. Another spelling is: dockerd ignores
// it, and gorilla/schema replaces the whole list with whichever spelling it
// visits last. ok is false when any spelling of name other than name itself
// occurs. The returned slice belongs to query and must not be modified.
func List(query url.Values, name string) (values []string, ok bool) {
	for key, keyValues := range query {
		if !strings.EqualFold(key, name) {
			continue
		}
		if key != name {
			return nil, false
		}
		values = keyValues
	}
	return values, true
}
