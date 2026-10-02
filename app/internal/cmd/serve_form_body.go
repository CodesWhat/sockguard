package cmd

import (
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/apipath"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/httpjson"
	"github.com/codeswhat/sockguard/app/internal/logging"
)

const (
	reasonCodeRequestFormBodyRefused = "request_form_body_refused"

	formEncodedBodyDenyMessage   = "form-encoded request bodies are not accepted: the daemon reads parameters from the body ahead of the URL query"
	multipartFormBodyDenyMessage = "multipart/form-data request bodies are not accepted on this endpoint: the daemon reads parameters from the body that the URL query leaves out"

	// The markers are matched as substrings of a lower-cased Content-Type
	// line. See formBodyRefusal for why that is wider than net/http's own
	// test on purpose.
	formEncodedMediaTypeMarker   = "x-www-form-urlencoded"
	multipartFormMediaTypeMarker = "multipart/form-data"
)

// withFormBodyGuard refuses a request whose body the daemon would read
// request parameters from.
//
// Every layer from the filter inward reads parameters from the URL query, and
// the ones that enforce by rewriting (the owner and visibility label filters,
// the owner label on a build) write them back to the URL query. Neither
// engine stops at the query:
//
//   - dockerd's handlers call httputils.ParseForm and read r.Form. net/http's
//     ParseForm parses an application/x-www-form-urlencoded body on POST, PUT
//     and PATCH and puts its fields in r.Form ahead of the query's, so
//     r.Form.Get returns the body's value whenever both name a key. A prune
//     with the owner filter injected into its query and "filters={}" in its
//     body prunes every owner's resources, and a pull whose query names an
//     allowed registry pulls the body's fromImage instead.
//   - dockerd's postBuild never calls ParseForm. Its first parameter read is
//     r.FormValue, which calls ParseMultipartForm, so on POST /build a
//     multipart/form-data body is parsed as well and its fields are appended
//     after the query's. That supplies every parameter the query leaves out
//     (remote, networkmode) and adds to the repeated ones (t, extrahosts).
//     Any handler that reaches r.FormValue before ParseForm behaves the same
//     way, and which ones do changes between daemon versions.
//   - Podman's API wrapper calls r.ParseForm on every request before the
//     handler runs. Most handlers then decode r.URL.Query(), but the tag and
//     untag handlers read r.Form, and the form body is consumed either way.
//   - dockerd's createPlugin ignores Content-Type and untars the raw body,
//     while the plugin inspector here reads a multipart body's parts. Those
//     are two readings of one body, so the framing is refused instead of
//     inspected.
//
// The first three were read from moby 29.5.2 and Podman 5.8.6, and the dockerd
// ones confirmed against a running dockerd 29.5.2.
//
// Refusing is the fix rather than merging the body into the view policy
// evaluates, because no client depends on one. The Docker Go SDK, which the
// CLI and Compose are built on, puts every parameter in the URL query and
// sends bodies as application/json, application/x-tar or text/plain, and
// Podman's bindings send JSON, tar, or multipart. Podman's own API takes
// multipart/form-data as an upload format on its native build, manifest
// modify and quadlet install endpoints, read with r.MultipartReader and never
// as parameters, so the /libpod/ namespace is left to the filter, which
// already gates the multipart build behind insecure_allow_body_blind_writes.
// dockerd serves nothing under /libpod/.
//
// The layer runs immediately before the filter. That puts it ahead of every
// rule, body inspector, visibility and ownership decision, behind the rate
// limiter (so a refused request still spends quota, like any other denial),
// and behind sockguard's own endpoints, which never reach the daemon: the
// documented `curl --data-binary @candidate.yaml .../admin/validate` labels
// its YAML as a form body and has to keep working.
//
// It is a hard rejection in every rollout mode, like withRequestTargetGuard.
// Warn and audit preview what a policy would block; this is a request the
// proxy cannot evaluate, because the parameters it would evaluate are not the
// ones the daemon will act on.
func withFormBodyGuard() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if reason := formBodyRefusal(r); reason != "" {
				logging.SetDeniedWithCode(w, r, reasonCodeRequestFormBodyRefused, reason, filter.NormalizePath)
				_ = httpjson.Write(w, http.StatusBadRequest, httpjson.ErrorResponse{Message: reason})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// formBodyRefusal returns the reason r is refused, or "" when its body cannot
// carry parameters to the daemon.
//
// The Content-Type test is deliberately wider than the one it guards against.
// net/http reads only the first Content-Type line and compares the media type
// mime.ParseMediaType returns: the text before the first ";", lower-cased with
// strings.ToLower and trimmed. That still yields the form type when a
// parameter is malformed ("...urlencoded; =bad", an error moby's ParseForm
// wrapper swallows), and for spellings strings.ToLower folds into ASCII, such
// as a U+0130 in place of the "i" in "application". Matching the marker as a
// substring of every line, lower-cased the same way, covers all of those and
// does not depend on this process and the daemon agreeing on which line
// counts or how a malformed one parses. FuzzFormBodyGuardCoversNetHTTP holds
// the guard to net/http's actual parser.
//
// A request with no body is let through whatever it declares.
// curl -d and wget --post-data with an empty string label an empty POST as a
// form, and with ContentLength == 0 there is nothing for the daemon to parse: net/http
// sets it to 0 only for a request with no body at all, and the proxy then
// forwards none. A chunked body has an unknown length (-1) and is treated as
// present.
//
// The method is not consulted. net/http restricts the urlencoded parse to
// POST, PUT and PATCH but parses multipart on any method, and no method has a
// legitimate form body to protect.
func formBodyRefusal(r *http.Request) string {
	contentTypes := r.Header["Content-Type"]
	if len(contentTypes) == 0 || r.ContentLength == 0 {
		return ""
	}

	multipartForm := false
	for _, contentType := range contentTypes {
		lowered := strings.ToLower(contentType)
		if strings.Contains(lowered, formEncodedMediaTypeMarker) {
			return formEncodedBodyDenyMessage
		}
		if strings.Contains(lowered, multipartFormMediaTypeMarker) {
			multipartForm = true
		}
	}
	if multipartForm && !apipath.IsLibpodPath(apipath.NormalizePath(r.URL.Path)) {
		return multipartFormBodyDenyMessage
	}
	return ""
}
