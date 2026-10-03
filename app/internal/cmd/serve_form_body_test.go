package cmd

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/apipath"
	"github.com/codeswhat/sockguard/v2/app/internal/config"
)

// formBodyProbeField is the parameter the differential helpers plant in a
// request body to see whether net/http hands it to a handler.
const formBodyProbeField = "sockguardprobe"

func newFormBodyGuardRequest(method, target string, contentTypes []string, contentLength int64) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	if len(contentTypes) > 0 {
		req.Header["Content-Type"] = contentTypes
	}
	req.ContentLength = contentLength
	if contentLength != 0 {
		req.Body = io.NopCloser(strings.NewReader("filters=%7B%7D"))
	}
	return req
}

func TestFormBodyRefusal(t *testing.T) {
	const (
		formType      = "application/x-www-form-urlencoded"
		multipartType = "multipart/form-data; boundary=sockguard"
		// chunked is what net/http reports for a body sent with
		// Transfer-Encoding: chunked.
		chunked = int64(-1)
	)

	tests := []struct {
		name          string
		method        string
		target        string
		contentTypes  []string
		contentLength int64
		want          string
	}{
		// application/x-www-form-urlencoded: refused on every path.
		{name: "form body", method: http.MethodPost, target: "/containers/prune", contentTypes: []string{formType}, contentLength: 14, want: formEncodedBodyDenyMessage},
		{name: "form body one byte long", method: http.MethodPost, target: "/containers/prune", contentTypes: []string{formType}, contentLength: 1, want: formEncodedBodyDenyMessage},
		{name: "form body of unknown length", method: http.MethodPost, target: "/containers/prune", contentTypes: []string{formType}, contentLength: chunked, want: formEncodedBodyDenyMessage},
		{name: "form body under a version prefix", method: http.MethodPost, target: "/v1.54/images/create?fromImage=app", contentTypes: []string{formType}, contentLength: 14, want: formEncodedBodyDenyMessage},
		{name: "form body with a charset", method: http.MethodPost, target: "/build", contentTypes: []string{formType + "; charset=utf-8"}, contentLength: 14, want: formEncodedBodyDenyMessage},
		{name: "form body in upper case", method: http.MethodPost, target: "/build", contentTypes: []string{"APPLICATION/X-WWW-FORM-URLENCODED"}, contentLength: 14, want: formEncodedBodyDenyMessage},
		{name: "form body padded with whitespace", method: http.MethodPost, target: "/build", contentTypes: []string{" \t" + formType + " "}, contentLength: 14, want: formEncodedBodyDenyMessage},
		{name: "form body with a malformed parameter", method: http.MethodPost, target: "/build", contentTypes: []string{formType + "; =bad"}, contentLength: 14, want: formEncodedBodyDenyMessage},
		{name: "form body spelled with U+0130", method: http.MethodPost, target: "/build", contentTypes: []string{"applİcation/x-www-form-urlencoded"}, contentLength: 14, want: formEncodedBodyDenyMessage},
		{name: "form type on the first of two lines", method: http.MethodPost, target: "/build", contentTypes: []string{formType, "application/json"}, contentLength: 14, want: formEncodedBodyDenyMessage},
		{name: "form type on the second of two lines", method: http.MethodPost, target: "/build", contentTypes: []string{"application/json", formType}, contentLength: 14, want: formEncodedBodyDenyMessage},
		{name: "form type folded into one line", method: http.MethodPost, target: "/build", contentTypes: []string{"application/json, " + formType}, contentLength: 14, want: formEncodedBodyDenyMessage},
		{name: "form body on PUT", method: http.MethodPut, target: "/containers/abc/archive?path=/", contentTypes: []string{formType}, contentLength: 14, want: formEncodedBodyDenyMessage},
		{name: "form body on PATCH", method: http.MethodPatch, target: "/containers/abc", contentTypes: []string{formType}, contentLength: 14, want: formEncodedBodyDenyMessage},
		{name: "form body on DELETE", method: http.MethodDelete, target: "/containers/abc?force=1", contentTypes: []string{formType}, contentLength: 14, want: formEncodedBodyDenyMessage},
		{name: "form body on GET", method: http.MethodGet, target: "/containers/json", contentTypes: []string{formType}, contentLength: 14, want: formEncodedBodyDenyMessage},
		{name: "form body on Podman's native API", method: http.MethodPost, target: "/v5.8.0/libpod/images/app/tag?repo=mine", contentTypes: []string{formType}, contentLength: 14, want: formEncodedBodyDenyMessage},
		{name: "form body on a hijack endpoint", method: http.MethodPost, target: "/containers/abc/attach?stream=1", contentTypes: []string{formType}, contentLength: 14, want: formEncodedBodyDenyMessage},
		{name: "form body on a BuildKit tunnel endpoint", method: http.MethodPost, target: "/session", contentTypes: []string{formType}, contentLength: 14, want: formEncodedBodyDenyMessage},
		{name: "form type wins over a multipart line on libpod", method: http.MethodPost, target: "/libpod/build", contentTypes: []string{multipartType, formType}, contentLength: 14, want: formEncodedBodyDenyMessage},

		// multipart/form-data: refused everywhere except Podman's native API.
		{name: "multipart body on build", method: http.MethodPost, target: "/build", contentTypes: []string{multipartType}, contentLength: 14, want: multipartFormBodyDenyMessage},
		{name: "multipart body under a version prefix", method: http.MethodPost, target: "/v1.54/build", contentTypes: []string{multipartType}, contentLength: 14, want: multipartFormBodyDenyMessage},
		{name: "multipart body of unknown length", method: http.MethodPost, target: "/build", contentTypes: []string{multipartType}, contentLength: chunked, want: multipartFormBodyDenyMessage},
		{name: "multipart body in upper case", method: http.MethodPost, target: "/build", contentTypes: []string{"Multipart/Form-Data; boundary=sockguard"}, contentLength: 14, want: multipartFormBodyDenyMessage},
		{name: "multipart body with no boundary", method: http.MethodPost, target: "/plugins/create?name=p", contentTypes: []string{"multipart/form-data"}, contentLength: 14, want: multipartFormBodyDenyMessage},
		{name: "multipart type on the second of two lines", method: http.MethodPost, target: "/build", contentTypes: []string{"application/x-tar", multipartType}, contentLength: 14, want: multipartFormBodyDenyMessage},
		{name: "multipart body on GET", method: http.MethodGet, target: "/containers/abc/json", contentTypes: []string{multipartType}, contentLength: 14, want: multipartFormBodyDenyMessage},
		{name: "multipart body on build cancel", method: http.MethodPost, target: "/build/cancel", contentTypes: []string{multipartType}, contentLength: 14, want: multipartFormBodyDenyMessage},
		{name: "multipart body on a path that only cleans to build", method: http.MethodPost, target: "/libpod/../build", contentTypes: []string{multipartType}, contentLength: 14, want: multipartFormBodyDenyMessage},
		{name: "multipart body on bare libpod", method: http.MethodPost, target: "/libpod", contentTypes: []string{multipartType}, contentLength: 14, want: multipartFormBodyDenyMessage},
		{name: "multipart body on a path merely containing libpod", method: http.MethodPost, target: "/images/libpod/build", contentTypes: []string{multipartType}, contentLength: 14, want: multipartFormBodyDenyMessage},
		{name: "multipart body on Podman's native build", method: http.MethodPost, target: "/libpod/build", contentTypes: []string{multipartType}, contentLength: 14},
		{name: "multipart body on a versioned Podman build", method: http.MethodPost, target: "/v5.8.0/libpod/build", contentTypes: []string{multipartType}, contentLength: chunked},
		{name: "multipart body on Podman manifest modify", method: http.MethodPut, target: "/v5.8.0/libpod/manifests/list", contentTypes: []string{multipartType}, contentLength: 14},

		// Everything a real client sends.
		{name: "no Content-Type and no body", method: http.MethodPost, target: "/containers/prune"},
		{name: "no Content-Type with a body", method: http.MethodPost, target: "/containers/abc/archive?path=/", contentLength: 14},
		{name: "empty Content-Type with a body", method: http.MethodPost, target: "/containers/prune", contentTypes: []string{""}, contentLength: 14},
		{name: "JSON body", method: http.MethodPost, target: "/containers/create", contentTypes: []string{"application/json"}, contentLength: 14},
		{name: "JSON body with a charset", method: http.MethodPost, target: "/containers/create", contentTypes: []string{"application/json; charset=utf-8"}, contentLength: 14},
		{name: "tar body", method: http.MethodPost, target: "/build", contentTypes: []string{"application/x-tar"}, contentLength: chunked},
		{name: "legacy tar body", method: http.MethodPost, target: "/images/load", contentTypes: []string{"application/tar"}, contentLength: chunked},
		{name: "text/plain attach", method: http.MethodPost, target: "/containers/abc/attach?stream=1", contentTypes: []string{"text/plain"}},
		{name: "octet-stream body", method: http.MethodPost, target: "/images/load", contentTypes: []string{"application/octet-stream"}, contentLength: 14},
		{name: "multipart/mixed is not a form", method: http.MethodPost, target: "/build", contentTypes: []string{"multipart/mixed; boundary=sockguard"}, contentLength: 14},
		{name: "form type with a zero-length body", method: http.MethodPost, target: "/containers/abc/restart", contentTypes: []string{formType}},
		{name: "multipart type with a zero-length body", method: http.MethodPost, target: "/build", contentTypes: []string{multipartType}},
		{name: "form type on a bodyless GET", method: http.MethodGet, target: "/containers/json", contentTypes: []string{formType}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newFormBodyGuardRequest(tt.method, tt.target, tt.contentTypes, tt.contentLength)
			if got := formBodyRefusal(req); got != tt.want {
				t.Fatalf("formBodyRefusal() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormBodyGuardRefusesWithoutCallingNext(t *testing.T) {
	nextCalls := 0
	handler := withFormBodyGuard()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalls++
		w.WriteHeader(http.StatusNoContent)
	}))

	tests := []struct {
		name        string
		contentType string
		wantStatus  int
		wantMessage string
		wantNext    int
	}{
		{name: "form body", contentType: "application/x-www-form-urlencoded", wantStatus: http.StatusBadRequest, wantMessage: formEncodedBodyDenyMessage},
		{name: "multipart body", contentType: "multipart/form-data; boundary=sockguard", wantStatus: http.StatusBadRequest, wantMessage: multipartFormBodyDenyMessage},
		{name: "JSON body", contentType: "application/json", wantStatus: http.StatusNoContent, wantNext: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nextCalls = 0
			rec := httptest.NewRecorder()
			req := newFormBodyGuardRequest(http.MethodPost, "/build", []string{tt.contentType}, 14)

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if nextCalls != tt.wantNext {
				t.Fatalf("next handler calls = %d, want %d", nextCalls, tt.wantNext)
			}
			if tt.wantMessage == "" {
				return
			}
			var payload map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
				t.Fatalf("json.Unmarshal(%q): %v", rec.Body.String(), err)
			}
			if got := payload["message"]; got != tt.wantMessage {
				t.Fatalf("message = %q, want %q", got, tt.wantMessage)
			}
		})
	}
}

// netHTTPReadsParametersFromBody reports whether net/http hands a handler a
// parameter out of the body of a request labeled with contentTypes, by
// either route a daemon takes: ParseForm, which parses a form-encoded body, or
// FormValue on an unparsed request, which parses a multipart one as well.
//
// It asks net/http itself rather than restating its rules, so the guard is
// held to whatever the parser in this toolchain actually does.
func netHTTPReadsParametersFromBody(method string, contentTypes []string) bool {
	formEncoded, multipartForm := netHTTPBodyParseKinds(method, contentTypes)
	return formEncoded || multipartForm
}

// netHTTPBodyParseKinds splits netHTTPReadsParametersFromBody by which parser
// read the parameter, because the guard treats the two differently: a
// form-encoded body is refused on every path, a multipart one only outside
// /libpod/.
func netHTTPBodyParseKinds(method string, contentTypes []string) (formEncoded, multipartForm bool) {
	newRequest := func(body string) *http.Request {
		return &http.Request{
			Method:        method,
			URL:           &url.URL{Path: "/build"},
			Header:        http.Header{"Content-Type": contentTypes},
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
		}
	}

	urlencoded := newRequest(formBodyProbeField + "=1")
	_ = urlencoded.ParseForm()
	if urlencoded.Form.Has(formBodyProbeField) {
		formEncoded = true
	}

	if len(contentTypes) == 0 {
		return formEncoded, false
	}
	// A multipart body only parses against the boundary its own Content-Type
	// declares, so build the body around whatever net/http reads out of it.
	_, params, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || params["boundary"] == "" {
		return formEncoded, false
	}
	boundary := params["boundary"]
	multipartRequest := newRequest("--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"" + formBodyProbeField + "\"\r\n\r\n" +
		"1\r\n--" + boundary + "--\r\n")
	return formEncoded, multipartRequest.FormValue(formBodyProbeField) != ""
}

// formBodyGuardCoversNetHTTP checks the one property the guard exists for:
// whenever net/http would read a parameter out of the body, the guard refuses
// the request. It returns a description of the gap, or "".
func formBodyGuardCoversNetHTTP(contentTypes []string) string {
	return formBodyGuardCoversNetHTTPAt("/build", 14, contentTypes)
}

// formBodyGuardCoversNetHTTPAt is the same property for a request at path
// carrying contentLength. The guard leaves two things alone on purpose, and
// the property says so in the same terms:
//
//   - a request with ContentLength == 0 has no body for net/http to parse, so
//     it must not be refused. Any other length, including -1 for a chunked
//     body, is a body that is present.
//   - a multipart body under /libpod/ is an upload format there. A
//     form-encoded body is refused on every path.
func formBodyGuardCoversNetHTTPAt(path string, contentLength int64, contentTypes []string) string {
	libpod := apipath.IsLibpodPath(apipath.NormalizePath(path))
	label := path + " length " + strconv.FormatInt(contentLength, 10) + " Content-Type " + strings.Join(contentTypes, " | ")

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodGet, http.MethodDelete} {
		req := newFormBodyGuardRequest(method, "/build", contentTypes, contentLength)
		req.URL.Path = path
		refusal := formBodyRefusal(req)

		if contentLength == 0 {
			if refusal != "" {
				return method + " " + label + ": the guard refuses a request with no body"
			}
			continue
		}

		formEncoded, multipartForm := netHTTPBodyParseKinds(method, contentTypes)
		if (formEncoded || (multipartForm && !libpod)) && refusal == "" {
			return method + " " + label + ": net/http reads parameters from the body and the guard lets it through"
		}
	}
	return ""
}

var formBodyGuardDifferentialSeeds = [][2]string{
	{"application/x-www-form-urlencoded", ""},
	{"APPLICATION/X-WWW-FORM-URLENCODED; charset=utf-8", ""},
	{" application/x-www-form-urlencoded ;", ""},
	{"application/x-www-form-urlencoded; =bad", ""},
	{"application/x-www-form-urlencoded; a=1; a=2", ""},
	{"applİcation/x-www-form-urlencoded", ""},
	{"application/x-www-form-urlencoded", "application/json"},
	{"application/json", "application/x-www-form-urlencoded"},
	{"multipart/form-data; boundary=sockguard", ""},
	{"Multipart/Form-Data; BOUNDARY=\"sock guard\"", ""},
	{"multipart/form-data; boundary*=utf-8''sockguard", ""},
	{"multİpart/form-data; boundary=sockguard", ""},
	{"multipart/form-data; boundary=sockguard", "application/x-tar"},
	{"multipart/mixed; boundary=sockguard", ""},
	{"application/json", ""},
	{"application/x-tar", ""},
	{"text/plain", ""},
	{"", ""},
}

func formBodyGuardDifferentialLines(first, second string) []string {
	if second == "" {
		return []string{first}
	}
	return []string{first, second}
}

// TestFormBodyGuardCoversNetHTTP pins the guard against net/http's own parser
// for the Content-Type spellings known to matter, and checks that the helper
// really does see net/http parse the plain ones, so the property cannot pass
// by never firing.
func TestFormBodyGuardCoversNetHTTP(t *testing.T) {
	for _, seed := range formBodyGuardDifferentialSeeds {
		if gap := formBodyGuardCoversNetHTTP(formBodyGuardDifferentialLines(seed[0], seed[1])); gap != "" {
			t.Error(gap)
		}
	}

	parses := []struct {
		method       string
		contentTypes []string
		want         bool
	}{
		{method: http.MethodPost, contentTypes: []string{"application/x-www-form-urlencoded"}, want: true},
		{method: http.MethodPut, contentTypes: []string{"application/x-www-form-urlencoded"}, want: true},
		{method: http.MethodPatch, contentTypes: []string{"application/x-www-form-urlencoded; =bad"}, want: true},
		{method: http.MethodPost, contentTypes: []string{"applİcation/x-www-form-urlencoded"}, want: true},
		{method: http.MethodPost, contentTypes: []string{"application/x-www-form-urlencoded", "application/json"}, want: true},
		{method: http.MethodPost, contentTypes: []string{"multipart/form-data; boundary=sockguard"}, want: true},
		{method: http.MethodGet, contentTypes: []string{"multipart/form-data; boundary=sockguard"}, want: true},
		{method: http.MethodGet, contentTypes: []string{"application/x-www-form-urlencoded"}, want: false},
		{method: http.MethodPost, contentTypes: []string{"application/json", "application/x-www-form-urlencoded"}, want: false},
		{method: http.MethodPost, contentTypes: []string{"multipart/mixed; boundary=sockguard"}, want: false},
		{method: http.MethodPost, contentTypes: []string{"application/json"}, want: false},
		{method: http.MethodPost, contentTypes: nil, want: false},
	}
	for _, tt := range parses {
		if got := netHTTPReadsParametersFromBody(tt.method, tt.contentTypes); got != tt.want {
			t.Errorf("net/http reads body parameters for %s %q = %v, want %v", tt.method, tt.contentTypes, got, tt.want)
		}
	}
}

// formBodyGuardPathSeeds cover the axes the Content-Type seeds leave fixed:
// the path (a Docker route, a version prefix, the /libpod/ namespace and the
// spellings that normalize into or out of it) and the content length (none,
// present, chunked).
var formBodyGuardPathSeeds = []struct {
	path          string
	contentLength int64
}{
	{"/build", 14},
	{"/build", 1},
	{"/build", 0},
	{"/build", -1},
	{"/v1.54/images/create", 14},
	{"/libpod/build", 14},
	{"/libpod/build", 0},
	{"/libpod/build", -1},
	{"/v5.0.0/libpod/manifests/x/add", 14},
	{"/libpod/../build", 14},
	{"/libpod", 14},
	{"//libpod//build", 14},
	{"", 14},
}

// FuzzFormBodyGuardCoversNetHTTP searches for a request path, content length
// and Content-Type that net/http parses a body's parameters under and the
// guard does not refuse, or a body-less request the guard refuses anyway.
func FuzzFormBodyGuardCoversNetHTTP(f *testing.F) {
	for _, seed := range formBodyGuardDifferentialSeeds {
		f.Add(seed[0], seed[1], "/build", int64(14))
	}
	for _, seed := range formBodyGuardPathSeeds {
		f.Add("application/x-www-form-urlencoded", "", seed.path, seed.contentLength)
		f.Add("multipart/form-data; boundary=sockguard", "", seed.path, seed.contentLength)
	}
	f.Fuzz(func(t *testing.T, first, second, path string, contentLength int64) {
		contentTypes := formBodyGuardDifferentialLines(first, second)
		if gap := formBodyGuardCoversNetHTTPAt(path, contentLength, contentTypes); gap != "" {
			t.Fatal(gap)
		}
	})
}

// TestFormBodyGuardCoversNetHTTPPathAndLength runs the fuzz property over the
// path and length seeds for both body kinds on every ordinary run.
func TestFormBodyGuardCoversNetHTTPPathAndLength(t *testing.T) {
	for _, contentType := range []string{"application/x-www-form-urlencoded", "multipart/form-data; boundary=sockguard", "application/json"} {
		for _, seed := range formBodyGuardPathSeeds {
			if gap := formBodyGuardCoversNetHTTPAt(seed.path, seed.contentLength, []string{contentType}); gap != "" {
				t.Error(gap)
			}
		}
	}
}

// TestFormBodyGuardLeavesTheAdminEndpointAlone covers the documented CI gate,
// `curl --data-binary @candidate.yaml .../admin/validate`. curl labels that
// YAML application/x-www-form-urlencoded. The admin endpoint answers it
// itself and never forwards anything to the daemon, so the guard must sit
// behind it.
func TestFormBodyGuardLeavesTheAdminEndpointAlone(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "form-admin")
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Admin.Enabled = true

	handler := buildServeHandler(t, &cfg, newDiscardLogger(), nil, adminTestRules(t), newServeTestDeps())

	candidate := `
upstream:
  socket: /var/run/docker.sock
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
`
	req := httptest.NewRequest(http.MethodPost, cfg.Admin.Path, strings.NewReader(candidate))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var report struct {
		OK    bool `json:"ok"`
		Rules int  `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("json.Unmarshal(%q): %v", rec.Body.String(), err)
	}
	if !report.OK || report.Rules != 2 {
		t.Fatalf("validate report = %+v, want ok with 2 rules; body: %s", report, rec.Body.String())
	}
}
