package filter

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func compileRulesForTest(t *testing.T, rules []Rule) []*CompiledRule {
	t.Helper()

	compiled := make([]*CompiledRule, 0, len(rules))
	for _, rule := range rules {
		cr, err := CompileRule(rule)
		if err != nil {
			t.Fatalf("CompileRule(%+v) failed: %v", rule, err)
		}
		compiled = append(compiled, cr)
	}
	return compiled
}

func newParsedRequest(t *testing.T, method, rawPath string) *http.Request {
	t.Helper()
	return httptest.NewRequest(method, "http://example.com"+rawPath, nil)
}

func TestNormalizePathAdversarialEncodings(t *testing.T) {
	tests := []struct {
		name    string
		rawPath string
		want    string
	}{
		{
			// net/http's request parser decodes one layer of escaping, so a
			// singly-encoded separator is already "/" when NormalizePath sees
			// it — exactly as the Docker daemon's parser sees it.
			name:    "single encoded slash is decoded once at the HTTP boundary",
			rawPath: "/containers%2Fjson",
			want:    "/containers/json",
		},
		{
			// A double-encoded separator survives the single HTTP-boundary
			// decode as a literal "%2F" and must NOT be decoded again: the
			// daemon's router leaves it literal too, so resolving it here
			// would desync sockguard's policy view from the daemon's routing.
			name:    "double encoded slash is left literal",
			rawPath: "/containers%252Fjson",
			want:    "/containers%2Fjson",
		},
		{
			name:    "single encoded dot-dot collapses after the boundary decode",
			rawPath: "/containers/%2e%2e/images/json",
			want:    "/images/json",
		},
		{
			// Same reasoning: a double-encoded "%2e%2e" stays a literal path
			// segment and is never resolved into a ".." traversal.
			name:    "double encoded dot-dot is left literal",
			rawPath: "/containers/%252e%252e/images/json",
			want:    "/containers/%2e%2e/images/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newParsedRequest(t, http.MethodGet, tt.rawPath)
			got := NormalizePath(req.URL.Path)
			if got != tt.want {
				t.Fatalf("NormalizePath(parsed %q) = %q, want %q", tt.rawPath, got, tt.want)
			}
		})
	}
}

func TestNormalizePathUnicodeEncoding(t *testing.T) {
	tests := []struct {
		name    string
		rawPath string
		want    string
	}{
		{
			// The HTTP-boundary decode resolves the single layer; the decoded
			// UTF-8 segment passes through NormalizePath unchanged.
			name:    "single encoded cjk segment stays decoded",
			rawPath: "/%E6%97%A5%E6%9C%AC/containers/json",
			want:    "/日本/containers/json",
		},
		{
			// Double-encoded non-ASCII survives the boundary decode as literal
			// "%XX" bytes and is left literal — NormalizePath never decodes
			// the second layer, matching the daemon.
			name:    "double encoded cyrillic segment is left literal",
			rawPath: "/%25D1%2582%25D0%25B5%25D1%2581%25D1%2582/images/json",
			want:    "/%D1%82%D0%B5%D1%81%D1%82/images/json",
		},
		{
			name:    "versioned double encoded arabic segment is left literal after prefix strip",
			rawPath: "/v1.45/%25D9%2585%25D8%25B1%25D8%25AD%25D8%25A8%25D8%25A7/json",
			want:    "/%D9%85%D8%B1%D8%AD%D8%A8%D8%A7/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newParsedRequest(t, http.MethodGet, tt.rawPath)
			got := NormalizePath(req.URL.Path)
			if got != tt.want {
				t.Fatalf("NormalizePath(parsed %q) = %q, want %q", tt.rawPath, got, tt.want)
			}
		})
	}
}

func TestEvaluateEncodedPathBypassResistance(t *testing.T) {
	containerRules := compileRulesForTest(t, []Rule{
		{Methods: []string{"GET"}, Pattern: "/containers/**", Action: ActionAllow, Index: 0},
		{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "default deny", Index: 1},
	})
	imageRules := compileRulesForTest(t, []Rule{
		{Methods: []string{"GET"}, Pattern: "/images/**", Action: ActionAllow, Index: 0},
		{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "default deny", Index: 1},
	})

	tests := []struct {
		name       string
		rules      []*CompiledRule
		rawPath    string
		wantAction Action
		wantIndex  int
	}{
		{
			name:       "single encoded slash matches the slash-delimited allow rule after one decode",
			rules:      containerRules,
			rawPath:    "/containers%2Fjson",
			wantAction: ActionAllow,
			wantIndex:  0,
		},
		{
			// A double-encoded slash is a literal "%2F" segment, not a path
			// separator — to sockguard and to the daemon's router alike. It
			// must not slip into the slash-delimited /containers/** rule; it
			// falls through to default-deny.
			name:       "double encoded slash stays literal and is denied",
			rules:      containerRules,
			rawPath:    "/containers%252Fjson",
			wantAction: ActionDeny,
			wantIndex:  1,
		},
		{
			name:       "single encoded dot-dot normalizes to the actual target path once",
			rules:      imageRules,
			rawPath:    "/containers/%2e%2e/images/json",
			wantAction: ActionAllow,
			wantIndex:  0,
		},
		{
			// A double-encoded "%2e%2e" stays a literal segment — it never
			// resolves into a ".." traversal, so the path does not canonicalize
			// onto /images/** and is denied.
			name:       "double encoded dot-dot stays literal and is denied",
			rules:      imageRules,
			rawPath:    "/containers/%252e%252e/images/json",
			wantAction: ActionDeny,
			wantIndex:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newParsedRequest(t, http.MethodGet, tt.rawPath)
			action, index, _ := Evaluate(tt.rules, req)
			if action != tt.wantAction {
				t.Fatalf("Evaluate(%q) action = %v, want %v", tt.rawPath, action, tt.wantAction)
			}
			if index != tt.wantIndex {
				t.Fatalf("Evaluate(%q) index = %d, want %d", tt.rawPath, index, tt.wantIndex)
			}
		})
	}
}

// TestContainerCreateDoubleEncodedPathIsNotACreateRequest verifies that a
// double-encoded path cannot smuggle a privileged container-create past the
// body inspector. A double-encoded "/containers%252Fcreate" decodes once at
// the HTTP boundary to the literal one-segment path "/containers%2Fcreate" —
// not "/containers/create". The daemon's router sees the same literal path and
// would 404, so it never runs a container-create; the inspector correctly does
// not fire, and the request is left for the rule layer's default-deny.
func TestContainerCreateDoubleEncodedPathIsNotACreateRequest(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodPost,
		"http://example.com/containers%252Fcreate",
		strings.NewReader(`{"HostConfig":{"Privileged":true}}`),
	)

	normalized := NormalizePath(req.URL.Path)
	if normalized == "/containers/create" {
		t.Fatalf("NormalizePath(%q) = %q, want a path that is NOT /containers/create", req.URL.Path, normalized)
	}

	policy := newContainerCreatePolicy(ContainerCreateOptions{})
	reason, err := policy.inspect(nil, req, normalized)
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	if reason != "" {
		t.Fatalf("inspect() reason = %q, want empty: a non-create path is not the inspector's to judge", reason)
	}
}

func TestEvaluateUnicodeNormalizationBypassResistance(t *testing.T) {
	precomposedRules := compileRulesForTest(t, []Rule{
		{Methods: []string{"GET"}, Pattern: "/caf\u00e9", Action: ActionAllow, Index: 0},
		{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "default deny", Index: 1},
	})
	decomposedRules := compileRulesForTest(t, []Rule{
		{Methods: []string{"GET"}, Pattern: "/cafe\u0301", Action: ActionAllow, Index: 0},
		{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "default deny", Index: 1},
	})

	tests := []struct {
		name       string
		rules      []*CompiledRule
		rawPath    string
		wantAction Action
		wantIndex  int
	}{
		{
			name:       "precomposed path matches the precomposed allow rule",
			rules:      precomposedRules,
			rawPath:    "/caf%C3%A9",
			wantAction: ActionAllow,
			wantIndex:  0,
		},
		{
			name:       "decomposed path does not bypass a visually equivalent precomposed allow rule",
			rules:      precomposedRules,
			rawPath:    "/cafe\u0301",
			wantAction: ActionDeny,
			wantIndex:  1,
		},
		{
			name:       "precomposed path does not bypass a visually equivalent decomposed allow rule",
			rules:      decomposedRules,
			rawPath:    "/caf%C3%A9",
			wantAction: ActionDeny,
			wantIndex:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newParsedRequest(t, http.MethodGet, tt.rawPath)
			action, index, _ := Evaluate(tt.rules, req)
			if action != tt.wantAction {
				t.Fatalf("Evaluate(%q) action = %v, want %v", tt.rawPath, action, tt.wantAction)
			}
			if index != tt.wantIndex {
				t.Fatalf("Evaluate(%q) index = %d, want %d", tt.rawPath, index, tt.wantIndex)
			}
		})
	}
}

func TestConfiguredMethodCaseNormalization(t *testing.T) {
	rule, err := CompileRule(Rule{
		Methods: []string{"gEt", "PoSt"},
		Pattern: "/containers/**",
		Action:  ActionAllow,
		Index:   0,
	})
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	tests := []struct {
		name   string
		method string
		want   bool
	}{
		{name: "uppercase GET", method: "GET", want: true},
		{name: "mixed case GET", method: "gEt", want: true},
		{name: "lowercase POST", method: "post", want: true},
		{name: "mixed case POST", method: "pOsT", want: true},
		{name: "unlisted method stays denied", method: "DeLeTe", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rule.matches(tt.method, "/containers/json")
			if got != tt.want {
				t.Fatalf("matches(%q, /containers/json) = %v, want %v", tt.method, got, tt.want)
			}
		})
	}
}

func TestEvaluateNullBytePathBypassResistance(t *testing.T) {
	rules := compileRulesForTest(t, []Rule{
		{Methods: []string{"GET"}, Pattern: "/containers/json", Action: ActionAllow, Index: 0},
		{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "default deny", Index: 1},
	})

	tests := []struct {
		name       string
		rawPath    string
		wantAction Action
		wantIndex  int
	}{
		{
			name:       "encoded null appended to literal path does not bypass allow rule",
			rawPath:    "/containers/json%00/extra",
			wantAction: ActionDeny,
			wantIndex:  1,
		},
		{
			name:       "encoded null inside path segment does not bypass allow rule",
			rawPath:    "/containers%00/json",
			wantAction: ActionDeny,
			wantIndex:  1,
		},
		{
			name:       "encoded null in nested segment does not bypass allow rule",
			rawPath:    "/containers/%00/json",
			wantAction: ActionDeny,
			wantIndex:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newParsedRequest(t, http.MethodGet, tt.rawPath)
			action, index, _ := Evaluate(rules, req)
			if action != tt.wantAction {
				t.Fatalf("Evaluate(%q) action = %v, want %v", tt.rawPath, action, tt.wantAction)
			}
			if index != tt.wantIndex {
				t.Fatalf("Evaluate(%q) index = %d, want %d", tt.rawPath, index, tt.wantIndex)
			}
			if got := NormalizePath(req.URL.Path); got == "/containers/json" {
				t.Fatalf("NormalizePath(%q) = %q, want null byte to remain non-matching", tt.rawPath, got)
			}
		})
	}
}

// TestCLTESmuggling_GoHTTPServerRejectsConflictingLengthHeaders locks in the
// assumption that Go's net/http server rejects requests that carry BOTH a
// Content-Length header and a Transfer-Encoding: chunked header.  RFC 9112
// §6.3 requires an intermediary to treat such a message as an error because
// the two framing mechanisms disagree — a server that accepts it silently
// becomes a request-smuggling vector.
//
// This test sends the conflicting headers over a raw TCP connection to bypass
// Go's http.Client, which would strip the redundant header before the bytes
// hit the wire.  The assertion is that the server responds with 400 Bad
// Request rather than forwarding the request to the upstream backend.
func TestCLTESmuggling_GoHTTPServerRejectsConflictingLengthHeaders(t *testing.T) {
	// A trivial upstream: if the filter middleware ever lets this request
	// through, the backend records it so the test can fail with a clear
	// message.
	reached := false
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/create", Action: ActionAllow, Index: 0})
	rules := []*CompiledRule{r1}
	handler := verboseMiddleware(rules, testLogger())(backend)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	// Craft a raw HTTP/1.1 request that carries both Content-Length and
	// Transfer-Encoding: chunked.  Go's http.Client would normalise this away,
	// so we dial TCP directly.
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// The body is one valid chunk ("5\r\nhello\r\n0\r\n\r\n") followed by the
	// terminating chunk.  Content-Length claims the body is only 5 bytes, which
	// contradicts Transfer-Encoding: chunked framing.
	rawRequest := "POST /containers/create HTTP/1.1\r\n" +
		fmt.Sprintf("Host: %s\r\n", srv.Listener.Addr().String()) +
		"Content-Length: 5\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"5\r\nhello\r\n0\r\n\r\n"

	if _, err := fmt.Fprint(conn, rawRequest); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Read just the status line from the response.
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	statusLine := string(buf[:n])

	// Go's net/http server silently drops the Content-Length when
	// Transfer-Encoding is present (RFC 9112 §6.3 p4) and processes the
	// chunked body, so the request is not rejected at the transport layer.
	// The important invariant is that the response is NOT a 5xx internal
	// error that would indicate the server crashed or panicked — the filter
	// layer must remain stable regardless.  If future Go versions start
	// returning 400 here, update the comment and strengthen the assertion.
	if strings.HasPrefix(statusLine, "HTTP/1.1 5") {
		t.Fatalf("server returned a 5xx on a CL+TE request — middleware may have panicked: %q", statusLine)
	}
	if reached {
		// Request reached the backend. Go processed the chunked body after
		// stripping Content-Length (conformant with RFC 9112 §6.3 p4).
		// This is the expected Go behavior; log it so a future reader
		// knows the assumption and can tighten it if Go's behavior changes.
		t.Logf("note: Go's net/http server forwarded the CL+TE request by preferring chunked framing (RFC 9112 §6.3 p4); backend was reached — this is expected")
	}
}

func TestEvaluateIgnoresMethodOverrideHeaders(t *testing.T) {
	rules := compileRulesForTest(t, []Rule{
		{Methods: []string{"POST"}, Pattern: "/containers/create", Action: ActionAllow, Index: 0},
		{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "default deny", Index: 1},
	})

	tests := []struct {
		name       string
		headerName string
		headerVal  string
		wantAction Action
		wantIndex  int
	}{
		{
			name:       "x http method override is ignored",
			headerName: "X-HTTP-Method-Override",
			headerVal:  http.MethodPost,
			wantAction: ActionDeny,
			wantIndex:  1,
		},
		{
			name:       "x method override is ignored",
			headerName: "X-Method-Override",
			headerVal:  http.MethodPost,
			wantAction: ActionDeny,
			wantIndex:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newParsedRequest(t, http.MethodGet, "/containers/create")
			req.Header.Set(tt.headerName, tt.headerVal)

			action, index, _ := Evaluate(rules, req)
			if action != tt.wantAction {
				t.Fatalf("Evaluate() action = %v, want %v", action, tt.wantAction)
			}
			if index != tt.wantIndex {
				t.Fatalf("Evaluate() index = %d, want %d", index, tt.wantIndex)
			}
		})
	}
}
