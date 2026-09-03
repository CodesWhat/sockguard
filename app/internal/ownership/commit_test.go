package ownership

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/app/internal/logging"
)

// commit_test.go covers POST /commit and POST /libpod/commit, which no
// ownership check reached before: the endpoint names its container in the
// query rather than the path, so the path classifier walked past it and a
// client allowed to commit could turn another owner's container into a new,
// unlabeled image.

// commitSpellings is every registered path for the endpoint. Docker registers
// the versioned and unversioned compat spellings; Podman registers both of
// those onto compat.CommitContainer plus its own native one.
var commitSpellings = []struct {
	name         string
	path         string
	libpodPrefix bool
}{
	{name: "compat", path: "/commit"},
	{name: "compat version prefixed", path: "/v1.51/commit"},
	{name: "libpod", path: "/libpod/commit", libpodPrefix: true},
	{name: "libpod version prefixed", path: "/v5.8.1/libpod/commit", libpodPrefix: true},
}

func TestCommitIsOwnerCheckedAgainstItsContainerParameter(t *testing.T) {
	t.Parallel()
	states := []struct {
		name       string
		container  string
		wantStatus int
		wantReason string
	}{
		{name: "owned", container: "owned", wantStatus: http.StatusCreated},
		{
			name:       "foreign",
			container:  "foreign",
			wantStatus: http.StatusForbidden,
			wantReason: `owner policy denied access to container "foreign" referenced by commit container parameter`,
		},
		{
			name:       "missing",
			container:  "gone",
			wantStatus: http.StatusNotFound,
			wantReason: `owner policy could not resolve container "gone" referenced by commit container parameter`,
		},
	}

	for _, spelling := range commitSpellings {
		for _, state := range states {
			t.Run(spelling.name+"/"+state.name, func(t *testing.T) {
				t.Parallel()
				fi := fakeInspector{resources: map[string]map[string]inspectResult{
					"containers": {
						"owned":   {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
						"foreign": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
						"gone":    {found: false},
					},
				}}
				forwarded := false
				handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}, fi.inspectResource, fi.inspectExec)(
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						forwarded = true
						w.WriteHeader(http.StatusCreated)
					}))

				meta := &logging.RequestMeta{RolloutMode: "enforce"}
				req := httptest.NewRequest(http.MethodPost, spelling.path+"?container="+state.container+"&repo=team/app", nil)
				req = req.WithContext(logging.WithMeta(req.Context(), meta))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				if rec.Code != state.wantStatus {
					t.Fatalf("status = %d, want %d; body: %s", rec.Code, state.wantStatus, rec.Body.String())
				}
				if wantForwarded := state.wantStatus == http.StatusCreated; forwarded != wantForwarded {
					t.Fatalf("forwarded = %v, want %v", forwarded, wantForwarded)
				}
				if state.wantReason == "" {
					return
				}
				wantReason := state.wantReason
				if spelling.libpodPrefix {
					wantReason = "libpod " + wantReason
				}
				if meta.Reason != wantReason {
					t.Fatalf("reason = %q, want %q", meta.Reason, wantReason)
				}
				if meta.ReasonCode != reasonCodeOwnerPolicyDeniedAccess {
					t.Fatalf("reason code = %q, want %q", meta.ReasonCode, reasonCodeOwnerPolicyDeniedAccess)
				}
			})
		}
	}
}

// TestCommitStampsOwnerLabelIntoTheBody pins the second half of the fix. The
// owner check stops a client committing someone else's container; the stamp is
// what keeps the resulting image inside the owner's own view instead of
// landing unlabeled and outside every later check.
func TestCommitStampsOwnerLabelIntoTheBody(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		body            string
		contentType     string
		wantLabels      map[string]string
		wantOtherField  string
		wantContentType string
	}{
		{
			name:            "no body at all",
			wantLabels:      map[string]string{"com.sockguard.owner": "job-123"},
			wantContentType: "application/json",
		},
		{
			name:            "empty json object",
			body:            `{}`,
			contentType:     "application/json",
			wantLabels:      map[string]string{"com.sockguard.owner": "job-123"},
			wantContentType: "application/json",
		},
		{
			name:            "existing config is preserved",
			body:            `{"Cmd":["sh"],"Labels":{"team":"a"}}`,
			contentType:     "application/json",
			wantLabels:      map[string]string{"team": "a", "com.sockguard.owner": "job-123"},
			wantOtherField:  "sh",
			wantContentType: "application/json",
		},
		{
			// The client's own value for the owner key loses: moby merges the
			// source container's labels in only for keys the body did not
			// set, so a client value left in place would be the one the image
			// carries.
			name:            "client owner label is overwritten",
			body:            `{"Labels":{"com.sockguard.owner":"job-999"}}`,
			contentType:     "application/json",
			wantLabels:      map[string]string{"com.sockguard.owner": "job-123"},
			wantContentType: "application/json",
		},
	}

	for _, tt := range tests {
		for _, spelling := range commitSpellings {
			t.Run(tt.name+"/"+spelling.name, func(t *testing.T) {
				t.Parallel()
				fi := fakeInspector{resources: map[string]map[string]inspectResult{
					"containers": {"owned": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
				}}
				var got struct {
					Cmd    []string          `json:"Cmd"`
					Labels map[string]string `json:"Labels"`
				}
				var gotContentType string
				var gotContentLength int64
				var gotRawLength int
				handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}, fi.inspectResource, fi.inspectExec)(
					http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						gotContentType = r.Header.Get("Content-Type")
						gotContentLength = r.ContentLength
						raw, err := io.ReadAll(r.Body)
						if err != nil {
							t.Fatalf("read forwarded body: %v", err)
						}
						gotRawLength = len(raw)
						if err := json.Unmarshal(raw, &got); err != nil {
							t.Fatalf("decode forwarded body %q: %v", raw, err)
						}
						w.WriteHeader(http.StatusCreated)
					}))

				var body io.Reader
				if tt.body != "" {
					body = strings.NewReader(tt.body)
				}
				req := httptest.NewRequest(http.MethodPost, spelling.path+"?container=owned", body)
				if tt.contentType != "" {
					req.Header.Set("Content-Type", tt.contentType)
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				if rec.Code != http.StatusCreated {
					t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusCreated, rec.Body.String())
				}
				if len(got.Labels) != len(tt.wantLabels) {
					t.Fatalf("forwarded labels = %v, want %v", got.Labels, tt.wantLabels)
				}
				for key, value := range tt.wantLabels {
					if got.Labels[key] != value {
						t.Fatalf("forwarded labels = %v, want %v", got.Labels, tt.wantLabels)
					}
				}
				if tt.wantOtherField != "" && (len(got.Cmd) != 1 || got.Cmd[0] != tt.wantOtherField) {
					t.Fatalf("forwarded Cmd = %v, want the client's own config field preserved", got.Cmd)
				}
				if gotContentType != tt.wantContentType {
					t.Fatalf("forwarded Content-Type = %q, want %q; dockerd's CheckForJSON rejects a body without it", gotContentType, tt.wantContentType)
				}
				if gotContentLength != int64(gotRawLength) {
					t.Fatalf("forwarded Content-Length = %d, want %d (the rewritten body's own length)", gotContentLength, gotRawLength)
				}
			})
		}
	}
}

// TestCommitWithoutAnUnambiguousContainerIsDenied covers the shapes with no
// single container to authorize. The repeated and case-variant cases are the
// sharp ones: moby reads the first value of a repeated query parameter and
// Podman reads the last, so forwarding one would check a container the daemon
// does not commit.
func TestCommitWithoutAnUnambiguousContainerIsDenied(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		query      string
		wantReason string
	}{
		{name: "absent", query: "repo=team/app", wantReason: commitDenyNoContainer},
		{name: "empty", query: "container=", wantReason: commitDenyNoContainer},
		{name: "blank", query: "container=%20", wantReason: commitDenyNoContainer},
		{name: "repeated", query: "container=owned&container=foreign", wantReason: commitDenyAmbiguousContainer},
		{name: "case variant spellings", query: "container=owned&Container=foreign", wantReason: commitDenyAmbiguousContainer},
	}

	for _, tt := range tests {
		for _, spelling := range commitSpellings {
			t.Run(tt.name+"/"+spelling.name, func(t *testing.T) {
				t.Parallel()
				handler := middlewareWithDeps(
					testLogger(),
					Options{Owner: "job-123", LabelKey: "com.sockguard.owner"},
					func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
						t.Fatal("unclassifiable commit performed a resource inspect")
						return nil, false, nil
					},
					fakeInspector{}.inspectExec,
				)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Fatal("unclassifiable commit reached the upstream")
				}))

				meta := &logging.RequestMeta{RolloutMode: "enforce"}
				req := httptest.NewRequest(http.MethodPost, spelling.path+"?"+tt.query, nil)
				req = req.WithContext(logging.WithMeta(req.Context(), meta))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				if rec.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
				}
				wantReason := tt.wantReason
				if spelling.libpodPrefix {
					wantReason = "libpod " + wantReason
				}
				if meta.Reason != wantReason {
					t.Fatalf("reason = %q, want %q", meta.Reason, wantReason)
				}
			})
		}
	}
}

// TestCommitWithALabelChangeIsDenied pins the guard that keeps the stamp
// meaningful. Both engines apply `changes` on top of the body config, so a
// LABEL instruction there would overwrite the owner label with anything the
// client likes, including another tenant's value.
func TestCommitWithALabelChangeIsDenied(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		query     string
		wantDenID bool
	}{
		{name: "dockerfile form", query: "container=owned&changes=LABEL+com.sockguard.owner%3Djob-999", wantDenID: true},
		{name: "podman equals form", query: "container=owned&changes=LABEL%3Dcom.sockguard.owner%3Djob-999", wantDenID: true},
		{name: "lowercase instruction", query: "container=owned&changes=label+com.sockguard.owner%3Djob-999", wantDenID: true},
		{name: "case variant query key", query: "container=owned&Changes=LABEL+a%3Db", wantDenID: true},
		{name: "second line of a multiline value", query: "container=owned&changes=CMD+%5B%22sh%22%5D%0ALABEL+a%3Db", wantDenID: true},
		{name: "second changes value", query: "container=owned&changes=USER+app&changes=LABEL+a%3Db", wantDenID: true},
		{name: "leading whitespace", query: "container=owned&changes=++LABEL+a%3Db", wantDenID: true},
		// Controls: a change that cannot touch labels is still allowed, and a
		// value that merely contains the word is not an instruction.
		{name: "cmd change is allowed", query: "container=owned&changes=CMD+%5B%22sh%22%5D"},
		{name: "label inside a value is allowed", query: "container=owned&changes=ENV+LABEL%3Dx"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fi := fakeInspector{resources: map[string]map[string]inspectResult{
				"containers": {"owned": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
			}}
			forwarded := false
			handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}, fi.inspectResource, fi.inspectExec)(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					forwarded = true
					w.WriteHeader(http.StatusCreated)
				}))

			meta := &logging.RequestMeta{RolloutMode: "enforce"}
			req := httptest.NewRequest(http.MethodPost, "/commit?"+tt.query, nil)
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if tt.wantDenID {
				if rec.Code != http.StatusForbidden || forwarded {
					t.Fatalf("status = %d forwarded = %v, want %d and false; body: %s", rec.Code, forwarded, http.StatusForbidden, rec.Body.String())
				}
				if meta.Reason != commitDenyLabelChange {
					t.Fatalf("reason = %q, want %q", meta.Reason, commitDenyLabelChange)
				}
				return
			}
			if rec.Code != http.StatusCreated || !forwarded {
				t.Fatalf("status = %d forwarded = %v, want %d and true; body: %s", rec.Code, forwarded, http.StatusCreated, rec.Body.String())
			}
		})
	}
}

// TestCommitRolloutModesForwardTheDenial keeps commit on the same rollout
// contract as every other request-side owner verdict: warn and audit log the
// would-be denial and forward, so an operator can measure the change before
// enforcing it.
func TestCommitRolloutModesForwardTheDenial(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"warn", "audit"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			fi := fakeInspector{resources: map[string]map[string]inspectResult{
				"containers": {"foreign": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true}},
			}}
			forwarded := false
			handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}, fi.inspectResource, fi.inspectExec)(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					forwarded = true
					w.WriteHeader(http.StatusCreated)
				}))

			meta := &logging.RequestMeta{RolloutMode: mode}
			req := httptest.NewRequest(http.MethodPost, "/commit?container=foreign", nil)
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if !forwarded || rec.Code != http.StatusCreated {
				t.Fatalf("forwarded = %v status = %d, want true and %d", forwarded, rec.Code, http.StatusCreated)
			}
			if meta.Decision != logging.DecisionWouldDeny || meta.ReasonCode != reasonCodeOwnerPolicyDeniedAccess {
				t.Fatalf("meta = decision %q code %q, want %q and %q", meta.Decision, meta.ReasonCode, logging.DecisionWouldDeny, reasonCodeOwnerPolicyDeniedAccess)
			}
		})
	}
}

// TestCommitIsInertWithoutOwner proves the whole classification costs a
// deployment with no owner nothing: no inspect, no body rewrite, no header.
func TestCommitIsInertWithoutOwner(t *testing.T) {
	t.Parallel()
	for _, spelling := range commitSpellings {
		t.Run(spelling.name, func(t *testing.T) {
			t.Parallel()
			var gotBody string
			var gotContentType string
			handler := middlewareWithDeps(
				testLogger(),
				Options{},
				func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
					t.Fatal("ownership-disabled commit performed a resource inspect")
					return nil, false, nil
				},
				fakeInspector{}.inspectExec,
			)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatalf("read forwarded body: %v", err)
				}
				gotBody = string(raw)
				gotContentType = r.Header.Get("Content-Type")
				w.WriteHeader(http.StatusCreated)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, spelling.path+"?container=whatever", nil))

			if rec.Code != http.StatusCreated || gotBody != "" || gotContentType != "" {
				t.Fatalf("status = %d body = %q content type = %q, want %d and an untouched request", rec.Code, gotBody, gotContentType, http.StatusCreated)
			}
		})
	}
}

func TestIsCommitPath(t *testing.T) {
	t.Parallel()
	for path, want := range map[string]bool{
		"/commit":                true,
		"/libpod/commit":         true,
		"/commits":               false,
		"/commit/extra":          false,
		"/libpod/commit/extra":   false,
		"/containers/commit":     false,
		"/libpod/images/commit":  false,
		"/libpod/commit/../json": false,
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			if got := isCommitPath(path); got != want {
				t.Fatalf("isCommitPath(%q) = %v, want %v", path, got, want)
			}
		})
	}
}
