package ownership

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
)

// imagePushSplitViewInspector is a repository where the caller owns exactly
// one tag and somebody else owns another. Every test below sends a push that
// names the owned tag to this layer and a different reference to the daemon.
func imagePushSplitViewInspector(owner string) *recordingInspector {
	return &recordingInspector{resources: map[string]map[string]inspectResult{
		string(dockerresource.KindImage): {
			"registry.example/team/app:owned":   {labels: map[string]string{"com.sockguard.owner": owner}, found: true},
			"registry.example/team/app:foreign": {labels: map[string]string{"com.sockguard.owner": "someone-else"}, found: true},
		},
	}}
}

func serveImagePushRequest(t *testing.T, inspector *recordingInspector, owner string, req *http.Request) (rec *httptest.ResponseRecorder, forwarded bool) {
	t.Helper()
	handler := middlewareWithDeps(
		testLogger(),
		Options{Owner: owner, LabelKey: "com.sockguard.owner"},
		inspector.inspectResource,
		inspector.inspectExec,
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded = true
		w.WriteHeader(http.StatusOK)
	}))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec, forwarded
}

// TestImagePushRefusesFormBodyTag covers the request body dockerd reads the
// tag from. Moby's postImagesPush calls r.ParseForm and then r.Form.Get("tag"),
// and net/http puts the fields of an application/x-www-form-urlencoded POST
// body in front of the query string's, so the body's tag is the one pushed
// while the query's is the one this layer authorized. Confirmed against
// dockerd 29.5.2: ?tag=a with a body of tag=b answers "tag does not exist:
// ...:b", and a body of "tag=" pushes every tag of the repository.
func TestImagePushRefusesFormBodyTag(t *testing.T) {
	const owner = "job-123"
	const target = "/v1.45/images/registry.example/team/app/push?tag=owned"

	tests := []struct {
		name        string
		contentType []string
		body        string
	}{
		{name: "body names a foreign tag", contentType: []string{"application/x-www-form-urlencoded"}, body: "tag=foreign"},
		{name: "empty body tag is the push-all shape", contentType: []string{"application/x-www-form-urlencoded"}, body: "tag="},
		{name: "media type parameters", contentType: []string{"application/x-www-form-urlencoded; charset=utf-8"}, body: "tag=foreign"},
		{name: "media type case", contentType: []string{"Application/X-WWW-Form-URLEncoded"}, body: "tag=foreign"},
		{name: "second content type line", contentType: []string{"application/json", "application/x-www-form-urlencoded"}, body: "tag=foreign"},
		{name: "form content type with no body yet", contentType: []string{"application/x-www-form-urlencoded"}, body: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inspector := imagePushSplitViewInspector(owner)
			req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(tt.body))
			for _, value := range tt.contentType {
				req.Header.Add("Content-Type", value)
			}
			rec, forwarded := serveImagePushRequest(t, inspector, owner, req)
			if forwarded {
				t.Fatalf("push with a form body reached the upstream; inspects = %#v", inspector.calls)
			}
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), imagePushDenyFormBody) {
				t.Fatalf("body should carry %q, got: %s", imagePushDenyFormBody, rec.Body.String())
			}
		})
	}
}

// TestImagePushAllowsNonFormBodies pins the bodies real clients send with a
// push, none of which dockerd parses as a form: the docker CLI sends none and
// docker-py sends "{}" as application/json.
func TestImagePushAllowsNonFormBodies(t *testing.T) {
	const owner = "job-123"
	const target = "/v1.45/images/registry.example/team/app/push?tag=owned"

	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "no body and no content type"},
		{name: "text/plain with no body", contentType: "text/plain"},
		{name: "json body", contentType: "application/json", body: "{}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inspector := imagePushSplitViewInspector(owner)
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}
			req := httptest.NewRequest(http.MethodPost, target, body)
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			rec, forwarded := serveImagePushRequest(t, inspector, owner, req)
			if !forwarded || rec.Code != http.StatusOK {
				t.Fatalf("forwarded = %v, status = %d, want an allowed push; body: %s", forwarded, rec.Code, rec.Body.String())
			}
			if len(inspector.calls) != 1 || inspector.calls[0].id != "registry.example/team/app:owned" {
				t.Fatalf("inspect calls = %#v, want exactly the owned tag", inspector.calls)
			}
		})
	}
}

// TestImagePushRefusesTagSpellingsTheEnginesDisagreeOn covers a single tag
// parameter the two engines read differently. Podman decodes the query with
// gorilla/schema, which folds case, so it reads ?Tag=owned as the tag. Dockerd
// reads r.Form.Get("tag") and sees no tag at all, which is the push-every-tag
// shape (confirmed against dockerd 29.5.2: ?Tag=zzz on a repository with no
// such tag starts pushing the tags that do exist). Only the exact lowercase
// key means the same thing on both.
func TestImagePushRefusesTagSpellingsTheEnginesDisagreeOn(t *testing.T) {
	const owner = "job-123"
	const base = "/v1.45/images/registry.example/team/app/push"

	tests := []struct {
		name     string
		rawQuery string
		reason   string
	}{
		{name: "capitalized key", rawQuery: "Tag=owned", reason: imagePushDenyAmbiguous},
		{name: "upper-case key", rawQuery: "TAG=owned", reason: imagePushDenyAmbiguous},
		{name: "upper-case key beside unrelated parameters", rawQuery: "platform=&TAG=owned", reason: imagePushDenyAmbiguous},
		// A pre-1.17 Go runtime split the query on ";" as well as "&", so an
		// old dockerd read tag=foreign out of the first pair below while
		// net/url here drops that pair whole. Current daemons answer 400.
		{name: "semicolon separator", rawQuery: "x;tag=foreign&tag=owned", reason: imagePushDenyAmbiguous},
		{name: "invalid escape beside the tag", rawQuery: "tag=owned&x=%zz", reason: imagePushDenyAmbiguous},
		{name: "percent-encoded repeated key", rawQuery: "tag=owned&ta%67=foreign", reason: imagePushDenyAmbiguous},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inspector := imagePushSplitViewInspector(owner)
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.URL.Path = base
			req.URL.RawQuery = tt.rawQuery
			rec, forwarded := serveImagePushRequest(t, inspector, owner, req)
			if forwarded {
				t.Fatalf("push reached the upstream; inspects = %#v", inspector.calls)
			}
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.reason) {
				t.Fatalf("body should carry %q, got: %s", tt.reason, rec.Body.String())
			}
			if len(inspector.calls) != 0 {
				t.Fatalf("inspect calls = %#v, want none for a refused request shape", inspector.calls)
			}
		})
	}

	t.Run("percent-encoded lowercase key is still the tag", func(t *testing.T) {
		inspector := imagePushSplitViewInspector(owner)
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.URL.Path = base
		req.URL.RawQuery = "ta%67=owned"
		rec, forwarded := serveImagePushRequest(t, inspector, owner, req)
		if !forwarded || rec.Code != http.StatusOK {
			t.Fatalf("forwarded = %v, status = %d, want an allowed push; body: %s", forwarded, rec.Code, rec.Body.String())
		}
	})
}
