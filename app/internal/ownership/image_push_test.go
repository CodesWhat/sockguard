package ownership

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
)

func imagePushInspector(ownedTag string, owner string) *recordingInspector {
	return &recordingInspector{resources: map[string]map[string]inspectResult{
		string(dockerresource.KindImage): {
			ownedTag: {labels: map[string]string{"com.sockguard.owner": owner}, found: true},
		},
	}}
}

func serveImagePush(t *testing.T, inspector *recordingInspector, opts Options, target string, upstream func(*testing.T, *http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	handler := middlewareWithDeps(
		testLogger(),
		opts,
		inspector.inspectResource,
		inspector.inspectExec,
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if upstream == nil {
			t.Fatal("push request reached the upstream")
		}
		upstream(t, r)
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, target, nil))
	return rec
}

// TestImagePushAuthorizesQueryTagNotDefaultTag is the regression test for the
// push misresolution: POST /images/{name}/push?tag=X names its subject in two
// pieces, and the bare repository identifier resolved the daemon's default
// tag. A proxy-scoped build pushed as {name}:{tag} was denied whenever
// {name}:latest happened to be absent ("could not resolve image"), while a
// caller owning only {name}:latest could push {name}:{anything}.
func TestImagePushAuthorizesQueryTagNotDefaultTag(t *testing.T) {
	const (
		owner    = "job-123"
		repoPath = "/v1.45/images/registry.example/team/app/push"
		ownedRef = "registry.example/team/app:v1"
	)

	t.Run("owned tagged image without a local latest is allowed", func(t *testing.T) {
		inspector := imagePushInspector(ownedRef, owner)
		// No registry.example/team/app:latest and no bare repository entry:
		// before the fix the inspect missed and the push was denied.
		rec := serveImagePush(t, inspector, Options{Owner: owner, LabelKey: "com.sockguard.owner"}, repoPath+"?tag=v1", func(_ *testing.T, _ *http.Request) {})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
		}
		if len(inspector.calls) != 1 {
			t.Fatalf("inspect calls = %#v, want exactly one", inspector.calls)
		}
		if got := inspector.calls[0].id; got != ownedRef {
			t.Fatalf("inspect identifier = %q, want the tag-qualified %q", got, ownedRef)
		}
	})

	t.Run("foreign-owned tagged image is denied even when latest is owned", func(t *testing.T) {
		inspector := &recordingInspector{resources: map[string]map[string]inspectResult{
			string(dockerresource.KindImage): {
				"registry.example/team/app:latest":      {labels: map[string]string{"com.sockguard.owner": owner}, found: true},
				"registry.example/team/app:foreign-tag": {labels: map[string]string{"com.sockguard.owner": "someone-else"}, found: true},
			},
		}}
		rec := serveImagePush(t, inspector, Options{Owner: owner, LabelKey: "com.sockguard.owner"}, repoPath+"?tag=foreign-tag", nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "owner policy") {
			t.Fatalf("body should carry the owner-policy denial, got: %s", rec.Body.String())
		}
	})

	t.Run("locally absent tagged image fails closed as not resolved", func(t *testing.T) {
		inspector := &recordingInspector{resources: map[string]map[string]inspectResult{
			string(dockerresource.KindImage): {
				"registry.example/team/app:latest": {labels: map[string]string{"com.sockguard.owner": owner}, found: true},
			},
		}}
		rec := serveImagePush(t, inspector, Options{Owner: owner, LabelKey: "com.sockguard.owner"}, repoPath+"?tag=absent-tag", nil)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d (verdictDenyMissing); body: %s", rec.Code, http.StatusNotFound, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "could not resolve image") {
			t.Fatalf("body should carry the not-resolved denial, got: %s", rec.Body.String())
		}
	})

	t.Run("unowned tagged image honors allow_unowned_images", func(t *testing.T) {
		for _, allow := range []struct {
			flag bool
			want int
		}{{true, http.StatusOK}, {false, http.StatusForbidden}} {
			inspector := &recordingInspector{resources: map[string]map[string]inspectResult{
				string(dockerresource.KindImage): {
					"registry.example/team/app:v1": {labels: nil, found: true},
				},
			}}
			rec := serveImagePush(t, inspector, Options{Owner: owner, LabelKey: "com.sockguard.owner", AllowUnownedImages: allow.flag}, repoPath+"?tag=v1", func(_ *testing.T, _ *http.Request) {})
			if rec.Code != allow.want {
				t.Fatalf("allow_unowned_images=%v status = %d, want %d; body: %s", allow.flag, rec.Code, allow.want, rec.Body.String())
			}
		}
	})

	t.Run("registry host with port is not mistaken for a tag", func(t *testing.T) {
		const withPort = "registry.example:5000/team/app:v1"
		inspector := imagePushInspector(withPort, owner)
		rec := serveImagePush(t, inspector, Options{Owner: owner, LabelKey: "com.sockguard.owner"}, "/v1.45/images/registry.example:5000/team/app/push?tag=v1", func(_ *testing.T, _ *http.Request) {})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
		}
		if got := inspector.calls[0].id; got != withPort {
			t.Fatalf("inspect identifier = %q, want %q", got, withPort)
		}
	})
}

// TestImagePushRefusesUnenumerableTagShapes covers the push forms one image
// inspect cannot authorize: no tag at all (moby pushes every local tag of the
// repository) and a repeated or case-variant tag (moby reads the first value,
// Podman's compat handler the last).
func TestImagePushRefusesUnenumerableTagShapes(t *testing.T) {
	const owner = "job-123"
	inspector := imagePushInspector("registry.example/team/app:anything", owner)

	tests := []struct {
		name   string
		target string
		reason string
	}{
		{name: "no tag pushes every local tag", target: "/v1.45/images/registry.example/team/app/push", reason: imagePushDenyNoTag},
		{name: "empty tag is the same push-all shape", target: "/v1.45/images/registry.example/team/app/push?tag=", reason: imagePushDenyNoTag},
		{name: "repeated tag values disagree between engines", target: "/v1.45/images/registry.example/team/app/push?tag=v1&tag=v2", reason: imagePushDenyAmbiguous},
		{name: "case-variant tag keys disagree between engines", target: "/v1.45/images/registry.example/team/app/push?tag=v1&Tag=v2", reason: imagePushDenyAmbiguous},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := serveImagePush(t, inspector, Options{Owner: owner, LabelKey: "com.sockguard.owner"}, tt.target, nil)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.reason) {
				t.Fatalf("body should carry %q, got: %s", tt.reason, rec.Body.String())
			}
		})
	}
}

// TestImagePushDoesNotTouchOtherImageRoutes pins the neighbors: the retag
// route keeps authorizing the bare path source (docker tag src dst spells the
// full source reference into the path), and the plain image inspect keeps its
// bare-identifier semantics.
func TestImagePushDoesNotTouchOtherImageRoutes(t *testing.T) {
	const owner = "job-123"

	t.Run("retag authorizes the bare path source", func(t *testing.T) {
		inspector := &recordingInspector{resources: map[string]map[string]inspectResult{
			string(dockerresource.KindImage): {
				"src": {labels: map[string]string{"com.sockguard.owner": owner}, found: true},
			},
		}}
		handler := middlewareWithDeps(
			testLogger(),
			Options{Owner: owner, LabelKey: "com.sockguard.owner"},
			inspector.inspectResource,
			inspector.inspectExec,
		)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1.45/images/src/tag?repo=registry.example/team/app&tag=v2", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
		}
		if len(inspector.calls) != 1 || inspector.calls[0].id != "src" {
			t.Fatalf("inspect calls = %#v, want exactly one for the bare source %q", inspector.calls, "src")
		}
	})

	t.Run("image inspect keeps bare identifier", func(t *testing.T) {
		inspector := &recordingInspector{resources: map[string]map[string]inspectResult{
			string(dockerresource.KindImage): {
				"registry.example/team/app": {labels: map[string]string{"com.sockguard.owner": owner}, found: true},
			},
		}}
		handler := middlewareWithDeps(
			testLogger(),
			Options{Owner: owner, LabelKey: "com.sockguard.owner"},
			inspector.inspectResource,
			inspector.inspectExec,
		)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1.45/images/registry.example/team/app/json", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
		}
		if len(inspector.calls) != 1 || inspector.calls[0].id != "registry.example/team/app" {
			t.Fatalf("inspect calls = %#v, want exactly one bare identifier", inspector.calls)
		}
	})
}

// TestIsImagePushRoutePathClassification pins the route classifier itself.
func TestIsImagePushRoutePathClassification(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodPost, "/images/app/push", true},
		{http.MethodPost, "/v1.45/images/registry.example/team/app/push", false}, // normPath is version-stripped; the classifier never sees a prefix
		{http.MethodPost, "/images/app/push?tag=v1", false},                      // normPath never carries a query
		{http.MethodGet, "/images/app/push", false},
		{http.MethodPost, "/images/app/tag", false},
		{http.MethodPost, "/images/app/json", false},
		{http.MethodPost, "/libpod/images/app/push", false},
		{http.MethodPost, "/images/create", false},
		{http.MethodPost, "/containers/app/push", false},
	}
	for _, tt := range tests {
		if got := isImagePushRoutePath(tt.method, tt.path); got != tt.want {
			t.Errorf("isImagePushRoutePath(%q, %q) = %v, want %v", tt.method, tt.path, got, tt.want)
		}
	}
}

// TestImagePushOwnershipReferencesParsing covers the query extraction in
// isolation, including whitespace-only tags.
func TestImagePushOwnershipReferencesParsing(t *testing.T) {
	tests := []struct {
		name        string
		rawQuery    string
		wantTag     string
		wantDenyFor string
	}{
		{name: "plain tag", rawQuery: "tag=v1", wantTag: "v1"},
		{name: "tag with slash", rawQuery: url.QueryEscape("tag") + "=" + url.QueryEscape("v1.2/rc-3"), wantTag: "v1.2/rc-3"},
		{name: "whitespace tag", rawQuery: "tag=%20%20", wantDenyFor: imagePushDenyNoTag},
		{name: "no query", rawQuery: "", wantDenyFor: imagePushDenyNoTag},
		{name: "repeated tag", rawQuery: "tag=a&tag=b", wantDenyFor: imagePushDenyAmbiguous},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refs := imagePushOwnershipReferences(httptest.NewRequest(http.MethodPost, "/images/app/push?"+tt.rawQuery, nil))
			switch {
			case tt.wantDenyFor != "":
				if refs.denyReason != tt.wantDenyFor {
					t.Fatalf("denyReason = %q, want %q", refs.denyReason, tt.wantDenyFor)
				}
				if refs.imagePushTag != "" {
					t.Fatalf("imagePushTag = %q, want empty on refusal", refs.imagePushTag)
				}
			default:
				if refs.denyReason != "" {
					t.Fatalf("denyReason = %q, want none", refs.denyReason)
				}
				if refs.imagePushTag != tt.wantTag {
					t.Fatalf("imagePushTag = %q, want %q", refs.imagePushTag, tt.wantTag)
				}
			}
		})
	}
}
