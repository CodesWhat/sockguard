package filter

import (
	"net/http"
	"net/url"
	"testing"
)

// TestIsLibpodImageScpRoutePathCoversTheBareRoute pins which route views reach
// Podman's image-SCP handler. POST /libpod/images/scp/{name:.*} is registered
// after /libpod/images/{name:.*}/push, /tag and /untag, and `.*` matches the
// empty string, so the bare /libpod/images/scp/ is an SCP call with an empty
// source name. Replaying Podman v5.8.1's registration order through
// gorilla/mux v1.8.1 dispatches POST /v5.0.0/libpod/images/scp/ to ImageScp
// with name="".
func TestIsLibpodImageScpRoutePathCoversTheBareRoute(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		routePath string
		want      bool
	}{
		{"bare route with no name", "/libpod/images/scp/", true},
		{"named source", "/libpod/images/scp/victim", true},
		{"registry-qualified source", "/libpod/images/scp/registry.example.com/team/app", true},
		{"trailing slash defeats the push route", "/libpod/images/scp/victim/push/", true},
		{"push route belongs to the image-push handler", "/libpod/images/scp/victim/push", false},
		{"tag route belongs to the tag handler", "/libpod/images/scp/victim/tag", false},
		{"untag route belongs to the untag handler", "/libpod/images/scp/victim/untag", false},
		{"bare push is a push of the image scp", "/libpod/images/scp/push", false},
		{"prefix without the separator is another route", "/libpod/images/scp", false},
		{"unrelated libpod route", "/libpod/images/pull", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := isLibpodImageScpRoutePath(test.routePath); got != test.want {
				t.Fatalf("isLibpodImageScpRoutePath(%q) = %t, want %t", test.routePath, got, test.want)
			}
		})
	}
}

// TestBareLibpodImageScpRouteNeedsBothViews is the runtime half of the S17b
// fix for the empty source name. POST /libpod/images/scp/ cleans to
// /libpod/images/scp for policy matching while gorilla/mux routes it to the
// SCP catch-all, so a rule written for a sibling route must not admit it on
// the decoded view alone.
func TestBareLibpodImageScpRouteNeedsBothViews(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		pattern string
		want    Action
	}{
		{"sibling segment glob covers only the decoded view", "/libpod/images/*", ActionDeny},
		{"decoded spelling alone is not enough", "/libpod/images/scp", ActionDeny},
		{"route view alone is not enough", "/libpod/images/scp/", ActionDeny},
		{"a rule covering both views allows", "/libpod/images/scp/**", ActionAllow},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			rules := compileRulesForTest(t, []Rule{
				{Methods: []string{http.MethodPost}, Pattern: test.pattern, Action: ActionAllow, Index: 0},
				{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Index: 1},
			})
			req := &http.Request{Method: http.MethodPost, URL: &url.URL{Path: "/libpod/images/scp/"}}
			if action, _, _ := Evaluate(rules, req); action != test.want {
				t.Fatalf("Evaluate(POST /libpod/images/scp/) under allow %q = %v, want %v", test.pattern, action, test.want)
			}
		})
	}
}
