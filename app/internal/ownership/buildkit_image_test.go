package ownership

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/upstreamflavor"
)

type buildImageTransport func(*http.Request) (*http.Response, error)

func (f buildImageTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestBuildkitImageAuthorizerChecksCurrentDestination(t *testing.T) {
	for _, flavor := range []upstreamflavor.Flavor{upstreamflavor.Docker, upstreamflavor.Podman} {
		owner := "team-a"
		var targets []string
		rt := buildImageTransport(func(r *http.Request) (*http.Response, error) {
			target := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/images/"), "/json")
			targets = append(targets, target)
			status := http.StatusOK
			if strings.Contains(target, "missing") {
				status = http.StatusNotFound
			}
			if strings.Contains(target, "unreachable") {
				status = http.StatusInternalServerError
			}
			labels := map[string]string{DefaultLabelKey: owner}
			if strings.Contains(target, "unowned") {
				labels = nil
			}
			body, _ := json.Marshal(map[string]any{"Config": map[string]any{"Labels": labels}})
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header)}, nil
		})
		check := NewBuildkitImageAuthorizer(rt, Options{Owner: "team-a", LabelKey: DefaultLabelKey, UpstreamFlavor: flavor})
		if err := check(t.Context(), "mine/app:v1"); err != nil {
			t.Fatal(err)
		}
		owner = "team-b"
		if err := check(t.Context(), "mine/app:v1"); err == nil {
			t.Fatal("foreign destination accepted after retag")
		}
		for _, name := range []string{"unowned/app:v1", "unreachable/app:v1", "*", "name:tag@sha256:abc"} {
			if check(t.Context(), name) == nil {
				t.Errorf("accepted %s", name)
			}
		}
		if err := check(t.Context(), "missing/app:v1"); err != nil {
			t.Fatal(err)
		}
		if len(targets) == 0 {
			t.Fatal("no daemon lookups")
		}
		if flavor == upstreamflavor.Podman && targets[1] != "localhost/mine/app:v1" {
			t.Fatalf("stored name not checked: %v", targets)
		}
	}
}
