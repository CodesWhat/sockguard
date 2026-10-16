package filter

import (
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestDockerBuildOptionsDoNotRequirePodmanGrants(t *testing.T) {
	for _, query := range []string{"shmsize=67108864", "ulimits=%5B%5D", "extrahosts=one:127.0.0.1&extrahosts=two:127.0.0.2", "isolation=default"} {
		p := newBuildPolicy(BuildOptions{AllowRunInstructions: true})
		req := httptest.NewRequest("POST", "/build?"+query, strings.NewReader("build context"))
		reason, err := p.inspect(testLogger(), req, "/build")
		if err != nil || reason != "" {
			t.Fatalf("Docker option %s refused: %q, %v", query, reason, err)
		}
		body, err := io.ReadAll(req.Body)
		if err != nil || string(body) != "build context" || req.URL.RawQuery != query {
			t.Fatal("Docker request changed")
		}
	}
}

func TestPodmanRunBuildNeedsExplicitPrivateNetwork(t *testing.T) {
	for _, tc := range []struct {
		query  string
		denied bool
	}{
		{"", true}, {"networkmode=none", true},
		{"nsoptions=" + url.QueryEscape(`[{"Name":"network","Host":true}]`), true},
		{"nsoptions=" + url.QueryEscape(`[{"Name":"network","Path":"/proc/1/ns/net"}]`), true},
		{"nsoptions=" + url.QueryEscape(`[{"Name":"network"}]`), false},
		{"nsoptions=" + url.QueryEscape(`[{"Name":"network"}]`) + "&networkmode=none", false},
		{"nsoptions=" + url.QueryEscape(`[{"Name":"network"}]`) + "&isolation=chroot", true},
		{"nsoptions=" + url.QueryEscape(`[{"Name":"network"},{"Name":"network","Host":true}]`), true},
		{"nsoptions=[]", true}, {"nsoptions=invalid", true},
	} {
		t.Run(tc.query, func(t *testing.T) {
			p := newBuildPolicy(BuildOptions{AllowRunInstructions: true})
			req := httptest.NewRequest("POST", "/libpod/build?"+tc.query, nil)
			reason, err := p.inspect(testLogger(), req, "/libpod/build")
			if err != nil || (reason != "") != tc.denied {
				t.Fatalf("reason %q, error %v, denied=%v", reason, err, tc.denied)
			}
		})
	}
}
