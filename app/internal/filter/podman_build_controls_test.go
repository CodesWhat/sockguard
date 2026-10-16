package filter

import (
	"net/http/httptest"
	"net/url"
	"testing"
)

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
