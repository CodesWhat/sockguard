package filter

import (
	"io"
	"net/http/httptest"
	"net/url"
	"strconv"
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

func TestPodmanRunBuildIsolationModes(t *testing.T) {
	for _, route := range []string{"/libpod/build", "/v6.1.4/libpod/build", "/build"} {
		for _, mode := range []string{"0", "1", "3", "oci", "rootless", "2", "chroot", "4"} {
			for _, granted := range []bool{false, true} {
				t.Run(route+"/"+mode+"/granted="+strconv.FormatBool(granted), func(t *testing.T) {
					opts := BuildOptions{AllowRunInstructions: true, PodmanUpstream: true}
					if granted {
						opts.AllowedPodmanControls = []string{"isolation"}
					}
					query := url.Values{"nsoptions": {`[{"Name":"network","Host":false}]`}, "isolation": {mode}}.Encode()
					req := httptest.NewRequest("POST", route+"?"+query, strings.NewReader("build context"))
					path := "/libpod/build"
					if route == "/build" {
						path = route
					}
					p := newBuildPolicy(opts)
					reason, err := p.inspect(testLogger(), req, path)
					denied := !granted || mode == "2" || mode == "chroot" || mode == "4"
					if err != nil || (reason != "") != denied {
						t.Fatalf("reason %q, error %v, denied=%v", reason, err, denied)
					}
					if !denied {
						body, err := io.ReadAll(req.Body)
						if err != nil || string(body) != "build context" || req.URL.RawQuery != query {
							t.Fatal("Podman request changed")
						}
					}
				})
			}
		}
	}
}
