package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/filter"
	"github.com/codeswhat/sockguard/v3/app/internal/upstreamflavor"
)

// cgroupDaemon answers /version as Docker and /info with the given body,
// counting /info requests.
func cgroupDaemon(t *testing.T, infoStatus int, infoBody string) (addr string, infoCalls *atomic.Int64) {
	t.Helper()
	infoCalls = &atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(flavorTestDockerVersionBody))
		case "/info":
			infoCalls.Add(1)
			w.WriteHeader(infoStatus)
			_, _ = w.Write([]byte(infoBody))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), infoCalls
}

func cgroupTestConfig(optIn bool) *config.Config {
	cfg := flavorTestConfig("auto")
	cfg.RequestBody.ContainerCreate.AllowHostCgroupNSOnCgroupV1 = optIn
	return cfg
}

func TestResolveUpstreamCapabilitiesCgroupV1(t *testing.T) {
	t.Parallel()
	const v1, v2 = `{"CgroupVersion":"1"}`, `{"CgroupVersion":"2"}`
	tests := []struct {
		name   string
		optIn  bool
		infos  []string
		status []int
		want   bool
		probed bool
	}{
		{name: "single v1", optIn: true, infos: []string{v1}, want: true, probed: true},
		{name: "single v2", optIn: true, infos: []string{v2}, probed: true},
		{name: "unknown version field", optIn: true, infos: []string{`{}`}, probed: true},
		{name: "info errors", optIn: true, infos: []string{v1}, status: []int{500}, probed: true},
		{name: "failover all v1", optIn: true, infos: []string{v1, v1}, want: true, probed: true},
		{name: "failover v1 then v2", optIn: true, infos: []string{v1, v2}, probed: true},
		{name: "failover v2 then v1", optIn: true, infos: []string{v2, v1}, probed: true},
		{name: "failover v1 then unknown", optIn: true, infos: []string{v1, `{}`}, probed: true},
		{name: "opt-in off never probes", optIn: false, infos: []string{v1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var addrs []string
			var calls []*atomic.Int64
			for i, body := range tt.infos {
				status := http.StatusOK
				if i < len(tt.status) {
					status = tt.status[i]
				}
				addr, c := cgroupDaemon(t, status, body)
				addrs = append(addrs, addr)
				calls = append(calls, c)
			}
			logger, _ := flavorTestLogger()
			caps, err := resolveUpstreamCapabilities(t.Context(), newServeDeps(), cgroupTestConfig(tt.optIn), multiEndpointResolver(t, addrs...), logger)
			if err != nil {
				t.Fatalf("resolveUpstreamCapabilities() error = %v", err)
			}
			if caps.CgroupV1 != tt.want {
				t.Fatalf("CgroupV1 = %v, want %v", caps.CgroupV1, tt.want)
			}
			if !tt.probed {
				for i, c := range calls {
					if c.Load() != 0 {
						t.Fatalf("endpoint %d got %d /info requests with the opt-in off, want 0", i, c.Load())
					}
				}
			}
		})
	}
}

func TestResolveUpstreamCapabilitiesCgroupV1NilProbeFailsClosed(t *testing.T) {
	t.Parallel()
	addr, _ := cgroupDaemon(t, http.StatusOK, `{"CgroupVersion":"1"}`)
	deps := newServeDeps()
	deps.probeCgroupVersion = nil
	logger, _ := flavorTestLogger()
	caps, err := resolveUpstreamCapabilities(t.Context(), deps, cgroupTestConfig(true), multiEndpointResolver(t, addr), logger)
	if err != nil || caps.CgroupV1 {
		t.Fatalf("caps = %+v, err = %v, want CgroupV1 false and no error", caps, err)
	}
}

func TestCgroupV1OptInConfiguredSeesProfiles(t *testing.T) {
	t.Parallel()
	cfg := flavorTestConfig("auto")
	if cgroupV1OptInConfigured(cfg) {
		t.Fatal("default config reports the opt-in")
	}
	var profile config.ClientProfileConfig
	profile.RequestBody.ContainerCreate.AllowHostCgroupNSOnCgroupV1 = true
	cfg.Clients.Profiles = []config.ClientProfileConfig{profile}
	if !cgroupV1OptInConfigured(cfg) {
		t.Fatal("profile opt-in not seen")
	}
}

// withFilter must hand the probed capability to the global policy: the same
// host-cgroupns create passes on a confirmed cgroup v1 upstream and is denied
// otherwise.
func TestWithFilterCarriesUpstreamCgroupV1(t *testing.T) {
	t.Parallel()
	rule, err := filter.CompileRule(filter.Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/create", Action: filter.ActionAllow})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		v1   bool
		want int
	}{{true, http.StatusNoContent}, {false, http.StatusForbidden}} {
		logger, _ := flavorTestLogger()
		handler := withFilter(cgroupTestConfig(true), nil, logger, []*filter.CompiledRule{rule}, map[string]filter.Policy{}, upstreamflavor.Docker, tt.v1)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"Image":"x","HostConfig":{"CgroupnsMode":"host"}}`))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tt.want {
			t.Fatalf("upstream v1=%v: status = %d, want %d (%s)", tt.v1, rec.Code, tt.want, rec.Body.String())
		}
	}
}
