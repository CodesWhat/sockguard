package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// switchableCgroupDaemon answers GET /info with whatever status and body are
// currently stored, counting requests.
type switchableCgroupDaemon struct {
	addr   string
	calls  atomic.Int64
	status atomic.Int64
	body   atomic.Value
}

func newSwitchableCgroupDaemon(t *testing.T, body string) *switchableCgroupDaemon {
	t.Helper()
	d := &switchableCgroupDaemon{}
	d.status.Store(http.StatusOK)
	d.body.Store(body)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/info" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		d.calls.Add(1)
		w.WriteHeader(int(d.status.Load()))
		_, _ = w.Write([]byte(d.body.Load().(string)))
	}))
	t.Cleanup(srv.Close)
	d.addr = srv.Listener.Addr().String()
	return d
}

const (
	cgroupInfoV1 = `{"CgroupVersion":"1"}`
	cgroupInfoV2 = `{"CgroupVersion":"2"}`
)

func waitForCgroup(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func newTestCgroupTracker(t *testing.T, d *switchableCgroupDaemon) *cgroupV1Tracker {
	t.Helper()
	logger, _ := flavorTestLogger()
	return newCgroupV1Tracker(newServeDeps(), multiEndpointResolver(t, d.addr), logger)
}

// The periodic probe sees a daemon migrate v1 -> v2 and closes the gate, and
// reopens it if the daemon goes back to v1.
func TestCgroupV1TrackerPeriodicProbeObservesMigration(t *testing.T) {
	t.Parallel()
	d := newSwitchableCgroupDaemon(t, cgroupInfoV1)
	tracker := newTestCgroupTracker(t, d)
	tracker.seed(true, true)
	go tracker.run(t.Context(), 10*time.Millisecond)

	if !tracker.isV1() {
		t.Fatal("seeded v1 result should be open")
	}
	d.body.Store(cgroupInfoV2)
	waitForCgroup(t, "gate to close after v1->v2", func() bool { return !tracker.isV1() })
	d.body.Store(cgroupInfoV1)
	waitForCgroup(t, "gate to reopen after v2->v1", func() bool { return tracker.isV1() })
}

func TestCgroupV1TrackerProbeErrorClosesGate(t *testing.T) {
	t.Parallel()
	d := newSwitchableCgroupDaemon(t, cgroupInfoV1)
	tracker := newTestCgroupTracker(t, d)
	tracker.seed(true, true)
	d.status.Store(http.StatusInternalServerError)
	tracker.refresh(t.Context())
	if tracker.isV1() {
		t.Fatal("a failed /info probe must close the gate")
	}
	d.status.Store(http.StatusOK)
	d.body.Store(`not json`)
	tracker.seed(true, true)
	tracker.refresh(t.Context())
	if tracker.isV1() {
		t.Fatal("an unparseable /info body must close the gate")
	}
}

// A health transition kicks an immediate re-probe, long before the interval.
func TestCgroupV1TrackerKickReprobes(t *testing.T) {
	t.Parallel()
	d := newSwitchableCgroupDaemon(t, cgroupInfoV1)
	tracker := newTestCgroupTracker(t, d)
	tracker.seed(true, true)
	go tracker.run(t.Context(), time.Hour)

	d.body.Store(cgroupInfoV2)
	tracker.kick()
	waitForCgroup(t, "kick to close the gate", func() bool { return !tracker.isV1() })
}

func TestCgroupV1TrackerNoProbesWhileOptionUnset(t *testing.T) {
	t.Parallel()
	d := newSwitchableCgroupDaemon(t, cgroupInfoV1)
	tracker := newTestCgroupTracker(t, d)
	tracker.seed(false, false)
	go tracker.run(t.Context(), 5*time.Millisecond)
	tracker.kick()
	tracker.refresh(t.Context())
	time.Sleep(100 * time.Millisecond)
	if n := d.calls.Load(); n != 0 {
		t.Fatalf("daemon got %d /info requests with the option unset, want 0", n)
	}
	if tracker.isV1() {
		t.Fatal("gate must stay closed with the option unset")
	}
}

func TestCgroupV1TrackerSetWanted(t *testing.T) {
	t.Parallel()
	d := newSwitchableCgroupDaemon(t, cgroupInfoV1)
	tracker := newTestCgroupTracker(t, d)
	if !tracker.setWanted(true) {
		t.Fatal("first enable should report newly enabled")
	}
	if tracker.isV1() {
		t.Fatal("gate must stay closed until the probe completes")
	}
	tracker.refresh(t.Context())
	if !tracker.isV1() {
		t.Fatal("gate should open after a v1 probe")
	}
	if tracker.setWanted(true) {
		t.Fatal("re-applying the same setting is not a new enable")
	}
	if !tracker.isV1() {
		t.Fatal("an unchanged reload must keep the probe result")
	}
	tracker.setWanted(false)
	if tracker.isV1() {
		t.Fatal("disabling the option closes the gate")
	}

	var nilTracker *cgroupV1Tracker
	if nilTracker.isV1() || nilTracker.isV1Func() != nil || nilTracker.setWanted(true) {
		t.Fatal("nil tracker must fail closed")
	}
	nilTracker.seed(true, true)
	nilTracker.kick()
	nilTracker.refresh(t.Context())
}

// A hot reload that turns the option on probes before the new chain goes live.
func TestReloadEnablingCgroupV1OptionProbes(t *testing.T) {
	d := newSwitchableCgroupDaemon(t, cgroupInfoV1)
	initial := config.Defaults()
	f := newReloadCoordinatorFixture(t, &initial)
	f.coordinator.runtime.cgroupV1 = newTestCgroupTracker(t, d)
	f.coordinator.runtime.cgroupV1.seed(false, false)

	reloaded := initial
	reloaded.RequestBody.ContainerCreate.AllowHostCgroupNSOnCgroupV1 = true
	f.loadCfg = &reloaded
	f.coordinator.reload()

	if n := d.calls.Load(); n != 1 {
		t.Fatalf("reload enabling the option made %d /info probes, want 1; log:\n%s", n, f.logBuf.String())
	}
	if !f.coordinator.runtime.cgroupV1.isV1() {
		t.Fatalf("gate should be open after the reload probe; log:\n%s", f.logBuf.String())
	}

	// A reload that leaves the option on does not probe again.
	f.coordinator.reload()
	if n := d.calls.Load(); n != 1 {
		t.Fatalf("unchanged reload probed again: %d /info probes", n)
	}

	// A failed probe on enable leaves the gate closed.
	d2 := newSwitchableCgroupDaemon(t, cgroupInfoV2)
	f.coordinator.runtime.cgroupV1 = newTestCgroupTracker(t, d2)
	f.coordinator.runtime.cgroupV1.seed(false, false)
	f.coordinator.reload()
	if f.coordinator.runtime.cgroupV1.isV1() {
		t.Fatal("a v2 daemon must keep the gate closed after the enabling reload")
	}
	if strings.Contains(f.logBuf.String(), "reuses the startup cgroup version probe") {
		t.Fatal("stale reuse log line still present")
	}
}

func TestCgroupV1TrackerLogsOnlyResultTransitions(t *testing.T) {
	t.Parallel()
	d := newSwitchableCgroupDaemon(t, cgroupInfoV1)
	logger, collector := flavorTestLogger()
	tracker := newCgroupV1Tracker(newServeDeps(), multiEndpointResolver(t, d.addr), logger)
	tracker.seed(true, true)
	for _, tt := range []struct {
		name, body string
		v1         bool
		warnings   int
	}{
		{name: "stable v1", body: cgroupInfoV1, v1: true},
		{name: "migrated to v2", body: cgroupInfoV2, warnings: 1},
		{name: "stable v2", body: cgroupInfoV2, warnings: 1},
		{name: "migrated back to v1", body: cgroupInfoV1, v1: true, warnings: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d.body.Store(tt.body)
			if retry := tracker.refresh(t.Context()); retry {
				t.Fatal("successful cgroup probe requested a retry")
			}
			if got := tracker.isV1(); got != tt.v1 {
				t.Fatalf("v1 gate=%v, want %v", got, tt.v1)
			}
			records := collector.FindMessage("upstream cgroup version result changed")
			if len(records) != tt.warnings {
				t.Fatalf("transition warnings=%d, want %d", len(records), tt.warnings)
			}
			if len(records) > 0 {
				attrs := records[len(records)-1].Attrs
				if attrs["was"] != !tt.v1 || attrs["upstream_cgroup_v1"] != tt.v1 {
					t.Fatalf("transition attributes=%v, want was=%v and upstream_cgroup_v1=%v", attrs, !tt.v1, tt.v1)
				}
			}
		})
	}
}
