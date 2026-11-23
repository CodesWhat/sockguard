package cmd

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/filter"
)

type compatAck int

const (
	ackNone compatAck = iota
	ackRead
	ackBlind
	ackBoth
)

// compileCompatEnv expands the given compat environment through ApplyCompat
// and the real validator, returning the compiled rules (or the validation
// error). ack selects which of the read-exfiltration and body-blind-write
// acknowledgments are set.
func compileCompatEnv(t *testing.T, env map[string]string, ack compatAck) ([]*filter.CompiledRule, error) {
	t.Helper()
	isolateReadExfilEnv(t)
	for _, key := range []string{"TIMEOUT_CLIENT", "TIMEOUT_SERVER", "DISABLE_IPV6"} {
		t.Setenv(key, "")
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	cfg := config.Defaults()
	if !config.ApplyCompat(&cfg, slog.New(slog.NewTextHandler(io.Discard, nil))) {
		t.Fatalf("compat did not activate for %v", env)
	}
	cfg.InsecureAllowReadExfiltration = ack == ackRead || ack == ackBoth
	cfg.InsecureAllowBodyBlindWrites = ack == ackBlind || ack == ackBoth
	return validateAndCompileRules(&cfg)
}

func evalCompat(rules []*filter.CompiledRule, method, path string) filter.Action {
	req := httptest.NewRequest(method, path, nil)
	action, _, _ := filter.Evaluate(rules, req)
	return action
}

func TestLinuxServerCompatEndToEnd(t *testing.T) {
	tests := []struct {
		name   string
		env    map[string]string
		method string
		path   string
		want   filter.Action
	}{
		{"containers alone is tecnativa and allows logs", map[string]string{"CONTAINERS": "1"}, "GET", "/v1.45/containers/x/logs", filter.ActionAllow},
		{"lsio flavor denies logs without ALLOW_LOGS", map[string]string{"CONTAINERS": "1", "ALLOW_TOP": "1"}, "GET", "/v1.45/containers/x/logs", filter.ActionDeny},
		{"lsio flavor allows top", map[string]string{"CONTAINERS": "1", "ALLOW_TOP": "1"}, "GET", "/v1.45/containers/x/top", filter.ActionAllow},
		{"ALLOW_LOGS allows logs", map[string]string{"CONTAINERS": "1", "ALLOW_LOGS": "1"}, "GET", "/containers/x/logs", filter.ActionAllow},
		{"ALLOW_LOGS explicit zero keeps the guard", map[string]string{"CONTAINERS": "1", "ALLOW_LOGS": "0"}, "GET", "/containers/x/logs", filter.ActionDeny},
		{"lsio flavor still reads other container routes", map[string]string{"CONTAINERS": "1", "ALLOW_TOP": "1"}, "GET", "/containers/json", filter.ActionAllow},
		{"libpod ping defaults on", map[string]string{"LIBPOD_PODS": "0"}, "GET", "/v5.4.0/libpod/_ping", filter.ActionAllow},
		{"libpod version defaults on", map[string]string{"LIBPOD_PODS": "0"}, "GET", "/v5.4.0/libpod/version", filter.ActionAllow},
		{"libpod ping can be disabled", map[string]string{"LIBPOD_PING": "0"}, "GET", "/libpod/_ping", filter.ActionDeny},
		{"libpod pause denied by guard despite LIBPOD_ALLOW_PAUSE", map[string]string{"LIBPOD_ALLOW_PAUSE": "1"}, "POST", "/v5.4.0/libpod/containers/x/pause", filter.ActionDeny},
		{"libpod pause allowed when both set", map[string]string{"LIBPOD_ALLOW_PAUSE": "1", "ALLOW_PAUSE": "1"}, "POST", "/libpod/containers/x/pause", filter.ActionAllow},
		{"libpod pod pause denied by guard", map[string]string{"LIBPOD_ALLOW_POD_PAUSE": "1"}, "POST", "/libpod/pods/x/pause", filter.ActionDeny},
		{"libpod start via LIBPOD_ALLOW_START", map[string]string{"LIBPOD_ALLOW_START": "1"}, "POST", "/libpod/containers/x/start", filter.ActionAllow},
		{"ALLOW_START covers libpod pods", map[string]string{"ALLOW_START": "1", "LIBPOD_PING": "1"}, "POST", "/libpod/pods/x/start", filter.ActionAllow},
		{"ALLOW_START does not cover stop", map[string]string{"ALLOW_START": "1", "LIBPOD_PING": "1"}, "POST", "/libpod/containers/x/stop", filter.ActionDeny},
		{"libpod logs guarded", map[string]string{"LIBPOD_CONTAINERS": "1"}, "GET", "/libpod/containers/x/logs", filter.ActionDeny},
		{"libpod logs allowed with ALLOW_LOGS", map[string]string{"LIBPOD_CONTAINERS": "1", "ALLOW_LOGS": "1"}, "GET", "/libpod/containers/x/logs", filter.ActionAllow},
		{"libpod exec create guarded without EXEC", map[string]string{"LIBPOD_CONTAINERS": "1", "POST": "1"}, "POST", "/libpod/containers/x/exec", filter.ActionDeny},
		{"libpod container read allowed", map[string]string{"LIBPOD_CONTAINERS": "1"}, "GET", "/libpod/containers/json", filter.ActionAllow},
		{"EXEC without CONTAINERS denies container exec create", map[string]string{"EXEC": "1", "ALLOW_LOGS": "0", "POST": "1"}, "POST", "/containers/x/exec", filter.ActionDeny},
		{"EXEC with CONTAINERS allows container exec create", map[string]string{"CONTAINERS": "1", "EXEC": "1", "POST": "1", "ALLOW_LOGS": "0"}, "POST", "/containers/x/exec", filter.ActionAllow},
		{"libpod write needs POST", map[string]string{"LIBPOD_PODS": "1"}, "POST", "/libpod/pods/create", filter.ActionDeny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := compileCompatEnv(t, tt.env, ackBoth)
			if err != nil {
				t.Fatalf("validate: %v", err)
			}
			if got := evalCompat(rules, tt.method, tt.path); got != tt.want {
				t.Fatalf("%s %s = %s, want %s", tt.method, tt.path, got, tt.want)
			}
		})
	}
}

// TestLinuxServerCompatLibpodGatedLikeDocker proves the libpod sections do not
// slip past the acknowledgments their Docker twins need. Each case names the
// gate it exercises: without the matching acknowledgment validation must fail
// with that gate's key, and with only the OTHER acknowledgment it must still
// fail, so the two gates are proven independently.
func TestLinuxServerCompatLibpodGatedLikeDocker(t *testing.T) {
	const (
		readGate  = "insecure_allow_read_exfiltration"
		blindGate = "insecure_allow_body_blind_writes"
	)
	tests := []struct {
		name string
		env  map[string]string
		gate string
	}{
		{"LIBPOD_CONTAINERS read", map[string]string{"LIBPOD_CONTAINERS": "1"}, readGate},
		{"LIBPOD_IMAGES read", map[string]string{"LIBPOD_IMAGES": "1"}, readGate},
		{"LIBPOD_GENERATE read", map[string]string{"LIBPOD_GENERATE": "1"}, readGate},
		{"LIBPOD_PLAY body blind", map[string]string{"LIBPOD_PLAY": "1", "POST": "1"}, blindGate},
		{"LIBPOD_MANIFESTS body blind", map[string]string{"LIBPOD_MANIFESTS": "1", "POST": "1"}, blindGate},
		{"LIBPOD_CONTAINERS with POST body blind", map[string]string{"LIBPOD_CONTAINERS": "1", "POST": "1"}, blindGate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := compileCompatEnv(t, tt.env, ackNone)
			if err == nil || !strings.Contains(err.Error(), tt.gate) {
				t.Fatalf("without acknowledgments error = %v, want mention of %q", err, tt.gate)
			}

			// Acknowledge only the other gate: this one must still refuse.
			other := ackRead
			if tt.gate == readGate {
				other = ackBlind
			}
			if tt.gate == blindGate {
				// Body-blind cases are exercised with the read ack set, so the
				// body-blind gate itself is what refuses.
				_, err = compileCompatEnv(t, tt.env, ackRead)
				if err == nil || !strings.Contains(err.Error(), blindGate) {
					t.Fatalf("with only the read ack error = %v, want %q", err, blindGate)
				}
			} else {
				_, err = compileCompatEnv(t, tt.env, other)
				if err == nil || !strings.Contains(err.Error(), readGate) {
					t.Fatalf("with only the body-blind ack error = %v, want %q", err, readGate)
				}
			}

			if _, err := compileCompatEnv(t, tt.env, ackBoth); err != nil {
				t.Fatalf("acknowledged config should validate: %v", err)
			}
		})
	}
}

func TestLinuxServerCompatDefaultsNeedNoAcknowledgment(t *testing.T) {
	rules, err := compileCompatEnv(t, map[string]string{"ALLOW_LOGS": "0"}, ackNone)
	if err != nil {
		t.Fatalf("lsio defaults (ping, version, events) must validate without acknowledgment: %v", err)
	}
	if evalCompat(rules, http.MethodGet, "/libpod/_ping") != filter.ActionAllow {
		t.Fatal("libpod ping should be allowed by default")
	}
}

// TestLinuxServerCompatLibpodSystemDoesNotReachAutoupdate pins what
// LIBPOD_SYSTEM=1 actually opens: /libpod/system/**, which needs no
// acknowledgment, and not /libpod/autoupdate (a sibling path that would need
// both), so the section can't be used to reach it.
func TestLinuxServerCompatLibpodSystemDoesNotReachAutoupdate(t *testing.T) {
	rules, err := compileCompatEnv(t, map[string]string{"LIBPOD_SYSTEM": "1", "POST": "1"}, ackNone)
	if err != nil {
		t.Fatalf("LIBPOD_SYSTEM=1 POST=1 should validate without acknowledgment: %v", err)
	}
	if got := evalCompat(rules, http.MethodGet, "/libpod/system/df"); got != filter.ActionAllow {
		t.Fatalf("GET /libpod/system/df = %s, want allow", got)
	}
	if got := evalCompat(rules, http.MethodPost, "/libpod/autoupdate"); got != filter.ActionDeny {
		t.Fatalf("POST /libpod/autoupdate = %s, want deny", got)
	}
}
