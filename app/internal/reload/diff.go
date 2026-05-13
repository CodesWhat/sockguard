package reload

import (
	"reflect"

	"github.com/codeswhat/sockguard/internal/config"
)

// ImmutableFields lists the dotted config paths whose values cannot be
// changed by a hot reload. A reload that mutates any of these fields is
// rejected; the operator must restart sockguard to pick the new values up.
//
// These fields are bound at startup to long-lived resources (listeners,
// log sinks, the metrics registry, the health watchdog goroutine, the
// admin endpoint wiring) that we cannot atomically replace from inside a
// running process without dropping in-flight requests or leaking goroutines.
// Everything outside this list (rules, client profiles, response filters,
// request-body policies, ownership) is rebuilt on every reload.
var ImmutableFields = []string{
	"listen",
	"upstream.socket",
	"log",
	"health",
	"metrics",
	"admin",
}

// ImmutableDiff returns the names of immutable config fields whose values
// differ between old and new. An empty slice means the reload is safe to
// apply; a non-empty slice means the caller must reject the reload and ask
// the operator to restart instead.
//
// The comparison is structural (reflect.DeepEqual on each sub-block) rather
// than YAML-string-based so trivial reformatting — comment changes, key
// reordering, whitespace — does not register as a real change.
func ImmutableDiff(oldCfg, newCfg *config.Config) []string {
	if oldCfg == nil || newCfg == nil {
		return nil
	}

	var changed []string
	if !reflect.DeepEqual(oldCfg.Listen, newCfg.Listen) {
		changed = append(changed, "listen")
	}
	if oldCfg.Upstream.Socket != newCfg.Upstream.Socket {
		changed = append(changed, "upstream.socket")
	}
	if !reflect.DeepEqual(oldCfg.Log, newCfg.Log) {
		changed = append(changed, "log")
	}
	if !reflect.DeepEqual(oldCfg.Health, newCfg.Health) {
		changed = append(changed, "health")
	}
	if !reflect.DeepEqual(oldCfg.Metrics, newCfg.Metrics) {
		changed = append(changed, "metrics")
	}
	if !reflect.DeepEqual(oldCfg.Admin, newCfg.Admin) {
		changed = append(changed, "admin")
	}
	return changed
}
