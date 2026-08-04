package reload

import (
	"fmt"
	"reflect"
	"sort"

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
	"listeners",
	"upstream.socket",
	"upstream.endpoints",
	"upstream.failover",
	"log",
	"health",
	"metrics",
	"admin",
	"policy_bundle.enabled",
	"policy_bundle.allowed_signing_keys",
	"policy_bundle.allowed_keyless",
	"policy_bundle.require_rekor_inclusion",
	"policy_bundle.verify_timeout",
	"reload.enabled",
	"reload.debounce",
	"reload.poll_interval",
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
	// Legacy mode (both configs have an empty Listeners list) keeps
	// reporting the single "listen" key exactly as before #149 — this is a
	// deliberate back-compat pin, not an oversight: operators who never set
	// listeners: must see identical reload diagnostics. The moment either
	// side uses the explicit listeners: list, diffListeners takes over with
	// per-name, per-field reporting (and immutably rejects a legacy<->list
	// mode switch even when the switch happens to be a structural no-op).
	if len(oldCfg.Listeners) == 0 && len(newCfg.Listeners) == 0 {
		if !reflect.DeepEqual(oldCfg.Listen, newCfg.Listen) {
			changed = append(changed, "listen")
		}
	} else {
		changed = append(changed, diffListeners(oldCfg, newCfg)...)
	}
	if oldCfg.Upstream.Socket != newCfg.Upstream.Socket {
		changed = append(changed, "upstream.socket")
	}
	// Endpoints and the failover health loop bind to the long-lived Resolver and
	// its background goroutine at startup, so they cannot change under a reload.
	// upstream.request_timeout stays mutable: it is rebuilt with the handler
	// chain on every reload.
	if !reflect.DeepEqual(oldCfg.Upstream.Endpoints, newCfg.Upstream.Endpoints) {
		changed = append(changed, "upstream.endpoints")
	}
	if !reflect.DeepEqual(oldCfg.Upstream.Failover, newCfg.Upstream.Failover) {
		changed = append(changed, "upstream.failover")
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
	// SignaturePath is intentionally mutable so an operator can re-sign the
	// same YAML and bump only the sibling sigstore-bundle path. Everything
	// else under policy_bundle changes the trust root and therefore must
	// pin to startup so a reload cannot silently widen the set of accepted
	// signers.
	if oldCfg.PolicyBundle.Enabled != newCfg.PolicyBundle.Enabled {
		changed = append(changed, "policy_bundle.enabled")
	}
	if !reflect.DeepEqual(oldCfg.PolicyBundle.AllowedSigningKeys, newCfg.PolicyBundle.AllowedSigningKeys) {
		changed = append(changed, "policy_bundle.allowed_signing_keys")
	}
	if !reflect.DeepEqual(oldCfg.PolicyBundle.AllowedKeyless, newCfg.PolicyBundle.AllowedKeyless) {
		changed = append(changed, "policy_bundle.allowed_keyless")
	}
	if oldCfg.PolicyBundle.RequireRekorInclusion != newCfg.PolicyBundle.RequireRekorInclusion {
		changed = append(changed, "policy_bundle.require_rekor_inclusion")
	}
	if oldCfg.PolicyBundle.VerifyTimeout != newCfg.PolicyBundle.VerifyTimeout {
		changed = append(changed, "policy_bundle.verify_timeout")
	}
	// The reload watcher reads these once at startup to wire its fsnotify watch
	// plus the debounce/poll timers; a reload can't reconfigure the already-
	// running watcher, so a change here has no effect until restart. Treat it as
	// immutable rather than silently ignoring it.
	if oldCfg.Reload.Enabled != newCfg.Reload.Enabled {
		changed = append(changed, "reload.enabled")
	}
	if oldCfg.Reload.Debounce != newCfg.Reload.Debounce {
		changed = append(changed, "reload.debounce")
	}
	if oldCfg.Reload.PollInterval != newCfg.Reload.PollInterval {
		changed = append(changed, "reload.poll_interval")
	}
	return changed
}

// diffListeners is the explicit listeners: list's ImmutableDiff projection:
// the listener SET is immutable by name (add/remove/rename all reject), and
// every per-listener field is immutable EXCEPT AllowedProfiles, which is the
// sole reload-mutable field (consistent with clients.profiles already being
// reload-mutable — an allowed_profiles change compiles into the same
// swapped handler generation as a rules/profiles change, no rebind
// required). Pure reordering is a no-op: comparison is by name, not slice
// position.
func diffListeners(oldCfg, newCfg *config.Config) []string {
	oldExplicit := len(oldCfg.Listeners) > 0
	newExplicit := len(newCfg.Listeners) > 0

	// Switching between legacy listen: and explicit listeners: mode is
	// immutable even when the switch happens to be structurally a no-op
	// (e.g. a single explicit entry named "default" with identical fields
	// to the synthesized legacy listener) — the two modes bind through
	// different code paths and must not be silently reinterpreted mid-run.
	if oldExplicit != newExplicit {
		return []string{"listeners: switching between legacy listen: and explicit listeners: requires a restart"}
	}
	if !oldExplicit {
		// Both legacy; caller already handled "listen" via the DeepEqual
		// branch above and never reaches here in that case, but stay
		// defensive.
		return nil
	}

	oldByName := indexListenersByName(oldCfg.Listeners)
	newByName := indexListenersByName(newCfg.Listeners)

	names := make(map[string]struct{}, len(oldByName)+len(newByName))
	for name := range oldByName {
		names[name] = struct{}{}
	}
	for name := range newByName {
		names[name] = struct{}{}
	}

	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)

	var changed []string
	for _, name := range sorted {
		o, oOK := oldByName[name]
		n, nOK := newByName[name]
		switch {
		case !oOK:
			changed = append(changed, fmt.Sprintf("listeners.%s: added", name))
		case !nOK:
			changed = append(changed, fmt.Sprintf("listeners.%s: removed", name))
		default:
			changed = append(changed, diffListenerFields(name, o, n)...)
		}
	}
	return changed
}

func indexListenersByName(entries []config.ListenerConfig) map[string]config.ListenerConfig {
	byName := make(map[string]config.ListenerConfig, len(entries))
	for _, e := range entries {
		byName[e.Name] = e
	}
	return byName
}

// diffListenerFields reports every field that changed between two entries
// with the same name, excluding AllowedProfiles (the sole mutable field).
// Granularity is per top-level field (socket/address/socket_mode/ownership/
// TLS-as-a-whole/plaintext acks) rather than recursing into TLS subfields —
// coarser than a full per-subfield projection, but every entry still names
// exactly which listener and which top-level field changed, which is the
// diagnostic improvement this rewrite is for.
func diffListenerFields(name string, o, n config.ListenerConfig) []string {
	var changed []string
	prefix := "listeners." + name + "."
	if o.Socket != n.Socket {
		changed = append(changed, prefix+"socket")
	}
	if o.Address != n.Address {
		changed = append(changed, prefix+"address")
	}
	if o.SocketMode != n.SocketMode {
		changed = append(changed, prefix+"socket_mode")
	}
	if !reflect.DeepEqual(o.SocketUID, n.SocketUID) {
		changed = append(changed, prefix+"socket_uid")
	}
	if !reflect.DeepEqual(o.SocketGID, n.SocketGID) {
		changed = append(changed, prefix+"socket_gid")
	}
	if o.InsecureAllowPlainTCP != n.InsecureAllowPlainTCP {
		changed = append(changed, prefix+"insecure_allow_plain_tcp")
	}
	if o.InsecureAllowUnauthenticatedClients != n.InsecureAllowUnauthenticatedClients {
		changed = append(changed, prefix+"insecure_allow_unauthenticated_clients")
	}
	if !reflect.DeepEqual(o.TLS, n.TLS) {
		changed = append(changed, prefix+"tls")
	}
	// AllowedProfiles intentionally excluded: the sole reload-mutable field.
	return changed
}
