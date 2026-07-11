package filter_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
)

// The finalize exec argv drydock issues during self-update. It must match the
// allowed_commands entry in drydock-with-selfupdate.yaml exactly (token count +
// every token). Source: drydock app/triggers/providers/docker/self-update-controller.ts.
const drydockFinalizeArgvBody = `{"Cmd":["node","dist/triggers/providers/docker/self-update-finalize-entrypoint.js"]}`

// drydockFinalizeExecCreateBody is the full exec-create body drydock's helper
// container issues for runFinalizeCallbackInContainer, including the Env
// array buildFinalizeExecEnv assembles (DD_SELF_UPDATE_FINALIZE_URL/SECRET/
// OPERATION_ID/STATUS/PHASE) and the AttachStdout/AttachStderr flags. The
// preset's allowed_env_vars allowlists exactly this set, so this body must
// pass identically to drydockFinalizeArgvBody. Source: drydock
// app/triggers/providers/docker/self-update-controller.ts (runFinalizeCallbackInContainer,
// buildFinalizeExecEnv).
const drydockFinalizeExecCreateBody = `{` +
	`"AttachStdout":true,"AttachStderr":true,` +
	`"Cmd":["node","dist/triggers/providers/docker/self-update-finalize-entrypoint.js"],` +
	`"Env":["DD_SELF_UPDATE_FINALIZE_URL=http://127.0.0.1:3000/internal/self-update/finalize",` +
	`"DD_SELF_UPDATE_FINALIZE_SECRET=s3cr3t","DD_SELF_UPDATE_OPERATION_ID=op-1",` +
	`"DD_SELF_UPDATE_STATUS=succeeded","DD_SELF_UPDATE_PHASE=succeeded"]` +
	`}`

// drydockFinalizeExecCreateBodyWithNodeOptions is the same real-world body as
// drydockFinalizeExecCreateBody but with an extra, non-allowlisted Env entry
// (NODE_OPTIONS) appended. Cmd still matches allowed_commands exactly, so
// this proves allowed_env_vars is enforced independently of the argv pin —
// pinning Cmd alone would not have caught this, since NODE_OPTIONS changes
// what the pinned "node" argv executes without changing argv itself.
const drydockFinalizeExecCreateBodyWithNodeOptions = `{` +
	`"AttachStdout":true,"AttachStderr":true,` +
	`"Cmd":["node","dist/triggers/providers/docker/self-update-finalize-entrypoint.js"],` +
	`"Env":["DD_SELF_UPDATE_FINALIZE_URL=http://127.0.0.1:3000/internal/self-update/finalize",` +
	`"DD_SELF_UPDATE_FINALIZE_SECRET=s3cr3t","DD_SELF_UPDATE_OPERATION_ID=op-1",` +
	`"DD_SELF_UPDATE_STATUS=succeeded","DD_SELF_UPDATE_PHASE=succeeded",` +
	`"NODE_OPTIONS=--require /tmp/evil.js"]` +
	`}`

// presetCase is one (method, path, body) request and whether the drydock preset's
// filter chain (rule layer + request-body inspectors) should let it reach upstream.
type presetCase struct {
	name    string
	method  string
	path    string
	body    string // JSON body for inspected POSTs; empty for none
	allowed bool
}

// TestDrydockPresetConformance fires drydock v1.5.0's real Docker Engine API
// surface at a filter chain built from the shipped drydock presets, asserting
// which requests survive and which the default-deny blocks. It guards the
// integration contract the presets exist to satisfy:
//
//   - container recreate carries HostConfig.Runtime "runc" → must pass the
//     allowed_runtimes allowlist (a preset that drops allowed_runtimes:[runc]
//     regresses every update);
//   - multi-network recreate issues POST /networks/{id}/connect → must be allowed;
//   - the self-update finalize exec (no User field, exact finalize argv) must pass
//     drydock-with-selfupdate.yaml's exec inspector (allow_root_user must stay
//     true, since sockguard treats an empty exec User as root), and only that
//     exact argv — any other command stays denied;
//   - the base drydock.yaml denies exec entirely.
//
// It is a unit-level guard (stub upstream, no live daemon). The exec *start*
// path (POST /exec/*/start) needs a daemon round-trip to inspect the existing
// exec, so it is out of scope here — exec coverage targets the create path,
// where allowed_commands and allow_root_user are enforced.
func TestDrydockPresetConformance(t *testing.T) {
	// Shared surface both presets must admit / reject identically.
	base := []presetCase{
		// Health + metadata.
		{"ping-get", http.MethodGet, "/_ping", "", true},
		{"ping-head", http.MethodHead, "/_ping", "", true},
		{"version", http.MethodGet, "/version", "", true},
		{"info", http.MethodGet, "/info", "", true},
		{"events", http.MethodGet, "/events", "", true},

		// Container reads drydock's watch + update flow uses.
		{"containers-list", http.MethodGet, "/containers/json", "", true},
		{"container-inspect", http.MethodGet, "/containers/abc/json", "", true},
		{"container-stats", http.MethodGet, "/containers/abc/stats", "", true},

		// Container lifecycle drydock's update flow drives.
		{"start", http.MethodPost, "/containers/abc/start", "", true},
		{"stop", http.MethodPost, "/containers/abc/stop", "", true},
		{"restart", http.MethodPost, "/containers/abc/restart", "", true},
		{"kill", http.MethodPost, "/containers/abc/kill", "", true},
		{"rename", http.MethodPost, "/containers/abc/rename", "", true},
		{"update", http.MethodPost, "/containers/abc/update", "", true},
		{"wait", http.MethodPost, "/containers/abc/wait", "", true},
		{"remove", http.MethodDelete, "/containers/abc", "", true},

		// Recreate: the inspect spec carries an explicit runc runtime, which the
		// allowed_runtimes allowlist must admit. Guards regression B1.
		{"create-runc", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Runtime":"runc"}}`, true},
		// A non-allowlisted runtime must still be denied — proves the allowlist
		// is enforcing, not merely absent.
		{"create-kata-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Runtime":"kata"}}`, false},

		// Image reads + pull + delete.
		{"images-list", http.MethodGet, "/images/json", "", true},
		{"image-inspect", http.MethodGet, "/images/busybox/json", "", true},
		{"image-inspect-namespaced", http.MethodGet, "/images/library/busybox/json", "", true},
		{"image-history", http.MethodGet, "/images/busybox/history", "", true},
		{"image-pull", http.MethodPost, "/images/create?fromImage=busybox:latest", "", true},
		{"image-delete", http.MethodDelete, "/images/busybox", "", true},

		// Networks: list + inspect + connect (multi-network recreate). Guards D1.
		{"networks-list", http.MethodGet, "/networks", "", true},
		{"network-inspect", http.MethodGet, "/networks/abc", "", true},
		{"network-connect", http.MethodPost, "/networks/abc/connect", `{"Container":"abc"}`, true},
		// Aliases-only secondary-network connect — the regression test that would
		// have caught the drydock incident this preset suite guards against.
		// Docker Compose sets Aliases: [serviceName] on every endpoint it
		// creates, so a multi-network Compose recreate's connect call for its
		// secondary network(s) always carries an Aliases-only EndpointConfig.
		// Before the endpoint-config/aliases fix, this was unconditionally
		// denied (no allow_endpoint_config escape hatch could fix it without
		// also opening static IP/MAC/DriverOpts), breaking every such recreate.
		// Must pass by default now — neither drydock preset sets
		// allow_endpoint_config.
		{"network-connect-aliases-only-allowed", http.MethodPost, "/networks/abc/connect", `{"Container":"abc","EndpointConfig":{"Aliases":["myapp"]}}`, true},
		// The real incident shape: a macvlan connect carrying a static IP
		// (IPAMConfig.IPv4Address) alongside the Aliases Compose always sets.
		// drydock recreating a macvlan+static-IP container issues exactly this
		// on POST /networks/{id}/connect for its extra network(s); neither
		// drydock preset opts into allow_endpoint_config, so this must stay
		// denied by default — with the static-IP reason, not the (now-removed)
		// aliases denial — and operators who need macvlan/static-IP recreates
		// must explicitly set allow_endpoint_config: true (see the preset
		// header comments).
		{"network-connect-macvlan-static-ip-denied", http.MethodPost, "/networks/abc/connect", `{"Container":"abc","EndpointConfig":{"IPAMConfig":{"IPv4Address":"172.20.0.50"},"Aliases":["myapp"]}}`, false},

		// Volumes + distribution + services reads.
		{"volumes-list", http.MethodGet, "/volumes", "", true},
		{"volume-inspect", http.MethodGet, "/volumes/abc", "", true},
		{"distribution", http.MethodGet, "/distribution/busybox/json", "", true},
		{"services-list", http.MethodGet, "/services", "", true},
		{"service-inspect", http.MethodGet, "/services/abc", "", true},

		// Default-deny surface: exfiltration streams, network create, builds,
		// secrets — none are in the preset.
		{"logs-denied", http.MethodGet, "/containers/abc/logs", "", false},
		{"archive-denied", http.MethodGet, "/containers/abc/archive", "", false},
		{"network-create-denied", http.MethodPost, "/networks/create", "", false},
		{"build-denied", http.MethodPost, "/build", "", false},
		{"secrets-create-denied", http.MethodPost, "/secrets/create", "", false},
	}

	t.Run("drydock.yaml", func(t *testing.T) {
		handler := buildDrydockPresetHandler(t, "drydock.yaml")
		cases := append([]presetCase{}, base...)
		// The base preset denies exec entirely — finalize falls to default-deny.
		cases = append(cases,
			presetCase{"exec-create-denied", http.MethodPost, "/containers/abc/exec", drydockFinalizeArgvBody, false},
		)
		for _, c := range cases {
			fireDrydockCase(t, handler, c)
		}
	})

	t.Run("drydock-with-selfupdate.yaml", func(t *testing.T) {
		handler := buildDrydockPresetHandler(t, "drydock-with-selfupdate.yaml")
		cases := append([]presetCase{}, base...)
		cases = append(cases,
			// The finalize exec: exact argv, no User field. Allowed only because
			// allow_root_user is true (empty User reads as root). Guards B2.
			presetCase{"finalize-exec-allowed", http.MethodPost, "/containers/abc/exec", drydockFinalizeArgvBody, true},
			// The real body the helper container sends, Env included: the
			// preset's allowed_env_vars allowlists exactly the DD_SELF_UPDATE_*
			// names it carries, so the verdict is unchanged.
			presetCase{"finalize-exec-allowed-full-body", http.MethodPost, "/containers/abc/exec", drydockFinalizeExecCreateBody, true},
			// Any other exec command stays denied by the exact-argv allowlist.
			presetCase{"exec-shell-denied", http.MethodPost, "/containers/abc/exec", `{"Cmd":["sh","-c","id"]}`, false},
			presetCase{"exec-other-node-denied", http.MethodPost, "/containers/abc/exec", `{"Cmd":["node","evil.js"]}`, false},
			// Same allowlisted argv, but with an extra non-allowlisted Env
			// entry (NODE_OPTIONS): allowed_env_vars must deny this even
			// though allowed_commands alone would have let it through.
			presetCase{"finalize-exec-denied-node-options-env", http.MethodPost, "/containers/abc/exec", drydockFinalizeExecCreateBodyWithNodeOptions, false},
			// The exec inspect rule is present (start needs a daemon, so not asserted).
			presetCase{"exec-inspect", http.MethodGet, "/exec/abc/json", "", true},
		)
		for _, c := range cases {
			fireDrydockCase(t, handler, c)
		}
	})
}

// TestDrydockPresetNetworkConnectAllowEndpointConfigEscapeHatch proves the
// documented escape hatch actually works against the shipped drydock
// presets: an operator who sets request_body.network.allow_endpoint_config:
// true gets the real-incident macvlan+static-IP connect admitted, on both
// presets. Neither preset sets the flag itself (see the header-comment
// operator guidance added alongside this test), so this exercises the
// override path rather than a preset default.
func TestDrydockPresetNetworkConnectAllowEndpointConfigEscapeHatch(t *testing.T) {
	const macvlanStaticIPBody = `{"Container":"abc","EndpointConfig":{"IPAMConfig":{"IPv4Address":"172.20.0.50"},"Aliases":["myapp"]}}`

	for _, presetFile := range []string{"drydock.yaml", "drydock-with-selfupdate.yaml"} {
		t.Run(presetFile, func(t *testing.T) {
			handler := buildDrydockPresetHandlerWithNetworkAllowEndpointConfig(t, presetFile)
			fireDrydockCase(t, handler, presetCase{
				name:    "network-connect-macvlan-static-ip-allowed",
				method:  http.MethodPost,
				path:    "/networks/abc/connect",
				body:    macvlanStaticIPBody,
				allowed: true,
			})
		})
	}
}

// buildDrydockPresetHandler loads a preset from app/configs and assembles the
// filter middleware the way serve.go does (rules + request-body inspectors),
// wrapping a stub upstream that 200s when a request is allowed through.
func buildDrydockPresetHandler(t *testing.T, presetFile string) http.Handler {
	t.Helper()

	cfg, err := config.Load(filepath.Join("..", "..", "configs", presetFile))
	if err != nil {
		t.Fatalf("load preset %s: %v", presetFile, err)
	}

	return drydockPresetHandlerFromConfig(t, cfg)
}

// buildDrydockPresetHandlerWithNetworkAllowEndpointConfig loads a preset the
// same way buildDrydockPresetHandler does, then overrides
// request_body.network.allow_endpoint_config to true before compiling the
// filter chain — simulating an operator who has explicitly opted into the
// macvlan/static-IP/MAC/DriverOpts escape hatch documented in the preset
// header comments, without needing a second on-disk preset variant just for
// this one test.
func buildDrydockPresetHandlerWithNetworkAllowEndpointConfig(t *testing.T, presetFile string) http.Handler {
	t.Helper()

	cfg, err := config.Load(filepath.Join("..", "..", "configs", presetFile))
	if err != nil {
		t.Fatalf("load preset %s: %v", presetFile, err)
	}
	cfg.RequestBody.Network.AllowEndpointConfig = true

	return drydockPresetHandlerFromConfig(t, cfg)
}

// drydockPresetHandlerFromConfig assembles the filter middleware the way
// serve.go does (rules + request-body inspectors) from an already-loaded
// preset config, wrapping a stub upstream that 200s when a request is
// allowed through. Shared by buildDrydockPresetHandler and its
// allow-endpoint-config-override sibling so both build the handler
// identically apart from the one field they intentionally differ on.
func drydockPresetHandlerFromConfig(t *testing.T, cfg *config.Config) http.Handler {
	t.Helper()

	policy := cfg.RequestBody.ToFilterOptions()
	policy.DenyResponseVerbosity = filter.DenyResponseVerbosityVerbose
	// insecure_allow_body_blind_writes is a top-level Config field (not part
	// of RequestBodyConfig), wired at serve time by
	// internal/cmd/serve.go's attachRuntimeInspectors. Mirror that single
	// assignment here so preset conformance tests exercise the same
	// production wiring instead of a stub that always leaves it false.
	policy.Exec.AllowBlindWrites = cfg.InsecureAllowBodyBlindWrites
	opts := filter.Options{PolicyConfig: policy}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "allowed")
	})

	return filter.MiddlewareWithOptions(compileDrydockRules(t, cfg.Rules), logger, opts)(next)
}

// compileDrydockRules compiles a preset's YAML rules into filter matchers,
// mirroring the production rule pipeline (comma-split methods, first-match-wins).
func compileDrydockRules(t *testing.T, rules []config.RuleConfig) []*filter.CompiledRule {
	t.Helper()

	compiled := make([]*filter.CompiledRule, 0, len(rules))
	for i, rule := range rules {
		methods := make([]string, 0, 2)
		for _, part := range strings.Split(rule.Match.Method, ",") {
			if m := strings.TrimSpace(part); m != "" {
				methods = append(methods, m)
			}
		}
		cr, err := filter.CompileRule(filter.Rule{
			Methods: methods,
			Pattern: rule.Match.Path,
			Action:  filter.Action(rule.Action),
			Reason:  rule.Reason,
			Index:   i,
		})
		if err != nil {
			t.Fatalf("compile rule %d (%s %s): %v", i, rule.Match.Method, rule.Match.Path, err)
		}
		compiled = append(compiled, cr)
	}
	return compiled
}

// fireDrydockCase drives one request through the preset handler and asserts the
// allow/deny verdict. A filter denial (rule layer or body inspector) returns 403;
// anything else means the request reached the stub upstream (allowed).
func fireDrydockCase(t *testing.T, handler http.Handler, c presetCase) {
	t.Helper()

	var body io.Reader
	if c.body != "" {
		body = strings.NewReader(c.body)
	}
	req := httptest.NewRequest(c.method, c.path, body)
	if c.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	allowed := rec.Code != http.StatusForbidden
	if allowed == c.allowed {
		return
	}
	verb := "denied"
	if allowed {
		verb = "allowed"
	}
	t.Errorf("%s: %s %s was %s (status %d, body %q); want allowed=%v",
		c.name, c.method, c.path, verb, rec.Code, strings.TrimSpace(rec.Body.String()), c.allowed)
}
