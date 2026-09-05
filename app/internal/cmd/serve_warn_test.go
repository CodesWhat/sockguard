package cmd

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/upstream"
)

// warnLabelACLOnce must fire only when container-label ACLs are enabled, and
// only once per Once even though the handler chain (and therefore the call
// site) is rebuilt on every config hot-reload.
func TestWarnLabelACLOnce(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var once sync.Once

	disabled := config.Defaults()
	warnLabelACLOnce(&disabled, logger, &once)
	if buf.Len() != 0 {
		t.Fatalf("disabled config logged: %q", buf.String())
	}

	enabled := config.Defaults()
	enabled.Clients.ContainerLabels.Enabled = true
	warnLabelACLOnce(&enabled, logger, &once)
	if got := strings.Count(buf.String(), "container-label ACLs are enabled"); got != 1 {
		t.Fatalf("warning count after first enabled build = %d, want 1; log: %q", got, buf.String())
	}

	// Simulate the chain rebuild a hot-reload performs: same process, same
	// Once, enabled again — must NOT log a second time.
	warnLabelACLOnce(&enabled, logger, &once)
	if got := strings.Count(buf.String(), "container-label ACLs are enabled"); got != 1 {
		t.Fatalf("warning count after reload rebuild = %d, want still 1; log: %q", got, buf.String())
	}

	// A fresh Once (fresh process) with the feature enabled warns again.
	var fresh sync.Once
	buf.Reset()
	warnLabelACLOnce(&enabled, logger, &fresh)
	if got := strings.Count(buf.String(), "container-label ACLs are enabled"); got != 1 {
		t.Fatalf("warning count with fresh Once = %d, want 1; log: %q", got, buf.String())
	}
}

// warnBodyBlindWritesOnce must fire only when insecure_allow_body_blind_writes
// is enabled, and only once per Once across reload chain rebuilds — mirroring
// TestWarnLabelACLOnce for the analogous startup-acknowledgment warning.
func TestWarnBodyBlindWritesOnce(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var once sync.Once

	disabled := config.Defaults()
	warnBodyBlindWritesOnce(&disabled, logger, &once)
	if buf.Len() != 0 {
		t.Fatalf("disabled config logged: %q", buf.String())
	}

	enabled := config.Defaults()
	enabled.InsecureAllowBodyBlindWrites = true
	warnBodyBlindWritesOnce(&enabled, logger, &once)
	if got := strings.Count(buf.String(), "insecure_allow_body_blind_writes is enabled"); got != 1 {
		t.Fatalf("warning count after first enabled build = %d, want 1; log: %q", got, buf.String())
	}

	// Simulate the chain rebuild a hot-reload performs: same process, same
	// Once, enabled again — must NOT log a second time.
	warnBodyBlindWritesOnce(&enabled, logger, &once)
	if got := strings.Count(buf.String(), "insecure_allow_body_blind_writes is enabled"); got != 1 {
		t.Fatalf("warning count after reload rebuild = %d, want still 1; log: %q", got, buf.String())
	}

	// A fresh Once (fresh process) with the feature enabled warns again.
	var fresh sync.Once
	buf.Reset()
	warnBodyBlindWritesOnce(&enabled, logger, &fresh)
	if got := strings.Count(buf.String(), "insecure_allow_body_blind_writes is enabled"); got != 1 {
		t.Fatalf("warning count with fresh Once = %d, want 1; log: %q", got, buf.String())
	}
}

// warnReadExfiltrationOnce must fire only when
// insecure_allow_read_exfiltration is enabled, only once per Once across
// reload chain rebuilds, and must name the exfiltration endpoints the current
// rule set actually admits — mirroring TestWarnBodyBlindWritesOnce for the
// read-side acknowledgment.
func TestWarnReadExfiltrationOnce(t *testing.T) {
	t.Parallel()

	const marker = "insecure_allow_read_exfiltration is enabled"

	broadRules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: "GET", Path: "/containers/**"}, Action: "allow"},
	}
	broad, err := compileConfiguredRules(broadRules)
	if err != nil {
		t.Fatalf("compileConfiguredRules: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var once sync.Once

	disabled := config.Defaults()
	disabled.Rules = broadRules
	warnReadExfiltrationOnce(&disabled, broad, nil, logger, &once)
	if buf.Len() != 0 {
		t.Fatalf("disabled config logged: %q", buf.String())
	}

	enabled := config.Defaults()
	enabled.InsecureAllowReadExfiltration = true
	enabled.Rules = broadRules
	warnReadExfiltrationOnce(&enabled, broad, nil, logger, &once)
	if got := strings.Count(buf.String(), marker); got != 1 {
		t.Fatalf("warning count after first enabled build = %d, want 1; log: %q", got, buf.String())
	}
	for _, want := range []string{"process-list", "process arguments"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("warning does not describe %q exposure; log: %q", want, buf.String())
		}
	}
	// The warning names what the acknowledgment is currently buying, sourced
	// from the same probe the startup validator uses for its refusal message.
	for _, want := range []string{
		"GET /containers/sockguard-test/archive",
		"GET /containers/sockguard-test/export",
		"GET /containers/sockguard-test/logs",
		"GET /containers/sockguard-test/attach/ws",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("warning does not name %q; log: %q", want, buf.String())
		}
	}

	// Simulate the chain rebuild a hot-reload performs: same process, same
	// Once, enabled again — must NOT log a second time.
	warnReadExfiltrationOnce(&enabled, broad, nil, logger, &once)
	if got := strings.Count(buf.String(), marker); got != 1 {
		t.Fatalf("warning count after reload rebuild = %d, want still 1; log: %q", got, buf.String())
	}

	// A fresh Once (fresh process) with the feature enabled warns again.
	var fresh sync.Once
	buf.Reset()
	warnReadExfiltrationOnce(&enabled, broad, nil, logger, &fresh)
	if got := strings.Count(buf.String(), marker); got != 1 {
		t.Fatalf("warning count with fresh Once = %d, want 1; log: %q", got, buf.String())
	}

	// The acknowledgment set while no rule needs it still warns, with an empty
	// endpoint list — that combination is a standing permission worth removing.
	narrowRules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: "GET", Path: "/containers/json"}, Action: "allow"},
	}
	narrow, err := compileConfiguredRules(narrowRules)
	if err != nil {
		t.Fatalf("compileConfiguredRules: %v", err)
	}
	var narrowOnce sync.Once
	buf.Reset()
	narrowCfg := enabled
	narrowCfg.Rules = narrowRules
	warnReadExfiltrationOnce(&narrowCfg, narrow, nil, logger, &narrowOnce)
	if got := strings.Count(buf.String(), marker); got != 1 {
		t.Fatalf("warning count for narrow rules = %d, want 1; log: %q", got, buf.String())
	}
	if strings.Contains(buf.String(), "sockguard-test") {
		t.Fatalf("narrow rules named an exposed endpoint; log: %q", buf.String())
	}

	// The acknowledgment is global, so a named client profile can be the only
	// reason it is set. Profile rules are evaluated in place of the top-level
	// set and the per-profile startup refusal never fires once the
	// acknowledgment is present, so a top-level-only report would show an
	// empty list for a config that is genuinely exposed.
	profiles := map[string]filter.Policy{"zeta-reader": {Rules: broad}, "alpha-reader": {Rules: broad}}
	profileCfg := narrowCfg
	profileCfg.Clients.Profiles = []config.ClientProfileConfig{
		{Name: "zeta-reader", Rules: broadRules},
		{Name: "alpha-reader", Rules: broadRules},
	}
	var profileOnce sync.Once
	buf.Reset()
	warnReadExfiltrationOnce(&profileCfg, narrow, profiles, logger, &profileOnce)
	if got := strings.Count(buf.String(), marker); got != 1 {
		t.Fatalf("warning count for profile rules = %d, want 1; log: %q", got, buf.String())
	}
	for _, want := range []string{
		"alpha-reader: GET /containers/sockguard-test/archive",
		"zeta-reader: GET /containers/sockguard-test/logs",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("warning does not name %q; log: %q", want, buf.String())
		}
	}
	// Profile names come out of a map, so the field has to be sorted or it
	// reorders between runs and this test flakes instead of failing.
	if alpha, zeta := strings.Index(buf.String(), "alpha-reader"), strings.Index(buf.String(), "zeta-reader"); alpha > zeta {
		t.Fatalf("profile endpoints are not sorted by profile name; log: %q", buf.String())
	}
}

func TestWarnReadExfiltrationRetainsShadowedTopLevelRoute(t *testing.T) {
	t.Parallel()

	configured := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/sockguard-test/push"}, Action: "deny"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/team/**"}, Action: "allow"},
	}
	rules, err := compileConfiguredRules(configured)
	if err != nil {
		t.Fatalf("compileConfiguredRules: %v", err)
	}

	cfg := config.Defaults()
	cfg.InsecureAllowReadExfiltration = true
	cfg.Rules = configured
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var once sync.Once
	warnReadExfiltrationOnce(&cfg, rules, nil, logger, &once)

	if !strings.Contains(buf.String(), "POST /libpod/images/team/push") {
		t.Fatalf("warning lost reachable push route behind a denied representative; log: %q", buf.String())
	}
}

func TestWarnReadExfiltrationRetainsShadowedProfileRoute(t *testing.T) {
	t.Parallel()

	configured := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/sockguard-test/push"}, Action: "deny"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/*/images/team/*/push"}, Action: "allow"},
	}
	rules, err := compileConfiguredRules(configured)
	if err != nil {
		t.Fatalf("compileConfiguredRules: %v", err)
	}

	cfg := config.Defaults()
	cfg.InsecureAllowReadExfiltration = true
	cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "publisher", Rules: configured}}
	profiles := map[string]filter.Policy{"publisher": {Rules: rules}}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var once sync.Once
	warnReadExfiltrationOnce(&cfg, nil, profiles, logger, &once)

	if !strings.Contains(buf.String(), "publisher: POST /libpod/images/team/a/push") {
		t.Fatalf("warning lost reachable profile push route behind a denied representative; log: %q", buf.String())
	}
}

func TestWarnReadExfiltrationReportsExactLibpodImagePushRepresentativeOnce(t *testing.T) {
	t.Parallel()

	topLevelRules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/sockguard-test/push"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	compiledTopLevel, err := compileConfiguredRules(topLevelRules)
	if err != nil {
		t.Fatalf("compileConfiguredRules(top-level): %v", err)
	}
	profileRules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/images/scp/sockguard-test/push"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	compiledProfile, err := compileConfiguredRules(profileRules)
	if err != nil {
		t.Fatalf("compileConfiguredRules(profile): %v", err)
	}

	cfg := config.Defaults()
	cfg.InsecureAllowReadExfiltration = true
	cfg.Rules = topLevelRules
	cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "publisher", Rules: profileRules}}
	profiles := map[string]filter.Policy{"publisher": {Rules: compiledProfile}}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var once sync.Once
	warnReadExfiltrationOnce(&cfg, compiledTopLevel, profiles, logger, &once)

	for _, endpoint := range []string{
		"POST /libpod/images/sockguard-test/push",
		"publisher: POST /libpod/images/scp/sockguard-test/push",
	} {
		if got := strings.Count(buf.String(), endpoint); got != 1 {
			t.Fatalf("warning count for %q = %d, want 1; log: %q", endpoint, got, buf.String())
		}
	}
}

func TestWarnReadExfiltrationOncePreservesShadowedRouteDetection(t *testing.T) {
	t.Parallel()

	topLevelRules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/sockguard-test/archive"}, Action: "deny"},
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/*/archive"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	topLevelCompiled, err := compileConfiguredRules(topLevelRules)
	if err != nil {
		t.Fatalf("compile top-level rules: %v", err)
	}
	profileRules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/sockguard-test/checkpoint"}, Action: "deny"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/checkpoint"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	profileCompiled, err := compileConfiguredRules(profileRules)
	if err != nil {
		t.Fatalf("compile profile rules: %v", err)
	}

	cfg := config.Defaults()
	cfg.InsecureAllowReadExfiltration = true
	cfg.Rules = topLevelRules
	cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "backup-reader", Rules: profileRules}}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var once sync.Once
	warnReadExfiltrationOnce(&cfg, topLevelCompiled, map[string]filter.Policy{
		"backup-reader": {Rules: profileCompiled},
	}, logger, &once)

	for _, want := range []string{
		"GET /containers/a/archive",
		"backup-reader: POST /libpod/containers/a/checkpoint",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("warning does not name reachable route %q after representative shadow; log: %q", want, buf.String())
		}
	}
}

func TestWarnReadExfiltrationOnceDescribesCheckpointAndMountRisks(t *testing.T) {
	t.Parallel()

	rules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/checkpoint"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	compiled, err := compileConfiguredRules(rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	cfg := config.Defaults()
	cfg.InsecureAllowReadExfiltration = true
	cfg.Rules = rules

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var once sync.Once
	warnReadExfiltrationOnce(&cfg, compiled, nil, logger, &once)

	for _, want := range []string{
		"raw archive/export",
		"log/attach streaming",
		"checkpoint export",
		"container rootfs mount",
		"registry push",
		"container memory",
		"daemon-host filesystem paths",
		"POST /libpod/containers/sockguard-test/checkpoint",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("warning does not describe %q; log: %q", want, buf.String())
		}
	}
}

// TestWarnReadExfiltrationOnceNamesExactNameProcessListRule pins the audit
// that actually runs: allowedSensitiveExfilEndpoints searches the catalog's
// route language against the authored rule literals, so an exact container
// name is found and reported rather than left to the request-time gate. The
// configured and compiled rule sets have to be the same policy for the
// assertion to mean anything — feeding config.Defaults() alongside a disjoint
// compiled set makes an empty endpoint list vacuous.
func TestWarnReadExfiltrationOnceNamesExactNameProcessListRule(t *testing.T) {
	t.Parallel()

	rules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/containers/payments/top"}, Action: "allow"},
	}
	compiled, err := compileConfiguredRules(rules)
	if err != nil {
		t.Fatalf("compileConfiguredRules: %v", err)
	}

	enabled := config.Defaults()
	enabled.InsecureAllowReadExfiltration = true
	enabled.Rules = rules

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var once sync.Once
	warnReadExfiltrationOnce(&enabled, compiled, nil, logger, &once)
	logOutput := buf.String()

	if !strings.Contains(logOutput, "process-list reads allowed by policy are admitted instead of denied at request time") {
		t.Fatalf("warning does not describe request-time process-list enforcement; log: %q", logOutput)
	}
	if !strings.Contains(logOutput, "GET /containers/payments/top") {
		t.Fatalf("warning does not name the exact-name process-list rule the literal audit reaches; log: %q", logOutput)
	}
}

// withFilter must actually call warnIfReadExfiltrationEnabled. Every other
// assertion about this warning drives warnReadExfiltrationOnce directly with
// an injected Once, so the chain-build call site is the one part of the
// feature no test touches: deleting that line leaves the whole suite green
// while the running proxy emits nothing. This test is deliberately not
// parallel and resets the package-level Once, which is safe because no other
// test in this package builds a filter chain with the acknowledgment set.
func TestWithFilterWarnsReadExfiltration(t *testing.T) {
	readExfiltrationWarnOnce = sync.Once{}
	t.Cleanup(func() { readExfiltrationWarnOnce = sync.Once{} })

	rules, err := compileConfiguredRules([]config.RuleConfig{
		{Match: config.MatchConfig{Method: "GET", Path: "/containers/**"}, Action: "allow"},
	})
	if err != nil {
		t.Fatalf("compileConfiguredRules: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	cfg := config.Defaults()
	cfg.InsecureAllowReadExfiltration = true
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: "GET", Path: "/containers/**"}, Action: "allow"},
	}
	cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "broad-reader", Rules: cfg.Rules}}
	withFilter(&cfg, nil, logger, rules, map[string]filter.Policy{"broad-reader": {Rules: rules}})

	if got := strings.Count(buf.String(), "insecure_allow_read_exfiltration is enabled"); got != 1 {
		t.Fatalf("chain build warning count = %d, want 1; log: %q", got, buf.String())
	}
	if !strings.Contains(buf.String(), "GET /containers/sockguard-test/archive") {
		t.Fatalf("chain build warning does not name the exposed endpoint; log: %q", buf.String())
	}
	// withFilter must hand its clientProfiles map to the warning, not just its
	// top-level rules.
	if !strings.Contains(buf.String(), "broad-reader: GET /containers/sockguard-test/archive") {
		t.Fatalf("chain build warning does not name the exposed profile endpoint; log: %q", buf.String())
	}

	// A chain rebuilt without the acknowledgment must stay silent, so the
	// call site is gated by the flag rather than logging unconditionally.
	buf.Reset()
	readExfiltrationWarnOnce = sync.Once{}
	clean := config.Defaults()
	withFilter(&clean, nil, logger, rules, map[string]filter.Policy{"broad-reader": {Rules: rules}})
	if strings.Contains(buf.String(), "insecure_allow_read_exfiltration is enabled") {
		t.Fatalf("chain build without the acknowledgment logged: %q", buf.String())
	}
}

// warnOpaqueBuildkitTunnelDeprecatedOnce must fire only when
// insecure_accept_opaque_buildkit_tunnels is enabled, and only once per Once
// across reload chain rebuilds — mirroring TestWarnBodyBlindWritesOnce for
// the analogous startup-acknowledgment warning.
func TestWarnOpaqueBuildkitTunnelDeprecatedOnce(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var once sync.Once

	disabled := config.Defaults()
	warnOpaqueBuildkitTunnelDeprecatedOnce(&disabled, logger, &once)
	if buf.Len() != 0 {
		t.Fatalf("disabled config logged: %q", buf.String())
	}

	enabled := config.Defaults()
	enabled.InsecureAcceptOpaqueBuildkitTunnels = true //nolint:staticcheck // SA1019: exercising the deprecated flag intentionally
	warnOpaqueBuildkitTunnelDeprecatedOnce(&enabled, logger, &once)
	if got := strings.Count(buf.String(), "insecure_accept_opaque_buildkit_tunnels is deprecated"); got != 1 {
		t.Fatalf("warning count after first enabled build = %d, want 1; log: %q", got, buf.String())
	}

	// Simulate the chain rebuild a hot-reload performs: same process, same
	// Once, enabled again — must NOT log a second time.
	warnOpaqueBuildkitTunnelDeprecatedOnce(&enabled, logger, &once)
	if got := strings.Count(buf.String(), "insecure_accept_opaque_buildkit_tunnels is deprecated"); got != 1 {
		t.Fatalf("warning count after reload rebuild = %d, want still 1; log: %q", got, buf.String())
	}

	// A fresh Once (fresh process) with the feature enabled warns again.
	var fresh sync.Once
	buf.Reset()
	warnOpaqueBuildkitTunnelDeprecatedOnce(&enabled, logger, &fresh)
	if got := strings.Count(buf.String(), "insecure_accept_opaque_buildkit_tunnels is deprecated"); got != 1 {
		t.Fatalf("warning count with fresh Once = %d, want 1; log: %q", got, buf.String())
	}
}

func TestWarnInsecureUpstreamSpecs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec upstream.EndpointSpec
		want string // substring expected in the log, "" means no log
	}{
		{name: "plain tcp", spec: upstream.EndpointSpec{Address: "tcp://daemon:2375", InsecureAllowPlainTCP: true}, want: "plaintext TCP"},
		{name: "skip verify", spec: upstream.EndpointSpec{Address: "tcp://daemon:2376", InsecureSkipTLSVerify: true}, want: "skips TLS certificate verification"},
		{name: "secure", spec: upstream.EndpointSpec{Address: "tcp://daemon:2376", CertFile: "c", KeyFile: "k"}, want: ""},
		{name: "unix socket", spec: upstream.EndpointSpec{Address: "/var/run/docker.sock"}, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))
			warnInsecureUpstreamSpecs(logger, []upstream.EndpointSpec{tt.spec}, "test")
			if tt.want == "" {
				if buf.Len() != 0 {
					t.Fatalf("expected no log, got %q", buf.String())
				}
				return
			}
			if !strings.Contains(buf.String(), tt.want) {
				t.Fatalf("log = %q, want substring %q", buf.String(), tt.want)
			}
		})
	}

	// A nil logger must be a safe no-op.
	warnInsecureUpstreamSpecs(nil, []upstream.EndpointSpec{{Address: "tcp://x:1", InsecureAllowPlainTCP: true}}, "test")
}
