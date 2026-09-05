package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/health"
	"github.com/codeswhat/sockguard/app/internal/imagetrust"
	"github.com/codeswhat/sockguard/app/internal/ui"
	"github.com/codeswhat/sockguard/app/internal/version"
)

// Check names, in the order they run. They are part of the --json contract:
// a scripted caller keys off these strings, so they are constants rather than
// inline literals at each construction site.
const (
	verifyCheckNameConfig     = "config"
	verifyCheckNameUpstream   = "upstream"
	verifyCheckNameListener   = "listener"
	verifyCheckNameTLS        = "tls"
	verifyCheckNameImageTrust = "image-trust"
)

// Per-check outcomes. "skip" is not a failure and never changes the exit
// code: it records a check that does not apply to this deployment — an opt-in
// feature left off, a listener that is not running — so the report carries one
// line per check either way and a caller diffing two runs sees a check appear
// or disappear rather than a line vanish.
const (
	verifyStatusOK   = "ok"
	verifyStatusFail = "fail"
	verifyStatusSkip = "skip"
)

// verifyListenerProbeTimeout bounds the GET <health.path> issued against each
// configured sockguard listener, so a listener that accepts the connection and
// then never answers is reported as not up instead of hanging the command.
const verifyListenerProbeTimeout = 3 * time.Second

// loadImageTrustRoot fetches the TUF-backed Sigstore trust root that keyless
// image-trust identities verify against. Package var of the same shape as
// loadBundleTrustedMaterial, so a test can make the fetch fail without a
// network; production binds imagetrust.LoadLiveTrustedRoot, the same function
// internal/filter calls on the request path.
var loadImageTrustRoot = imagetrust.LoadLiveTrustedRoot

var verifyJSONOutput bool

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Run runtime self-checks against the effective configuration",
	Long: `Load the configuration the way serve does (flags, environment, file) and check
that the things it names are actually reachable right now.

Where validate is an offline check on a config file, verify is a runtime check
on a deployment: it probes the upstream Docker daemon, the sockguard listener's
own health endpoint, the TLS material on disk, and the image-trust trust root.
It runs five checks and prints one line each with ok, fail, or skip. A skip is
a check that does not apply (an opt-in feature that is off, a listener that is
not up) and does not affect the exit code; any fail exits non-zero.

Use --json for a machine-readable report.`,
	RunE: runVerify,
	// A failing check is a report, not a usage error, so the failure must not
	// bury the per-check lines under the usage string.
	SilenceUsage: true,
}

func init() {
	rootCmd.AddCommand(verifyCmd)

	verifyCmd.Flags().BoolVar(&verifyJSONOutput, "json", false, "emit the report as JSON instead of one line per check")
	// The two serve flags that change what verify probes. The remaining serve
	// overrides (log level/format, deny verbosity) select behavior verify does
	// not exercise, so registering them here would imply a check that is not run.
	verifyCmd.Flags().String("listen-socket", "", "proxy socket path (overrides config)")
	verifyCmd.Flags().String("upstream-socket", "", "Docker socket path (overrides config)")
}

// verifyCheck is one line of the report.
type verifyCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// verifyReport is the whole report, and the --json document.
type verifyReport struct {
	Config  string        `json:"config"`
	Version string        `json:"version"`
	Status  string        `json:"status"`
	Checks  []verifyCheck `json:"checks"`
}

func verifyResult(name, status, detail string) verifyCheck {
	return verifyCheck{Name: name, Status: status, Detail: detail}
}

func runVerify(cmd *cobra.Command, args []string) error {
	return runVerifyWithDeps(cmd, newServeDeps())
}

func runVerifyWithDeps(cmd *cobra.Command, deps *serveDeps) error {
	report := buildVerifyReport(cmd, deps)

	out := cmd.OutOrStdout()
	if verifyJSONOutput {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			return fmt.Errorf("encode verify report: %w", err)
		}
	} else {
		writeVerifyText(out, report)
	}

	if report.Status == verifyStatusFail {
		return fmt.Errorf("verify failed: %d of %d checks failed", countVerifyFailures(report.Checks), len(report.Checks))
	}
	return nil
}

// buildVerifyReport runs every check and assembles the report. A check never
// aborts the run: an operator with a dark daemon still wants to know whether
// the certificates load.
func buildVerifyReport(cmd *cobra.Command, deps *serveDeps) verifyReport {
	report := verifyReport{Config: cfgFile, Version: version.Version}

	cfg, configCheck := verifyLoadConfig(cmd, deps)
	report.Checks = append(report.Checks, configCheck)

	if cfg == nil {
		// Every later check reads the config, so they cannot run — but they
		// stay in the report as skips so the check list is the same length
		// and the same order on every run.
		const detail = "skipped because the configuration did not load"
		for _, name := range []string{verifyCheckNameUpstream, verifyCheckNameListener, verifyCheckNameTLS, verifyCheckNameImageTrust} {
			report.Checks = append(report.Checks, verifyResult(name, verifyStatusSkip, detail))
		}
		report.Status = verifyOverallStatus(report.Checks)
		return report
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	report.Checks = append(report.Checks,
		verifyUpstreamCheck(ctx, deps, cfg),
		verifyListenerCheck(ctx, deps, cfg),
		verifyTLSCheck(cfg),
		verifyImageTrustCheck(cfg),
	)
	report.Status = verifyOverallStatus(report.Checks)
	return report
}

func verifyOverallStatus(checks []verifyCheck) string {
	for _, check := range checks {
		if check.Status == verifyStatusFail {
			return verifyStatusFail
		}
	}
	return verifyStatusOK
}

func countVerifyFailures(checks []verifyCheck) int {
	failures := 0
	for _, check := range checks {
		if check.Status == verifyStatusFail {
			failures++
		}
	}
	return failures
}

// verifyLoadConfig loads the effective config through the same steps serve
// takes — preflight, file + SOCKGUARD_* env via config.Load, flag overrides,
// Tecnativa compat expansion — and then validates it STRUCTURALLY. The
// file-touching half of validation is the tls check below, so a config whose
// rules are fine but whose certificate is missing reports one ok and one fail
// rather than a single opaque failure.
func verifyLoadConfig(cmd *cobra.Command, deps *serveDeps) (*config.Config, verifyCheck) {
	if err := requireExplicitConfigFile(cmd, cfgFile); err != nil {
		return nil, verifyResult(verifyCheckNameConfig, verifyStatusFail, fmt.Sprintf("config preflight: %v", err))
	}

	cfg, err := deps.loadConfig(cfgFile)
	if err != nil {
		return nil, verifyResult(verifyCheckNameConfig, verifyStatusFail, fmt.Sprintf("config load: %v", err))
	}
	if err := applyFlagOverrides(cmd, cfg); err != nil {
		return nil, verifyResult(verifyCheckNameConfig, verifyStatusFail, fmt.Sprintf("apply flag overrides: %v", err))
	}

	compatActive := config.ApplyCompat(cfg, discardLogger)

	compiled, err := validateAndCompileRulesStructural(cfg)
	if err != nil {
		return nil, verifyResult(verifyCheckNameConfig, verifyStatusFail, fmt.Sprintf("config validation: %v", err))
	}

	detail := fmt.Sprintf("%s loaded, %d rules, %d client profiles", cfgFile, len(compiled), len(cfg.Clients.Profiles))
	if compatActive {
		detail += ", tecnativa compatibility active"
	}
	return cfg, verifyResult(verifyCheckNameConfig, verifyStatusOK, detail)
}

// verifyUpstreamCheck reproduces serve's upstream startup sequence: build the
// resolver (which loads any per-endpoint TLS material), run the same
// reachability probe, then ask the Docker API itself. The readiness probe
// comes from internal/health, so verify and /health agree on what "the daemon
// answers" means, and the flavor probe is the one serve resolves policy
// semantics from, so a deployment on upstream.flavor: auto learns here whether
// that probe works rather than at the next restart.
func verifyUpstreamCheck(ctx context.Context, deps *serveDeps, cfg *config.Config) verifyCheck {
	resolver, legacySocket, err := buildUpstreamResolver(cfg, discardLogger, os.LookupEnv)
	if err != nil {
		return verifyResult(verifyCheckNameUpstream, verifyStatusFail, fmt.Sprintf("upstream endpoint: %v", err))
	}
	label := upstreamLabel(resolver)

	if legacySocket {
		err = deps.verifyUpstreamReachable(cfg.Upstream.Socket, discardLogger)
	} else {
		probeCtx, cancel := context.WithTimeout(ctx, upstreamReachableTimeout)
		err = resolver.CheckReachable(probeCtx)
		cancel()
	}
	if err != nil {
		return verifyResult(verifyCheckNameUpstream, verifyStatusFail, fmt.Sprintf("%s is not reachable: %v", label, err))
	}

	monitor := health.NewReadinessMonitorWithRoundTripper(label, resolver, time.Now(), discardLogger, 0)
	state := monitor.Probe(ctx)
	if state.Err != nil {
		return verifyResult(verifyCheckNameUpstream, verifyStatusFail,
			fmt.Sprintf("%s accepts connections but does not answer the Docker API: %v", label, state.Err))
	}

	flavor, err := resolveUpstreamFlavor(ctx, deps, cfg, resolver, discardLogger)
	if err != nil {
		return verifyResult(verifyCheckNameUpstream, verifyStatusFail, fmt.Sprintf("upstream flavor: %v", err))
	}

	return verifyResult(verifyCheckNameUpstream, verifyStatusOK,
		fmt.Sprintf("%s reachable, Docker API %s, flavor %s", label, state.Status, flavor))
}

// verifyListenerCheck probes every effective listener's health endpoint. A
// listener that is not up is a skip, not a failure: verify is meant to be
// usable before the proxy starts as well as against a running one. A listener
// that IS up and answers anything other than 200 is a failure, because that is
// the proxy telling us it is unhealthy.
func verifyListenerCheck(ctx context.Context, deps *serveDeps, cfg *config.Config) verifyCheck {
	if !cfg.Health.Enabled {
		return verifyResult(verifyCheckNameListener, verifyStatusSkip,
			"health.enabled is false, so no listener exposes a health endpoint to probe")
	}
	if cfg.Health.Path == "" {
		return verifyResult(verifyCheckNameListener, verifyStatusSkip, "health.path is empty, so there is no endpoint to probe")
	}

	listeners := cfg.EffectiveListeners()
	details := make([]string, 0, len(listeners))
	status := verifyStatusSkip
	for _, listener := range listeners {
		result, detail := verifyProbeListener(ctx, deps, listener, cfg.Health.Path)
		details = append(details, detail)
		switch {
		case result == verifyStatusFail:
			status = verifyStatusFail
		case result == verifyStatusOK && status == verifyStatusSkip:
			status = verifyStatusOK
		}
	}
	return verifyResult(verifyCheckNameListener, status, strings.Join(details, "; "))
}

func verifyProbeListener(ctx context.Context, deps *serveDeps, listener config.ListenerConfig, healthPath string) (status, detail string) {
	var network, address, display string
	switch {
	case listener.Socket != "":
		if _, err := deps.statPath(listener.Socket); err != nil {
			return verifyStatusSkip, fmt.Sprintf("%s: unix:%s is not present, so the listener is not up", listener.Name, listener.Socket)
		}
		network, address, display = "unix", listener.Socket, "unix:"+listener.Socket
	case listener.Address == "":
		return verifyStatusSkip, fmt.Sprintf("%s: neither socket nor address is configured", listener.Name)
	case listener.TLS.Complete():
		// The listener requires a client certificate and verify holds none.
		// The listener's own server certificate is not a client credential,
		// so there is nothing to present and nothing to report but a skip.
		return verifyStatusSkip, fmt.Sprintf("%s: tcp://%s requires a client certificate, which verify does not hold", listener.Name, listener.Address)
	default:
		network, address, display = "tcp", listener.Address, "tcp://"+listener.Address
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, address)
			},
		},
		Timeout: verifyListenerProbeTimeout,
	}
	defer client.CloseIdleConnections()

	// The host is a placeholder: the dialer above ignores it and connects to
	// the configured socket or address.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://sockguard"+healthPath, nil)
	if err != nil {
		return verifyStatusFail, fmt.Sprintf("%s: build %s request: %v", listener.Name, healthPath, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return verifyStatusSkip, fmt.Sprintf("%s: %s is not answering, so the listener is not up (%v)", listener.Name, display, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return verifyStatusFail, fmt.Sprintf("%s: GET %s on %s returned HTTP %d", listener.Name, healthPath, display, resp.StatusCode)
	}
	return verifyStatusOK, fmt.Sprintf("%s: GET %s on %s answered HTTP 200", listener.Name, healthPath, display)
}

// verifyTLSTarget is one config block whose certificate material verify loads.
type verifyTLSTarget struct {
	field string
	tls   config.ListenTLSConfig
}

// verifyTLSTargets collects the mutual-TLS blocks the offline validator would
// open, mirroring its gating exactly: only TCP listeners, only blocks with
// cert, key and client CA all set, and the admin listener only when admin is
// enabled on a dedicated TCP address.
func verifyTLSTargets(cfg *config.Config) []verifyTLSTarget {
	var targets []verifyTLSTarget
	if len(cfg.Listeners) > 0 {
		for i, listener := range cfg.Listeners {
			label := fmt.Sprintf("listeners[%d]", i)
			if listener.Name != "" {
				label = fmt.Sprintf("listeners[%s]", listener.Name)
			}
			if listener.Socket == "" && listener.TLS.Complete() {
				targets = append(targets, verifyTLSTarget{field: label + ".tls", tls: listener.TLS})
			}
		}
	} else if cfg.Listen.Socket == "" && cfg.Listen.TLS.Complete() {
		targets = append(targets, verifyTLSTarget{field: "listen.tls", tls: cfg.Listen.TLS})
	}
	if cfg.Admin.Enabled && cfg.Admin.Listen.Address != "" && cfg.Admin.Listen.TLS.Complete() {
		targets = append(targets, verifyTLSTarget{field: "admin.listen.tls", tls: cfg.Admin.Listen.TLS})
	}
	return targets
}

// verifyTLSCheck is the filesystem half of validation, the half the admin
// API's structural validator deliberately never runs: it opens the cert, key
// and client CA each listener names. Here that is not a probing oracle — the
// operator running verify already has the filesystem.
func verifyTLSCheck(cfg *config.Config) verifyCheck {
	targets := verifyTLSTargets(cfg)
	if len(targets) == 0 {
		return verifyResult(verifyCheckNameTLS, verifyStatusSkip,
			"no listener configures mutual TLS, so there is no certificate material to load")
	}

	loaded := make([]string, 0, len(targets))
	for _, target := range targets {
		if _, err := config.BuildMutualTLSServerConfigForField(target.field, target.tls); err != nil {
			return verifyResult(verifyCheckNameTLS, verifyStatusFail, err.Error())
		}
		loaded = append(loaded, target.field)
	}
	return verifyResult(verifyCheckNameTLS, verifyStatusOK,
		fmt.Sprintf("certificate, key and client CA load for %s", strings.Join(loaded, ", ")))
}

// verifyImageTrustTarget is one image_trust block that is switched on.
type verifyImageTrustTarget struct {
	field string
	trust config.ImageTrustConfig
}

func verifyImageTrustTargets(cfg *config.Config) []verifyImageTrustTarget {
	targets := appendImageTrustTargets(nil, "request_body", cfg.RequestBody)
	for _, profile := range cfg.Clients.Profiles {
		targets = appendImageTrustTargets(targets, fmt.Sprintf("clients.profiles[%s].request_body", profile.Name), profile.RequestBody)
	}
	return targets
}

func appendImageTrustTargets(targets []verifyImageTrustTarget, prefix string, body config.RequestBodyConfig) []verifyImageTrustTarget {
	for _, candidate := range []verifyImageTrustTarget{
		{field: prefix + ".container_create.image_trust", trust: body.ContainerCreate.ImageTrust},
		{field: prefix + ".libpod_container_create.image_trust", trust: body.LibpodContainerCreate.ImageTrust},
		{field: prefix + ".service.image_trust", trust: body.Service.ImageTrust},
	} {
		if mode := imagetrust.Mode(candidate.trust.Mode); mode != imagetrust.ModeOff && mode != "" {
			targets = append(targets, candidate)
		}
	}
	return targets
}

// verifyImageTrustCheck reports whether image trust can reach the trust root
// it needs. Only keyless identities need one — a keyed-only policy verifies
// against PEM keys in the config and touches no network — so a keyed-only
// deployment is reported as ok with that stated, not as a skip.
func verifyImageTrustCheck(cfg *config.Config) verifyCheck {
	targets := verifyImageTrustTargets(cfg)
	if len(targets) == 0 {
		return verifyResult(verifyCheckNameImageTrust, verifyStatusSkip,
			"image trust is opt-in and every image_trust.mode is off")
	}

	keyless := make([]string, 0, len(targets))
	for _, target := range targets {
		if len(target.trust.AllowedKeyless) > 0 {
			keyless = append(keyless, target.field)
		}
	}
	if len(keyless) == 0 {
		return verifyResult(verifyCheckNameImageTrust, verifyStatusOK,
			fmt.Sprintf("%s verify against configured signing keys, which need no Sigstore trust root", strings.Join(imageTrustFields(targets), ", ")))
	}

	if _, err := loadImageTrustRoot(); err != nil {
		return verifyResult(verifyCheckNameImageTrust, verifyStatusFail,
			fmt.Sprintf("%s configure keyless identities but the Sigstore trust root did not load: %v", strings.Join(keyless, ", "), err))
	}
	return verifyResult(verifyCheckNameImageTrust, verifyStatusOK,
		fmt.Sprintf("%s reached the Sigstore trust root for their keyless identities", strings.Join(keyless, ", ")))
}

func imageTrustFields(targets []verifyImageTrustTarget) []string {
	fields := make([]string, len(targets))
	for i, target := range targets {
		fields[i] = target.field
	}
	return fields
}

func writeVerifyText(out io.Writer, report verifyReport) {
	p := ui.New(out)

	fmt.Fprintf(out, "  %s  %s\n", p.Dim("Config "), report.Config)
	fmt.Fprintf(out, "  %s  %s\n", p.Dim("Version"), report.Version)
	fmt.Fprintln(out)

	width := 0
	for _, check := range report.Checks {
		if len(check.Name) > width {
			width = len(check.Name)
		}
	}
	for _, check := range report.Checks {
		glyph, label := verifyStatusStyle(p, check.Status)
		// Pad the name before styling so ANSI escapes cannot eat visible
		// width; the status labels are padded to a fixed 4 for the same reason.
		fmt.Fprintf(out, "  %s %s  %s  %s\n", glyph, label, p.Dim(fmt.Sprintf("%-*s", width, check.Name)), check.Detail)
	}
	fmt.Fprintln(out)

	if report.Status == verifyStatusFail {
		fmt.Fprintf(out, "  %s %s\n", p.Red(ui.Cross), p.Red("verification failed"))
		return
	}
	fmt.Fprintf(out, "  %s %s\n", p.Green(ui.Check), p.Green("verification passed"))
}

func verifyStatusStyle(p *ui.Printer, status string) (glyph, label string) {
	switch status {
	case verifyStatusOK:
		return p.Green(ui.Check), p.Green("ok  ")
	case verifyStatusFail:
		return p.Red(ui.Cross), p.Red("fail")
	default:
		return p.Dim("-"), p.Dim("skip")
	}
}
