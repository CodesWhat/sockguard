package cmd

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/codeswhat/sockguard/internal/admin"

	"github.com/codeswhat/sockguard/internal/banner"
	"github.com/codeswhat/sockguard/internal/buildkitproxy"
	"github.com/codeswhat/sockguard/internal/clientacl"
	"github.com/codeswhat/sockguard/internal/config"

	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/health"
	"github.com/codeswhat/sockguard/internal/httpjson"

	"github.com/codeswhat/sockguard/internal/inbound"
	"github.com/codeswhat/sockguard/internal/logging"

	"github.com/codeswhat/sockguard/internal/metrics"

	"github.com/codeswhat/sockguard/internal/ownership"
	"github.com/codeswhat/sockguard/internal/policybundle"

	"github.com/codeswhat/sockguard/internal/proxy"
	"github.com/codeswhat/sockguard/internal/ratelimit"

	"github.com/codeswhat/sockguard/internal/reload"

	"github.com/codeswhat/sockguard/internal/responsefilter"
	"github.com/codeswhat/sockguard/internal/ui"
	"github.com/codeswhat/sockguard/internal/upstream"
	"github.com/codeswhat/sockguard/internal/version"

	"github.com/codeswhat/sockguard/internal/visibility"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/spf13/cobra"
	"io"
	"log/slog"

	"net"
	"net/http"
	"net/url"

	"os"

	"os/signal"
	"path/filepath"
	"runtime"

	"slices"
	"strings"
	"sync"

	"syscall"
	"time"
)

func requireExplicitConfigFile(cmd *cobra.Command, configPath string) error {
	flag := cmd.Flag("config")
	if flag == nil && cmd.Root() != nil {
		flag = cmd.Root().Flag("config")
	}
	if flag == nil || !flag.Changed {
		return nil
	}

	if strings.TrimSpace(configPath) == "" {
		return fmt.Errorf("config file path cannot be empty")
	}

	if _, err := os.Stat(configPath); err != nil {
		return fmt.Errorf("config file: %w", err)
	}
	return nil
}

const (
	matchOutputText = "text"
	matchOutputJSON = "json"
)

var (
	matchMethod string
	matchPath   string
	matchOutput string
)

var matchCmd = &cobra.Command{
	Use:   "match",
	Short: "Evaluate one request against the configured rules",
	Long:  "Load the effective configuration, normalize the request path, and report which rule would decide the request.",
	RunE:  runMatch,
}

type matchResult struct {
	Config         string           `json:"config"`
	Method         string           `json:"method"`
	Path           string           `json:"path"`
	NormalizedPath string           `json:"normalized_path"`
	Decision       string           `json:"decision"`
	Reason         string           `json:"reason,omitempty"`
	CompatMode     bool             `json:"compat_mode,omitempty"`
	MatchedRule    *matchedRuleInfo `json:"matched_rule,omitempty"`
}

type matchedRuleInfo struct {
	Index  int    `json:"index"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`
}

func init() {
	rootCmd.AddCommand(matchCmd)

	matchCmd.Flags().StringVarP(&matchMethod, "method", "X", "", "HTTP method to evaluate")
	matchCmd.Flags().StringVar(&matchPath, "path", "", "request path to evaluate")
	matchCmd.Flags().StringVarP(&matchOutput, "output", "o", matchOutputText, "output format: text or json")
	_ = matchCmd.MarkFlagRequired("method")
	_ = matchCmd.MarkFlagRequired("path")
}

func runMatch(cmd *cobra.Command, args []string) error {
	output := strings.ToLower(strings.TrimSpace(matchOutput))
	if output != matchOutputText && output != matchOutputJSON {
		return fmt.Errorf("unsupported output format %q (must be text or json)", matchOutput)
	}

	method := strings.ToUpper(strings.TrimSpace(matchMethod))
	path := strings.TrimSpace(matchPath)
	if method == "" {
		return fmt.Errorf("method is required")
	}
	if path == "" {
		return fmt.Errorf("path is required")
	}

	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("path must start with %q", "/")
	}

	if err := requireExplicitConfigFile(cmd, cfgFile); err != nil {
		return fmt.Errorf("config preflight: %w", err)
	}

	if cfgFile != "" {
		if _, err := os.Stat(cfgFile); err != nil {
			return fmt.Errorf("config file: %w", err)
		}
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("config load: %w", err)
	}

	compatActive := config.ApplyCompat(cfg, discardLogger)

	compiled, err := validateAndCompileRules(cfg)
	if err != nil {
		return fmt.Errorf("config validation: %w", err)
	}

	req := &http.Request{
		Method: method,
		URL:    &url.URL{Path: path},
	}
	decision, matchedRuleIndex, reason := filter.Evaluate(compiled, req)

	result := matchResult{
		Config:         cfgFile,
		Method:         method,
		Path:           path,
		NormalizedPath: filter.NormalizePath(path),
		Decision:       string(decision),
		Reason:         reason,
		CompatMode:     compatActive,
	}
	if matchedRuleIndex >= 0 && matchedRuleIndex < len(cfg.Rules) {
		rule := cfg.Rules[matchedRuleIndex]
		result.MatchedRule = &matchedRuleInfo{
			Index:  matchedRuleIndex + 1,
			Method: rule.Match.Method,
			Path:   rule.Match.Path,
			Action: rule.Action,
			Reason: rule.Reason,
		}
	}

	if output == matchOutputJSON {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
	}

	writeMatchText(cmd.OutOrStdout(), result)
	return nil
}

func writeMatchText(w io.Writer, result matchResult) {
	p := ui.New(w)

	label := func(s string) string { return p.Dim(fmt.Sprintf("%-16s", s)) }

	fmt.Fprintf(w, "%s %s\n", label("Config:"), result.Config)
	fmt.Fprintf(w, "%s %s\n", label("Method:"), result.Method)
	fmt.Fprintf(w, "%s %s\n", label("Path:"), result.Path)
	fmt.Fprintf(w, "%s %s\n", label("Normalized path:"), result.NormalizedPath)
	if result.CompatMode {
		fmt.Fprintf(w, "%s %s\n", label("Mode:"), "tecnativa compatibility")
	}
	fmt.Fprintln(w)

	decision := result.Decision
	if result.Decision == string(filter.ActionAllow) {
		decision = p.Green(decision)
	} else {
		decision = p.Red(decision)
	}
	fmt.Fprintf(w, "%s %s\n", label("Decision:"), decision)
	if result.MatchedRule == nil {
		fmt.Fprintf(w, "%s %s\n", label("Matched rule:"), "none")
	} else {
		action := result.MatchedRule.Action
		if result.MatchedRule.Action == string(filter.ActionAllow) {
			action = p.Green(action)
		} else {
			action = p.Red(action)
		}
		fmt.Fprintf(w, "%s #%d\n", label("Matched rule:"), result.MatchedRule.Index)
		fmt.Fprintf(w, "%s %s %s %s\n", label("Rule:"), action, result.MatchedRule.Method, result.MatchedRule.Path)
	}
	if result.Reason != "" {
		fmt.Fprintf(w, "%s %s\n", label("Reason:"), result.Reason)
	}
}

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "sockguard",
	Short: "Docker socket proxy — guide what gets through",
	Long: `Sockguard is a Docker socket proxy that filters API requests
by HTTP method, path, and request body content.

Default-deny posture ensures only explicitly allowed operations
reach the Docker daemon.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return serveCmd.RunE(cmd, args)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "/etc/sockguard/sockguard.yaml", "config file path (missing file falls back to built-in defaults + env overrides)")
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

var (
	validateConfig    = config.Validate
	compileFilterRule = filter.CompileRule
)

type bodySensitiveWriteEndpoint struct {
	method string
	path   string
}

type sensitiveExfilEndpoint struct {
	method string
	path   string
}

var bodySensitiveWriteEndpoints = []bodySensitiveWriteEndpoint{
	{method: http.MethodPost, path: "/containers/sockguard-test/exec"},
	{method: http.MethodPost, path: "/exec/sockguard-test/start"},
	{method: http.MethodPost, path: "/containers/sockguard-test/update"},
	{method: http.MethodPut, path: "/containers/sockguard-test/archive"},
	{method: http.MethodPost, path: "/images/create"},
	{method: http.MethodPost, path: "/images/load"},
	{method: http.MethodPost, path: "/build"},
	{method: http.MethodPost, path: "/volumes/create"},
	{method: http.MethodPost, path: "/networks/create"},
	{method: http.MethodPost, path: "/networks/sockguard-test/connect"},
	{method: http.MethodPost, path: "/networks/sockguard-test/disconnect"},
	{method: http.MethodPost, path: "/secrets/create"},
	{method: http.MethodPost, path: "/configs/create"},
	{method: http.MethodPost, path: "/services/create"},
	{method: http.MethodPost, path: "/services/sockguard-test/update"},
	{method: http.MethodPost, path: "/swarm/init"},
	{method: http.MethodPost, path: "/swarm/join"},
	{method: http.MethodPost, path: "/swarm/update"},
	{method: http.MethodPost, path: "/swarm/unlock"},
	{method: http.MethodPost, path: "/nodes/sockguard-test/update"},
	{method: http.MethodPost, path: "/plugins/pull"},
	{method: http.MethodPost, path: "/plugins/sockguard-test/upgrade"},
	{method: http.MethodPost, path: "/plugins/sockguard-test/set"},
	{method: http.MethodPost, path: "/plugins/create"},

	{method: http.MethodPost, path: "/libpod/containers/create"},

	{method: http.MethodPost, path: "/libpod/pods/create"},
	{method: http.MethodPost, path: "/libpod/containers/sockguard-test/exec"},
	{method: http.MethodPost, path: "/libpod/exec/sockguard-test/start"},
	{method: http.MethodPost, path: "/libpod/volumes/create"},
	{method: http.MethodPost, path: "/libpod/networks/create"},
	{method: http.MethodPost, path: "/libpod/secrets/create"},

	{method: http.MethodPost, path: "/libpod/play/kube"},
	{method: http.MethodPost, path: "/libpod/kube/play"},
	{method: http.MethodPost, path: "/libpod/kube/apply"},
	{method: http.MethodPost, path: "/libpod/manifests/create"},
	{method: http.MethodPost, path: "/libpod/manifests/sockguard-test"},
	{method: http.MethodPut, path: "/libpod/manifests/sockguard-test"},
}

type buildkitTunnelEndpoint struct {
	method string
	path   string
}

// buildkitTunnelEndpoints probes the opaque, unversioned BuildKit
// session/gRPC transport: POST /session (frontend/session bridge) and
// POST /grpc (the moby.buildkit.v1.Control gRPC service tunneled over an
// HTTP/1.1 hijack), still used by current Buildx (0.36.0) despite Engine API
// 1.53 deprecating both. Neither carries a request body sockguard can bound
// or inspect once opened, so admitting either requires the dedicated
// insecure_accept_opaque_buildkit_tunnels acknowledgment rather than the
// bounded-exec insecure_allow_body_blind_writes escape hatch. A literal
// "/moby.buildkit.v1.Control/*"-shaped rule is probed too: sockguard's
// net/http server has no h2c support today (see the h2c-preface guard
// integration test), so a native-gRPC path can't reach an operator-authored
// rule yet, but a rule that would admit one is still a live gap for the day
// it does.
var buildkitTunnelEndpoints = []buildkitTunnelEndpoint{
	{method: http.MethodPost, path: "/session"},
	{method: http.MethodPost, path: "/grpc"},
	{method: http.MethodPost, path: "/moby.buildkit.v1.Control/Solve"},
}

var sensitiveExfilEndpoints = []sensitiveExfilEndpoint{
	{method: http.MethodGet, path: "/containers/sockguard-test/archive"},
	{method: http.MethodGet, path: "/containers/sockguard-test/export"},

	{method: http.MethodGet, path: "/containers/sockguard-test/logs"},
	{method: http.MethodGet, path: "/containers/sockguard-test/attach/ws"},
	{method: http.MethodGet, path: "/services/sockguard-test/logs"},
	{method: http.MethodGet, path: "/tasks/sockguard-test/logs"},
	{method: http.MethodPost, path: "/containers/sockguard-test/attach"},
	{method: http.MethodGet, path: "/images/get"},
	{method: http.MethodGet, path: "/images/sockguard-test/get"},

	{method: http.MethodPost, path: "/images/sockguard-test/push"},
	{method: http.MethodPost, path: "/plugins/sockguard-test/push"},

	{method: http.MethodGet, path: "/libpod/containers/sockguard-test/archive"},
	{method: http.MethodGet, path: "/libpod/containers/sockguard-test/export"},
	{method: http.MethodGet, path: "/libpod/containers/sockguard-test/logs"},
	{method: http.MethodPost, path: "/libpod/containers/sockguard-test/attach"},
	{method: http.MethodGet, path: "/libpod/images/export"},
	{method: http.MethodGet, path: "/libpod/images/sockguard-test/get"},
	{method: http.MethodPost, path: "/libpod/images/sockguard-test/push"},
	{method: http.MethodGet, path: "/libpod/generate/kube"},

	{method: http.MethodPost, path: "/libpod/manifests/sockguard-test/registry/sockguard-test"},
	{method: http.MethodPost, path: "/libpod/manifests/sockguard-test/push"},
}

func validateAndCompileRules(cfg *config.Config) ([]*filter.CompiledRule, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	compiled, err := compileConfiguredRules(cfg.Rules)
	if err != nil {
		return nil, err
	}

	if err := validateBodyBlindWriteRules(cfg, compiled); err != nil {
		return nil, err
	}
	if err := validateReadExfiltrationRules(cfg, compiled); err != nil {
		return nil, err
	}
	if err := validateBuildkitTunnelRules(cfg, compiled); err != nil {
		return nil, err
	}
	if _, err := compileClientProfiles(cfg); err != nil {
		return nil, err
	}

	return compiled, nil
}

func compileConfiguredRules(rules []config.RuleConfig) ([]*filter.CompiledRule, error) {
	compiled := make([]*filter.CompiledRule, 0, len(rules))
	for i, rule := range rules {
		spec := filter.Rule{
			Methods: splitMethods(rule.Match.Method),
			Pattern: rule.Match.Path,
			Action:  filter.Action(rule.Action),
			Reason:  rule.Reason,
			Index:   i,
		}

		compiledRule, err := compileFilterRule(spec)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		compiled = append(compiled, compiledRule)
	}
	return compiled, nil
}

func splitMethods(methods string) []string {
	parts := strings.Split(methods, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		result = append(result, trimmed)
	}
	return result
}

func validateBodyBlindWriteRules(cfg *config.Config, compiled []*filter.CompiledRule) error {
	return validateBodyBlindWriteRulesForPolicy("", cfg.InsecureAllowBodyBlindWrites, cfg.RequestBody, compiled)
}

func validateReadExfiltrationRules(cfg *config.Config, compiled []*filter.CompiledRule) error {
	return validateReadExfiltrationRulesForPolicy("", cfg.InsecureAllowReadExfiltration, compiled)
}

func validateBuildkitTunnelRules(cfg *config.Config, compiled []*filter.CompiledRule) error {

	return validateBuildkitTunnelRulesForPolicy("", cfg.InsecureAcceptOpaqueBuildkitTunnels, cfg.RequestBody.Buildkit.ToPolicy(cfg.RequestBody.Build).Configured(), compiled)
}

func validateBodyBlindWriteRulesForPolicy(scope string, insecure bool, requestBody config.RequestBodyConfig, compiled []*filter.CompiledRule) error {
	if insecure {
		return nil
	}

	exposed := allowedBodySensitiveWriteEndpoints(requestBody, compiled)
	if len(exposed) == 0 {
		return nil
	}

	if scope == "" {
		return fmt.Errorf(
			"rules allow body-sensitive write endpoints without request body inspection; set insecure_allow_body_blind_writes=true to acknowledge this risk: %s",
			strings.Join(exposed, ", "),
		)
	}

	return fmt.Errorf(
		"client profile %q allows body-sensitive write endpoints without request body inspection; set the top-level insecure_allow_body_blind_writes=true to acknowledge this risk (it is a global setting, not per-profile): %s",
		scope,
		strings.Join(exposed, ", "),
	)
}

func validateReadExfiltrationRulesForPolicy(scope string, insecure bool, compiled []*filter.CompiledRule) error {
	if insecure {
		return nil
	}

	exposed := allowedSensitiveExfilEndpoints(compiled)
	if len(exposed) == 0 {
		return nil
	}

	if scope == "" {
		return fmt.Errorf(
			"rules allow raw archive/export, log/attach streaming, or registry push endpoints "+
				"(these can exfiltrate container files, images, plugins, environment variables, and secrets); "+
				"either tighten the allow rules to omit these paths or set "+
				"insecure_allow_read_exfiltration: true to acknowledge the risk. "+
				"Exposed endpoints: %s",
			strings.Join(exposed, ", "),
		)
	}

	return fmt.Errorf(
		"client profile %q allows raw archive/export, log/attach streaming, or registry push endpoints "+
			"(these can exfiltrate container files, images, plugins, environment variables, and secrets); "+
			"either tighten the profile's allow rules to omit these paths or set the "+
			"top-level insecure_allow_read_exfiltration: true to acknowledge the risk "+
			"(it is a global setting, not per-profile). "+
			"Exposed endpoints: %s",
		scope,
		strings.Join(exposed, ", "),
	)
}

// validateBuildkitTunnelRulesForPolicy admits a rule allowing the opaque
// BuildKit tunnel endpoints when EITHER the wholesale
// insecure_accept_opaque_buildkit_tunnels acknowledgment is set OR
// buildkitConfigured is true — i.e. request_body.buildkit
// (config.BuildkitRequestBodyConfig, translated via
// buildkitproxy.Policy.Configured) is configured for this scope. The two
// are mutually exclusive by construction (see
// validateBuildkitAckMutualExclusion in the config package), so in practice
// exactly one of these two conditions can ever be true for a given scope —
// this function does not need to (and does not) re-check that invariant.
//
// IMPORTANT — this function governs STARTUP admission only, i.e. whether
// sockguard refuses to boot at all. What actually happens to a /session or
// /grpc request at request time depends on which of the two conditions above
// admitted the rule, enforced by the filter inspector + mediator pair
// (filter.buildkitPolicy.inspect in buildkit.go, and cmd/serve.go's
// withBuildkitMediator): when request_body.buildkit IS configured for the
// resolved policy, withBuildkitMediator hands POST /session and POST /grpc to
// internal/buildkitproxy.Mediator, which terminates the h2c tunnel and
// enforces buildkitproxy.Classify + Policy.Allowed per gRPC method — the
// literal /moby.buildkit.v1.Control/<Method> probe path stays hard-denied by
// the filter inspector regardless of PolicyConfig.Buildkit.TunnelConfigured
// (see buildkit.go's inspect doc comment for why: it carries no upgrade for
// any mediator to terminate). When request_body.buildkit is NOT configured —
// the insecure_accept_opaque_buildkit_tunnels path — withBuildkitMediator is
// a no-op and the request falls through to the plain ReverseProxy exactly as
// it did pre-#185; that flag's meaning and denial message below are
// unchanged.
func validateBuildkitTunnelRulesForPolicy(scope string, insecure, buildkitConfigured bool, compiled []*filter.CompiledRule) error {
	if insecure || buildkitConfigured {
		return nil
	}

	exposed := allowedBuildkitTunnelEndpoints(compiled)
	if len(exposed) == 0 {
		return nil
	}

	if scope == "" {
		return fmt.Errorf(
			"rules allow the opaque BuildKit session/gRPC tunnel (POST /session, POST /grpc, or a moby.buildkit.v1.Control method path) — "+
				"these streams carry secrets, SSH agent forwarding, and file sync that sockguard cannot inspect or bound once opened; "+
				"set insecure_accept_opaque_buildkit_tunnels=true to acknowledge this risk, or configure request_body.buildkit (issue #185) "+
				"to admit them under sockguard's BuildKit gRPC mediation policy instead: %s",
			strings.Join(exposed, ", "),
		)
	}

	return fmt.Errorf(
		"client profile %q allows the opaque BuildKit session/gRPC tunnel (POST /session, POST /grpc, or a moby.buildkit.v1.Control method path); "+
			"set the top-level insecure_accept_opaque_buildkit_tunnels=true to acknowledge this risk (it is a global setting, not per-profile), "+
			"or configure this profile's request_body.buildkit (issue #185) to admit them under sockguard's BuildKit gRPC mediation policy instead: %s",
		scope,
		strings.Join(exposed, ", "),
	)
}

func allowedBuildkitTunnelEndpoints(compiled []*filter.CompiledRule) []string {
	allowed := make([]string, 0, len(buildkitTunnelEndpoints))
	for _, endpoint := range buildkitTunnelEndpoints {
		req := &http.Request{Method: endpoint.method, URL: &url.URL{Path: endpoint.path}}
		action, _, _ := filter.Evaluate(compiled, req)
		if action != filter.ActionAllow {
			continue
		}
		allowed = append(allowed, endpoint.method+" "+endpoint.path)
	}
	return allowed
}

func allowedBodySensitiveWriteEndpoints(requestBody config.RequestBodyConfig, compiled []*filter.CompiledRule) []string {
	allowed := make([]string, 0, len(bodySensitiveWriteEndpoints))
	for _, endpoint := range bodySensitiveWriteEndpoints {
		if bodyInspectionConfiguredForEndpoint(requestBody, endpoint) {
			continue
		}
		req := &http.Request{Method: endpoint.method, URL: &url.URL{Path: endpoint.path}}
		action, _, _ := filter.Evaluate(compiled, req)
		if action != filter.ActionAllow {
			continue
		}
		allowed = append(allowed, endpoint.method+" "+endpoint.path)
	}
	return allowed
}

func allowedSensitiveExfilEndpoints(compiled []*filter.CompiledRule) []string {
	allowed := make([]string, 0, len(sensitiveExfilEndpoints))
	for _, endpoint := range sensitiveExfilEndpoints {
		req := &http.Request{Method: endpoint.method, URL: &url.URL{Path: endpoint.path}}
		action, _, _ := filter.Evaluate(compiled, req)
		if action != filter.ActionAllow {
			continue
		}
		allowed = append(allowed, endpoint.method+" "+endpoint.path)
	}
	return allowed
}

func bodyInspectionConfiguredForEndpoint(requestBody config.RequestBodyConfig, endpoint bodySensitiveWriteEndpoint) bool {
	switch endpoint.path {
	case "/containers/sockguard-test/exec", "/exec/sockguard-test/start",
		"/libpod/containers/sockguard-test/exec", "/libpod/exec/sockguard-test/start":

		return len(requestBody.Exec.AllowedCommands) > 0
	case "/containers/sockguard-test/update", "/containers/sockguard-test/archive", "/images/create", "/images/load", "/build":
		return true
	case "/volumes/create", "/networks/create", "/networks/sockguard-test/connect", "/networks/sockguard-test/disconnect", "/secrets/create", "/configs/create", "/services/create", "/services/sockguard-test/update", "/swarm/init", "/plugins/pull", "/plugins/sockguard-test/upgrade":
		return true
	case "/swarm/join":
		return len(requestBody.Swarm.AllowedJoinRemoteAddrs) > 0
	case "/swarm/update", "/swarm/unlock", "/nodes/sockguard-test/update":
		return true
	case "/plugins/sockguard-test/set":
		return len(requestBody.Plugin.AllowedSetEnvPrefixes) > 0
	case "/plugins/create":
		return true
	case "/libpod/containers/create":
		return true
	case "/libpod/pods/create", "/libpod/volumes/create", "/libpod/networks/create", "/libpod/secrets/create":

		return true

	default:
		return false
	}
}

func compileClientProfiles(cfg *config.Config) (map[string]filter.Policy, error) {
	profiles := make(map[string]filter.Policy, len(cfg.Clients.Profiles))
	for _, profile := range cfg.Clients.Profiles {
		compiledRules, err := compileConfiguredRules(profile.Rules)
		if err != nil {
			return nil, fmt.Errorf("client profile %q: %w", profile.Name, err)
		}
		if err := validateBodyBlindWriteRulesForPolicy(profile.Name, cfg.InsecureAllowBodyBlindWrites, profile.RequestBody, compiledRules); err != nil {
			return nil, err
		}
		if err := validateReadExfiltrationRulesForPolicy(profile.Name, cfg.InsecureAllowReadExfiltration, compiledRules); err != nil {
			return nil, err
		}

		if err := validateBuildkitTunnelRulesForPolicy(profile.Name, cfg.InsecureAcceptOpaqueBuildkitTunnels, profile.RequestBody.Buildkit.ToPolicy(profile.RequestBody.Build).Configured(), compiledRules); err != nil {
			return nil, err
		}
		profiles[profile.Name] = filter.Policy{
			Rules:        compiledRules,
			PolicyConfig: profile.RequestBody.ToFilterOptions(),
		}
	}
	return profiles, nil
}

const readHeaderTimeout = 5 * time.Second
const idleTimeout = 120 * time.Second
const maxHeaderBytes = 1 << 20

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the proxy server",
	Long: `Start the sockguard proxy, listening for Docker API requests and filtering them according to configured rules.

Configuration sources (highest precedence first):
  1. CLI flags
  2. SOCKGUARD_* env vars (e.g. SOCKGUARD_LISTEN_SOCKET, SOCKGUARD_LOG_LEVEL)
  3. Tecnativa-compat env vars (SOCKET_PATH, LOG_LEVEL) — accepted as aliases
     for backward compatibility; lower precedence than the SOCKGUARD_* form
  4. YAML config file (--config)
  5. Built-in defaults`,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().String("listen-socket", "", "proxy socket path (overrides config)")
	serveCmd.Flags().String("upstream-socket", "", "Docker socket path (overrides config)")
	serveCmd.Flags().String("log-level", "", "log level (overrides config)")
	serveCmd.Flags().String("log-format", "", "log format (overrides config)")
	serveCmd.Flags().String("deny-verbosity", "", "deny response verbosity: verbose or minimal (overrides config)")
}

func runServe(cmd *cobra.Command, args []string) error {
	return runServeWithDeps(cmd, args, newServeDeps())
}

func runServeWithDeps(cmd *cobra.Command, args []string, deps *serveDeps) error {
	if err := requireExplicitConfigFile(cmd, cfgFile); err != nil {
		return fmt.Errorf("config preflight: %w", err)
	}

	cfg, err := deps.loadConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("config load: %w", err)
	}
	if err := applyFlagOverrides(cmd, cfg); err != nil {
		return fmt.Errorf("apply flag overrides: %w", err)
	}

	logger, logOutputCloser, err := deps.newLogger(cfg.Log.Level, cfg.Log.Format, cfg.Log.Output)
	if err != nil {
		return fmt.Errorf("logger: %w", err)
	}
	defer func() {
		if logOutputCloser == nil {
			return
		}
		if closeErr := logOutputCloser.Close(); closeErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "failed to close log output: %v\n", closeErr)
		}
	}()

	bundleVerifier, err := deps.buildBundleVerifier(cfg.PolicyBundle)
	if err != nil {
		return fmt.Errorf("policy bundle verifier: %w", err)
	}
	bundleResult, signedCfg, err := verifyPolicyBundleAtStartup(cmd.Context(), cfg, cfgFile, deps, bundleVerifier, logger)
	if err != nil {
		return fmt.Errorf("policy bundle: %w", err)
	}
	if signedCfg != nil {

		if err := applyFlagOverrides(cmd, signedCfg); err != nil {
			return fmt.Errorf("apply flag overrides: %w", err)
		}
		cfg = signedCfg
	}

	var auditLogger *logging.AuditLogger
	var auditLogOutputCloser io.Closer
	if cfg.Log.Audit.Enabled {
		auditLogger, auditLogOutputCloser, err = deps.newAuditLogger(cfg.Log.Audit.Format, cfg.Log.Audit.Output)
		if err != nil {
			return fmt.Errorf("audit logger: %w", err)
		}
		defer func() {
			if auditLogOutputCloser == nil {
				return
			}
			if closeErr := auditLogOutputCloser.Close(); closeErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "failed to close audit log output: %v\n", closeErr)
			}
		}()
	}

	compatActive := config.ApplyCompat(cfg, logger)

	rules, err := deps.validateRules(cfg)
	if err != nil {
		return fmt.Errorf("config validation: %w", err)
	}
	warnIfDefaultProfileExcluded(cfg, logger)
	runtime, err := newServeRuntime(cfg, logger, deps)
	if err != nil {
		return fmt.Errorf("upstream: %w", err)
	}
	if err := verifyUpstreamReachableForRuntime(cmd.Context(), deps, runtime, cfg, logger); err != nil {
		return err
	}

	board := newListenerStatusBoard()
	if runtime.health != nil {
		runtime.health.ListenersFunc = board.snapshot
	}
	if runtime.readiness != nil {
		runtime.readiness.ListenersFunc = board.snapshot
	}

	versioner := admin.NewPolicyVersioner()
	initialVersion := versioner.Update(buildInitialPolicySnapshot(deps, cfg, rules, compatActive, bundleResult))

	runtime.metrics.SetPolicyVersion(initialVersion)
	handler, chainTeardown := buildServeHandlerChainWithRuntime(serveHandlerBuild{
		Cfg:         cfg,
		Logger:      logger,
		AuditLogger: auditLogger,
		Rules:       rules,
		Deps:        deps,
		Runtime:     runtime,
		Versioner:   versioner,
	})
	swappable := reload.NewSwappableHandler(handler)
	coordinator := newReloadCoordinator(reloadCoordinatorParams{
		RootCtx:         cmd.Context(),
		Cfg:             cfg,
		CfgFile:         cfgFile,
		Swappable:       swappable,
		InitialTeardown: chainTeardown,
		Logger:          logger,
		AuditLogger:     auditLogger,
		Deps:            deps,
		Runtime:         runtime,
		Versioner:       versioner,
		BundleVerifier:  bundleVerifier,
	})
	defer coordinator.stop()

	members, err := bindMainListeners(cfg, deps, swappable, board)
	if err != nil {
		return err
	}
	adminMember, err := bindAdminServer(cfg, logger, auditLogger, versioner, deps, board)
	if err != nil {
		closeMembersReverse(members)
		return err
	}
	allMembers := append([]*listenerMember(nil), members...)
	if adminMember != nil {
		allMembers = append(allMembers, adminMember)
	}
	defer func() {

		for i := len(allMembers) - 1; i >= 0; i-- {
			member := allMembers[i]
			closeErr := member.listener.Close()
			if closeErr == nil || errors.Is(closeErr, net.ErrClosed) {
				continue
			}
			logger.Warn("failed to close listener", "listener", member.identity.Name, "error", closeErr)
		}
	}()

	setListenersUp(runtime.metrics, members, false)
	if adminMember != nil {
		runtime.metrics.SetListenerUp(adminMember.identity.Name, string(adminMember.identity.Role), string(adminMember.identity.Network), false)
	}

	fanIn := make(chan listenerResult, len(allMembers))
	publishMainListeners(deps, members, fanIn, board)
	if adminMember != nil {
		publishListenerMember(deps, adminMember, fanIn, board)
	}
	setListenersUp(runtime.metrics, members, true)
	if adminMember != nil {
		runtime.metrics.SetListenerUp(adminMember.identity.Name, string(adminMember.identity.Role), string(adminMember.identity.Network), true)
		logger.Info("admin listener started",
			"listen", adminListenerAddr(cfg),
			"validate_path", cfg.Admin.Path,
			"policy_version_path", cfg.Admin.PolicyVersionPath,
		)
	}

	upstreamName := upstreamLabel(runtime.resolver)
	stopResolver := runtime.startResolver(cmd.Context())
	defer stopResolver()
	stopWatchdog := runtime.startWatchdog(cmd.Context(), cfg)
	defer stopWatchdog()
	stopReadiness := runtime.startReadiness(cmd.Context(), cfg)
	defer stopReadiness()

	bannerLines := bannerListenerLines(members, cfg.EffectiveListeners())
	if adminMember != nil {
		bannerLines = append(bannerLines, "admin "+adminListenerAddr(cfg))
	}
	banner.Render(cmd.ErrOrStderr(), banner.Info{
		Listeners: bannerLines,
		Upstream:  upstreamName,
		Rules:     len(cfg.Rules),
		LogFormat: cfg.Log.Format,
		LogLevel:  cfg.Log.Level,
		AccessLog: cfg.Log.AccessLog,
	})
	logger.Info("sockguard started",
		"version", version.Version,
		"listeners", bannerLines,
		"upstream", upstreamName,
		"rules", len(cfg.Rules),
		"log_level", cfg.Log.Level,
		"upstream_request_timeout", upstreamRequestTimeoutLogValue(cfg),
	)

	stopReload := startConfigReload(cmd.Context(), cfg, cfgFile, coordinator, logger)
	defer stopReload()

	sigCh := make(chan os.Signal, 1)
	deps.notifySignals(sigCh, syscall.SIGTERM, syscall.SIGINT)

	var serveFailure error
	select {
	case sig := <-sigCh:
		logger.Info("shutdown signal received", "signal", sig.String())
	case result := <-fanIn:

		board.setState(result.name, health.ListenerStateFailed)
		cause := result.err
		if cause == nil {
			cause = errors.New("serve returned nil before group shutdown")
		} else if errors.Is(cause, http.ErrServerClosed) {
			cause = fmt.Errorf("serve exited before group shutdown: %w", cause)
		}
		if result.role == inbound.RoleAdmin {
			serveFailure = fmt.Errorf("admin server error: %w", cause)
		} else {
			serveFailure = fmt.Errorf("listener %q server error: %w", result.name, cause)
		}
	}
	stopWatchdog()

	var adminServer *http.Server
	if adminMember != nil {
		adminServer = adminMember.server
	}
	shutdownServers(cmd.Context(), deps, cfg, members, adminServer, runtime.metrics, board, logger)
	logger.Info("sockguard stopped")
	return serveFailure
}

// bindAdminServer prepares the dedicated admin listener as the final member
// of the all-or-none bind transaction. It deliberately does not call Serve;
// the caller publishes it only after every main and admin bind succeeded.
func bindAdminServer(
	cfg *config.Config,
	logger *slog.Logger,
	auditLogger *logging.AuditLogger,
	versioner *admin.PolicyVersioner,
	deps *serveDeps,
	board *listenerStatusBoard,
) (*listenerMember, error) {
	if !cfg.Admin.Enabled || !cfg.Admin.Listen.Configured() {
		return nil, nil
	}
	ln, err := deps.createAdminListener(cfg)
	if err != nil {
		return nil, fmt.Errorf("admin listener: %w", err)
	}
	warnIfAdminListenerWideOpen(cfg, logger)
	identity := inbound.Identity{Name: config.AdminListenerName, Role: inbound.RoleAdmin, Network: networkFor(cfg.Admin.Listen.ListenConfig)}
	server := newAdminHTTPServer(buildAdminHandlerChain(cfg, logger, auditLogger, versioner))
	server.ConnContext = inbound.ConnContext(identity, server.ConnContext)
	member := &listenerMember{
		identity:   identity,
		listener:   ln,
		server:     server,
		socketPath: cfg.Admin.Listen.Socket,
	}
	if member.socketPath != "" {
		member.socketIdentity = statSocketIdentity(deps.lstatPath, member.socketPath)
	}
	board.register(identity, health.ListenerStateBound)
	return member, nil
}

// shutdownServers gracefully stops every main listener and the admin
// http.Server, concurrently, within the configured grace period, and
// removes any unix sockets sockguard owns. Errors from each step are
// logged but do not block subsequent steps — shutdown must always make
// progress so a partial failure can't leave a stale listener behind.
func shutdownServers(ctx context.Context, deps *serveDeps, cfg *config.Config, members []*listenerMember, adminServer *http.Server, registry *metrics.Registry, board *listenerStatusBoard, logger *slog.Logger) {

	_ = ctx
	shutdownCtx, cancel := context.WithTimeout(context.Background(), deps.shutdownGracePeriod)
	defer cancel()

	setListenersUp(registry, members, false)
	if adminServer != nil {
		registry.SetListenerUp("admin", string(inbound.RoleAdmin), string(networkFor(cfg.Admin.Listen.ListenConfig)), false)
		board.setState("admin", health.ListenerStateDraining)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		shutdownMainListeners(shutdownCtx, deps, members, board, logger)
	}()

	if adminServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := deps.shutdownServer(adminServer, shutdownCtx); err != nil {
				logger.Error("admin shutdown error", "error", err)
				if shutdownCtx.Err() != nil {
					_ = adminServer.Close()
				}
			}
		}()
	}
	wg.Wait()

	if adminServer != nil {
		board.setState("admin", health.ListenerStateStopped)
	}

	if cfg.Admin.Enabled && cfg.Admin.Listen.Configured() && cfg.Admin.Listen.Socket != "" {
		if err := deps.removePath(cfg.Admin.Listen.Socket); err != nil && !os.IsNotExist(err) {
			logger.Error("remove admin socket error", "socket", cfg.Admin.Listen.Socket, "error", err)
		}
	}
}

// buildInitialPolicySnapshot captures the per-startup metadata that the
// admin policy-version endpoint and the policy-version gauge surface to
// operators. Bundle fields stay zero unless verification succeeded.
func buildInitialPolicySnapshot(deps *serveDeps, cfg *config.Config, rules []*filter.CompiledRule, compatActive bool, bundleResult *policybundle.VerifyResult) admin.PolicySnapshot {
	snap := admin.PolicySnapshot{
		LoadedAt:     deps.now(),
		Rules:        len(rules),
		Profiles:     len(cfg.Clients.Profiles),
		CompatActive: compatActive,
		Source:       "startup",
		ConfigSHA256: policyConfigHash(cfg),
	}
	if bundleResult != nil {
		snap.BundleSource = filepath.Base(cfg.PolicyBundle.SignaturePath)
		snap.BundleSigner = bundleResult.Signer
		snap.BundleDigest = bundleResult.DigestHex
	}
	return snap
}

// startConfigReload wires up the SIGHUP / fsnotify reload loop. Returns a
// stop closure the caller must defer; the closure is a no-op when reload is
// disabled or the watcher fails to start (logged at Error so an operator can
// see the degradation without taking the proxy down).
func startConfigReload(ctx context.Context, cfg *config.Config, cfgFile string, coordinator *reloadCoordinator, logger *slog.Logger) func() {
	if !cfg.Reload.Enabled || cfgFile == "" {
		return func() {}
	}
	debounce := reload.DefaultDebounce
	if cfg.Reload.Debounce != "" {
		if d, err := time.ParseDuration(cfg.Reload.Debounce); err == nil {
			debounce = d
		}
	}
	var pollInterval time.Duration
	if cfg.Reload.PollInterval != "" {
		if d, err := time.ParseDuration(cfg.Reload.PollInterval); err == nil {
			pollInterval = d
		}
	}
	stop, err := startReloader(ctx, cfgFile, debounce, pollInterval, coordinator, logger)
	if err != nil {
		logger.Error("config hot-reload disabled: failed to start watcher",
			"error", err,
			"path", cfgFile,
		)
		return func() {}
	}
	return stop
}

// serveHandlerBuild bundles the inputs the buildServeHandler* family needs.
// The chain pulls together config, rules, every per-process singleton, and
// the optional admin versioner; grouping them avoids 6-8 positional params
// at every call site.
type serveHandlerBuild struct {
	Cfg            *config.Config
	Logger         *slog.Logger
	AuditLogger    *logging.AuditLogger
	Rules          []*filter.CompiledRule
	Deps           *serveDeps
	Runtime        *serveRuntime
	Versioner      *admin.PolicyVersioner
	ClientProfiles map[string]filter.Policy
}

// buildServeHandlerChainWithRuntime is the production / reload entry point:
// it returns both the composed http.Handler and a teardown closure that stops
// every chain-scoped goroutine (the rate-limit sampler and per-profile
// Limiter eviction loops). Callers must invoke the returned teardown when
// the handler is replaced (hot reload) or when the server shuts down,
// otherwise the rate-limit goroutines tied to the previous chain leak.
//
// The versioner is process-scoped (its pointer is captured into the admin
// policy-version handler), so reloads pass the SAME versioner used at
// startup — the snapshot it returns is whatever the reload coordinator
// last published. Tests that don't care about the policy-version endpoint
// pass nil; in that case the layer is skipped.
//
// Tests that don't care about teardown should continue calling
// buildServeHandler which discards it — the goroutines die with the test
// process anyway.
func buildServeHandlerChainWithRuntime(b serveHandlerBuild) (http.Handler, func()) {
	resolver := runtimeResolver(b.Runtime, b.Cfg)
	clientProfiles, err := buildServeClientProfiles(b.Cfg, resolver)
	if err != nil {
		b.Logger.Error("invalid client profile config", "error", err)
		return invalidClientProfileHandler(), func() {}
	}

	handler := newServeUpstreamHandler(b.Cfg, resolver, b.Logger)
	b.ClientProfiles = clientProfiles
	layers, teardown := buildServeHandlerLayersWithRuntime(b)
	for _, layer := range layers {
		handler = layer.with(handler)
	}
	return handler, teardown
}

// serveRuntime holds process-scoped objects whose lifetime spans the whole
// run: the metrics registry and the upstream-health monitor. Both survive
// hot reloads — they are tied to immutable config fields, so a reload that
// would change them is rejected by the immutable-field gate before any
// rebuild happens. Chain-scoped goroutines (rate-limit sampler, per-profile
// Limiter eviction) are tracked separately by reloadCoordinator.
type serveRuntime struct {
	metrics   *metrics.Registry
	health    *health.Monitor
	readiness *health.Monitor
	// resolver is the shared upstream dial seam (endpoint selection, pooling,
	// TLS, failover). All request paths and side channels route through it so
	// failover is coherent across the proxy, hijack, and inspect calls.
	resolver *upstream.Resolver
	// legacyUpstreamSocket records that the upstream is the single local socket
	// (no endpoints, no DOCKER_HOST), so startup keeps the original fail-fast
	// reachability check.
	legacyUpstreamSocket bool
}

func newServeRuntime(cfg *config.Config, logger *slog.Logger, deps *serveDeps) (*serveRuntime, error) {
	runtime := &serveRuntime{}
	if cfg.Metrics.Enabled {
		runtime.metrics = metrics.NewRegistry()
	}

	resolver, legacy, err := buildUpstreamResolver(cfg, logger, os.Getenv)
	if err != nil {
		return nil, err
	}
	runtime.resolver = resolver
	runtime.legacyUpstreamSocket = legacy
	label := upstreamLabel(resolver)

	if cfg.Health.Enabled || cfg.Health.Watchdog.Enabled {
		runtime.health = health.NewMonitorWithDialer(label, resolver, deps.now(), logger)
	}
	if cfg.Health.Readiness.Enabled {
		timeout, _ := time.ParseDuration(cfg.Health.Readiness.Timeout)
		runtime.readiness = health.NewReadinessMonitorWithRoundTripper(label, resolver, deps.now(), logger, timeout)
	}
	return runtime, nil
}

// startResolver launches the resolver's background health/failover probe loop.
// It returns a stop func; the loop also exits when ctx is canceled.
func (r *serveRuntime) startResolver(ctx context.Context) func() {
	if r == nil || r.resolver == nil {
		return func() {}
	}
	resolverCtx, cancel := context.WithCancel(ctx)
	r.resolver.Start(resolverCtx)
	return cancel
}

func (r *serveRuntime) startWatchdog(ctx context.Context, cfg *config.Config) func() {
	if r == nil || r.health == nil || !cfg.Health.Watchdog.Enabled {
		return func() {}
	}
	interval, err := time.ParseDuration(cfg.Health.Watchdog.Interval)
	if err != nil || interval <= 0 {
		return func() {}
	}

	watchdogCtx, cancel := context.WithCancel(ctx)
	r.health.StartWatchdog(watchdogCtx, interval, func(state health.WatchdogState) {
		if r.metrics == nil {
			return
		}
		r.metrics.ObserveUpstreamWatchdog(state.Up)
		r.metrics.SetUpstreamSocketState(state.Up)
	})
	return cancel
}

func (r *serveRuntime) startReadiness(ctx context.Context, cfg *config.Config) func() {
	if r == nil || r.readiness == nil || !cfg.Health.Readiness.Enabled {
		return func() {}
	}
	interval, err := time.ParseDuration(cfg.Health.Readiness.Interval)
	if err != nil || interval <= 0 {
		return func() {}
	}

	readinessCtx, cancel := context.WithCancel(ctx)
	r.readiness.StartWatchdog(readinessCtx, interval, func(state health.WatchdogState) {
		if r.metrics == nil {
			return
		}
		r.metrics.ObserveUpstreamReadiness(state.Up)
		r.metrics.SetUpstreamAPIState(state.Up)
	})
	return cancel
}

type serveHandlerLayer struct {
	name string
	with func(http.Handler) http.Handler
}

func invalidClientProfileHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logging.SetDeniedWithCode(w, r, "client_profile_config_invalid", "client profile config invalid", filter.NormalizePath)
		_ = httpjson.Write(w, http.StatusInternalServerError, httpjson.ErrorResponse{Message: "client profile config invalid"})
	})
}

func buildServeClientProfiles(cfg *config.Config, res *upstream.Resolver) (map[string]filter.Policy, error) {
	clientProfiles, err := compileClientProfiles(cfg)
	if err != nil {
		return nil, err
	}
	for name, profile := range clientProfiles {
		profile.PolicyConfig = attachRuntimeInspectors(cfg, res, profile.PolicyConfig)
		clientProfiles[name] = profile
	}
	return clientProfiles, nil
}

// attachRuntimeInspectors wires the runtime-bound inspectors (currently the
// Docker-compat and libpod exec-start inspectors, both of which need the
// upstream) onto a PolicyConfig shaped by config translation. Each inspector
// issues its GET through the shared upstream resolver so exec-identity
// lookups follow the same active endpoint as the exec-create/start they
// guard under failover. Centralized so every call path that produces a
// filter.PolicyConfig destined for live request evaluation gets the same
// wiring — a future runtime dependency added here propagates to both the
// default policy and every client profile without revisiting two call
// sites.
func attachRuntimeInspectors(cfg *config.Config, res *upstream.Resolver, policy filter.PolicyConfig) filter.PolicyConfig {
	policy.Exec.InspectStart = filter.NewDockerExecInspectorWithRoundTripper(upstreamResolverFor(res, cfg))

	policy.Exec.InspectStartLibpod = filter.NewLibpodExecInspectorWithRoundTripper(upstreamResolverFor(res, cfg))

	policy.Exec.AllowBlindWrites = cfg.InsecureAllowBodyBlindWrites
	return policy
}

func newServeUpstreamHandler(cfg *config.Config, res *upstream.Resolver, logger *slog.Logger) http.Handler {
	rp := proxy.NewWithTransport(upstreamResolverFor(res, cfg), logger, proxy.Options{
		ModifyResponse: responsefilter.New(serveResponseFilterOptions(cfg)).ModifyResponse,
	})

	return proxy.WithRequestTimeout(rp, effectiveUpstreamRequestTimeout(cfg))
}

// effectiveUpstreamRequestTimeout resolves cfg.Upstream.RequestTimeout to the
// time.Duration proxy.WithRequestTimeout consumes. RequestTimeoutDisabled is
// the single source of truth for the "off"/legacy-empty disabled spelling,
// shared with config.validateUpstream so the two call sites can't drift.
// request_timeout is validated at config load, so a parse failure here
// degrades to "disabled" (0) rather than aborting the chain rebuild.
func effectiveUpstreamRequestTimeout(cfg *config.Config) time.Duration {
	if cfg.Upstream.RequestTimeoutDisabled() {
		return 0
	}
	d, err := time.ParseDuration(cfg.Upstream.RequestTimeout)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// upstreamRequestTimeoutLogValue renders the effective upstream.request_timeout
// for the "sockguard started" log line: "off" when the deadline is disabled
// (including a degraded invalid value, which is validated away at load time
// in normal operation), otherwise the configured duration string verbatim.
func upstreamRequestTimeoutLogValue(cfg *config.Config) string {
	if effectiveUpstreamRequestTimeout(cfg) <= 0 {
		return "off"
	}
	return cfg.Upstream.RequestTimeout
}

func buildServeHandlerLayersWithRuntime(b serveHandlerBuild) ([]serveHandlerLayer, func()) {
	cfg, logger, auditLogger := b.Cfg, b.Logger, b.AuditLogger
	runtime, versioner := b.Runtime, b.Versioner
	rules, clientProfiles := b.Rules, b.ClientProfiles
	resolver := runtimeResolver(runtime, cfg)
	layers := []serveHandlerLayer{

		namedServeHandlerLayer("withBuildkitMediator", withBuildkitMediator(cfg, resolver, logger)),
		namedServeHandlerLayer("withHijack", withHijack(resolver, logger)),

		namedServeHandlerLayer("withResourceLimitGuard", withResourceLimitGuard(cfg, resolver, logger, clientProfiles)),
		namedServeHandlerLayer("withOwnership", withOwnership(cfg, resolver, logger)),
		namedServeHandlerLayer("withVisibility", withVisibility(cfg, resolver, logger)),
		namedServeHandlerLayer("withFilter", withFilter(cfg, resolver, logger, rules, clientProfiles)),
	}

	if cfg.Admin.Enabled && !cfg.Admin.Listen.Configured() {
		if versioner != nil {
			layers = append(layers, namedServeHandlerLayer("withPolicyVersionEndpoint", mountOnGate(cfg, withPolicyVersionEndpoint(cfg, logger, versioner))))
		}
		layers = append(layers, namedServeHandlerLayer("withAdminEndpoint", mountOnGate(cfg, withAdminEndpoint(cfg, logger))))
	}

	teardown := func() {}
	if rlMiddleware, stop := buildRateLimitMiddleware(cfg, logger, runtime); rlMiddleware != nil {
		teardown = stop
		layers = append(layers, namedServeHandlerLayer("withRateLimit", rlMiddleware))
	}

	if cfg.Health.Enabled {
		layers = append(layers, namedServeHandlerLayer("withHealth", withHealth(cfg, runtime)))
	}
	if runtime.readiness != nil {
		layers = append(layers, namedServeHandlerLayer("withReadiness", withReadiness(cfg, runtime)))
	}
	if runtime.metrics != nil {
		layers = append(layers, namedServeHandlerLayer("withMetricsEndpoint", withMetricsEndpoint(cfg, runtime.metrics)))
	}

	layers = append(layers, namedServeHandlerLayer("withListenerAdmission", withListenerAdmission(cfg)))
	layers = append(layers,
		namedServeHandlerLayer("withClientACL", withClientACL(cfg, resolver, logger)),
	)
	if runtime.metrics != nil {
		layers = append(layers, namedServeHandlerLayer("withMetrics", withMetrics(runtime.metrics)))
	}
	layers = append(layers,
		namedServeHandlerLayer("withTraceContext", withTraceContext()),
		namedServeHandlerLayer("withRequestID", withRequestID()),
	)
	if cfg.Log.Audit.Enabled && auditLogger != nil {
		layers = append(layers, namedServeHandlerLayer("withAuditLog", withAuditLog(auditLogger, cfg)))
	}
	if cfg.Log.AccessLog {
		layers = append(layers, namedServeHandlerLayer("withAccessLog", withAccessLog(logger)))
	}
	return layers, teardown
}

// buildRateLimitMiddleware constructs the per-profile rate-limit+concurrency
// middleware and its audit sampler. Returns (nil, nil) when no profile has
// limits and no global concurrency cap is configured. The second return value
// is a stop function that halts the sampler eviction goroutine and every
// per-profile Limiter eviction goroutine; callers must call it on shutdown.
func buildRateLimitMiddleware(cfg *config.Config, logger *slog.Logger, runtime *serveRuntime) (func(http.Handler) http.Handler, func()) {
	profiles := make(map[string]ratelimit.ProfileOptions)
	for _, profile := range cfg.Clients.Profiles {
		opts := configLimitsToRateLimitOptions(profile.Name, profile.Limits, logger)
		if opts.Rate != nil || opts.Concurrency != nil || opts.Priority != ratelimit.PriorityNormal {
			profiles[profile.Name] = opts
		}
	}

	var globalConc *ratelimit.GlobalConcurrencyOptions
	if cfg.Clients.GlobalConcurrency != nil && cfg.Clients.GlobalConcurrency.MaxInflight > 0 {
		globalConc = &ratelimit.GlobalConcurrencyOptions{
			MaxInflight: cfg.Clients.GlobalConcurrency.MaxInflight,
		}
	}

	if len(profiles) == 0 && globalConc == nil {
		return nil, nil
	}

	warnAssignedProfilesWithoutLimits(cfg, profiles, logger)

	sampler, stopSampler := ratelimit.NewAuditSampler()
	mw, stopLimiters := ratelimit.Middleware(logger, runtime.metrics, sampler, ratelimit.MiddlewareOptions{
		Profiles:          profiles,
		ResolveProfile:    clientacl.RequestProfile,
		GlobalConcurrency: globalConc,
	})
	stop := func() {
		stopLimiters()
		stopSampler()
	}
	return mw, stop
}

func namedServeHandlerLayer(name string, with func(http.Handler) http.Handler) serveHandlerLayer {
	return serveHandlerLayer{name: name, with: with}
}

func withHijack(res *upstream.Resolver, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {

		return proxy.HijackHandlerWithDialer(res, logger, next)
	}
}

// withBuildkitMediator intercepts POST /session and POST /grpc once
// request_body.buildkit is configured for the request's effective policy
// (global, or the client profile clientacl resolved), handing them to
// internal/buildkitproxy.Mediator instead of letting them reach the plain
// ReverseProxy. filter.buildkitPolicy.inspect (see internal/filter/buildkit.go)
// already admitted these two paths at rule-evaluation time whenever
// TunnelConfigured was true; this layer is the actual h2c termination point,
// downstream of that admission — mirroring how withHijack is the real
// bidirectional-copy point for attach/exec, downstream of filter's own
// admission of those paths.
//
// When the resolved policy is NOT configured (the legacy
// insecure_accept_opaque_buildkit_tunnels path, or a request that reached
// here without either flag somehow — filter's admission gate makes that
// combination unreachable in practice), this layer is a no-op and the
// request falls through to next unchanged, exactly like Phase 1.
func withBuildkitMediator(cfg *config.Config, res *upstream.Resolver, logger *slog.Logger) func(http.Handler) http.Handler {
	warnIfOpaqueBuildkitTunnelDeprecated(cfg, logger)
	defaultPolicy := cfg.RequestBody.Buildkit.ToPolicy(cfg.RequestBody.Build)
	profilePolicies := make(map[string]buildkitproxy.Policy, len(cfg.Clients.Profiles))
	for _, profile := range cfg.Clients.Profiles {
		profilePolicies[profile.Name] = profile.RequestBody.Buildkit.ToPolicy(profile.RequestBody.Build)
	}
	mediator := buildkitproxy.NewMediator(res, logger)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			normPath := filter.NormalizePath(r.URL.Path)
			if r.Method != http.MethodPost || !filter.IsBuildkitTunnelPath(normPath) {
				next.ServeHTTP(w, r)
				return
			}

			profileName, hasProfile := clientacl.RequestProfile(r)
			policy := defaultPolicy
			if hasProfile {
				if p, ok := profilePolicies[profileName]; ok {
					policy = p
				}
			}
			if !policy.Configured() {
				next.ServeHTTP(w, r)
				return
			}

			key := buildkitproxy.SessionKey{ClientIdentity: r.RemoteAddr, Profile: profileName}
			switch normPath {
			case "/grpc":
				mediator.ServeGRPC(w, r, policy, key)
			case "/session":
				mediator.ServeSession(w, r, policy, key)
			}
		})
	}
}

// opaqueBuildkitTunnelWarnOnce gates warnIfOpaqueBuildkitTunnelDeprecated to a
// single emission per process, like bodyBlindWritesWarnOnce — withBuildkitMediator
// is a chain-build site rebuilt on every config hot-reload (the flag is not
// in reload.ImmutableFields), so an unguarded warning here would repeat on
// each reload.
var opaqueBuildkitTunnelWarnOnce sync.Once

// warnIfOpaqueBuildkitTunnelDeprecated surfaces the deprecation of
// insecure_accept_opaque_buildkit_tunnels now that request_body.buildkit
// (issue #185) provides full per-message mediation of the same POST
// /session and POST /grpc endpoints the flag wholesale-admits with zero
// inspection. validateBuildkitAckMutualExclusion (config/validate.go)
// already rejects the flag combined with a configured request_body.buildkit
// block, and validateAndCompileRules runs before the handler chain is ever
// built, so by the time this fires request_body.buildkit is guaranteed
// unconfigured everywhere — this warning and that validation error never
// fire for the same config.
func warnIfOpaqueBuildkitTunnelDeprecated(cfg *config.Config, logger *slog.Logger) {
	warnOpaqueBuildkitTunnelDeprecatedOnce(cfg, logger, &opaqueBuildkitTunnelWarnOnce)
}

// warnOpaqueBuildkitTunnelDeprecatedOnce is the testable core of
// warnIfOpaqueBuildkitTunnelDeprecated: the Once is injected so tests can
// verify both the enable-check and the once-per-process gating without
// racing other tests for the package-level guard.
func warnOpaqueBuildkitTunnelDeprecatedOnce(cfg *config.Config, logger *slog.Logger, once *sync.Once) {

	if !cfg.InsecureAcceptOpaqueBuildkitTunnels {
		return
	}
	once.Do(func() {
		logger.Warn("insecure_accept_opaque_buildkit_tunnels is deprecated: it admits POST /session and POST /grpc with zero inspection now that request_body.buildkit provides full per-message BuildKit mediation (issue #185); migrate to request_body.buildkit — this flag will be removed in a future major release")
	})
}

func withOwnership(cfg *config.Config, res *upstream.Resolver, logger *slog.Logger) func(http.Handler) http.Handler {
	return ownership.MiddlewareWithRoundTripper(res, logger, ownership.Options{
		Owner:                           cfg.Ownership.Owner,
		LabelKey:                        cfg.Ownership.LabelKey,
		AllowUnownedImages:              cfg.Ownership.AllowUnownedImages,
		AllowCrossOwnerNamespaceSharing: cfg.Ownership.AllowCrossOwnerNamespaceSharing,
	})
}

func withVisibility(cfg *config.Config, res *upstream.Resolver, logger *slog.Logger) func(http.Handler) http.Handler {
	return visibility.MiddlewareWithRoundTripper(res, logger, visibility.Options{
		VisibleResourceLabels: cfg.Response.VisibleResourceLabels,
		NamePatterns:          cfg.Response.NamePatterns,
		ImagePatterns:         cfg.Response.ImagePatterns,
		Profiles:              clientVisibilityProfiles(cfg.Clients.Profiles),
		ResolveProfile:        clientacl.RequestProfile,
	})
}

func withFilter(cfg *config.Config, res *upstream.Resolver, logger *slog.Logger, rules []*filter.CompiledRule, clientProfiles map[string]filter.Policy) func(http.Handler) http.Handler {
	warnIfBodyBlindWritesEnabled(cfg, logger)
	return filter.MiddlewareWithOptions(rules, logger, serveFilterOptions(cfg, res, clientProfiles))
}

// bodyBlindWritesWarnOnce gates warnIfBodyBlindWritesEnabled to a single
// emission per process, like labelACLWarnOnce — the handler chain is rebuilt
// on every config hot-reload, so an unguarded warning at the chain-build site
// would repeat on each reload.
var bodyBlindWritesWarnOnce sync.Once

// warnIfBodyBlindWritesEnabled surfaces the runtime consequence of
// insecure_allow_body_blind_writes: true at chain-build time (startup or
// hot-reload). The startup validator (validateBodyBlindWriteRulesForPolicy in
// rules.go) already refuses to start without this acknowledgment when a
// body-blind endpoint is reachable; this is the loud runtime echo of that same
// acknowledgment, visible in the running process's logs rather than only at
// validate time.
func warnIfBodyBlindWritesEnabled(cfg *config.Config, logger *slog.Logger) {
	warnBodyBlindWritesOnce(cfg, logger, &bodyBlindWritesWarnOnce)
}

func warnIfDefaultProfileExcluded(cfg *config.Config, logger *slog.Logger) {
	if cfg == nil || logger == nil || cfg.Clients.DefaultProfile == "" || len(cfg.Listeners) == 0 {
		return
	}
	for _, listener := range cfg.Listeners {
		if listener.Wildcard() || allowedProfileContains(listener.AllowedProfiles, cfg.Clients.DefaultProfile) {
			continue
		}
		logger.Warn("default profile is not allowed on listener; unmatched clients will be denied",
			"listener", listener.Name,
			"default_profile", cfg.Clients.DefaultProfile,
		)
	}
}

// warnBodyBlindWritesOnce is the testable core of warnIfBodyBlindWritesEnabled:
// the Once is injected so tests can verify both the enable-check and the
// once-per-process gating without racing other tests for the package-level
// guard.
func warnBodyBlindWritesOnce(cfg *config.Config, logger *slog.Logger, once *sync.Once) {
	if !cfg.InsecureAllowBodyBlindWrites {
		return
	}
	once.Do(func() {
		logger.Warn("insecure_allow_body_blind_writes is enabled: body-sensitive write endpoints with no request-body allowlist configured (e.g. exec with an empty allowed_commands) are reachable without that allowlist check — other configured gates (allow_privileged, allow_root_user, allowed_env_vars/denied_env_vars, allowed_join_remote_addrs, allowed_set_env_prefixes) still apply in full")
	})
}

// withHealth wires the /health endpoint onto the runtime monitor.
//
// Precondition: cfg.Health.Enabled is true, so newServeRuntime has already
// allocated runtime.health. The caller must guarantee this — a nil monitor
// here is a programming error and will panic on Handler() rather than be
// papered over with a silently-allocated fallback.
func withHealth(cfg *config.Config, runtime *serveRuntime) func(http.Handler) http.Handler {
	healthHandler := runtime.health.Handler()
	return func(next http.Handler) http.Handler {
		return pathInterceptor(cfg.Health.Path, healthHandler, next)
	}
}

// withReadiness wires the readiness endpoint onto the runtime's readiness
// monitor. Precondition: runtime.readiness is non-nil (cfg.Health.Readiness
// .Enabled), guaranteed by the caller as with withHealth.
func withReadiness(cfg *config.Config, runtime *serveRuntime) func(http.Handler) http.Handler {
	readinessHandler := runtime.readiness.Handler()
	return func(next http.Handler) http.Handler {
		return pathInterceptor(cfg.Health.Readiness.Path, readinessHandler, next)
	}
}

func withMetricsEndpoint(cfg *config.Config, registry *metrics.Registry) func(http.Handler) http.Handler {
	metricsHandler := registry.Handler()
	return func(next http.Handler) http.Handler {
		return pathInterceptor(cfg.Metrics.Path, metricsHandler, next)
	}
}

func withMetrics(registry *metrics.Registry) func(http.Handler) http.Handler {
	return registry.Middleware()
}

func withClientACL(cfg *config.Config, res *upstream.Resolver, logger *slog.Logger) func(http.Handler) http.Handler {
	warnIfLabelACLEnabled(cfg, logger)
	warnIfRulesHaveVersionPrefix(cfg, logger)
	return clientacl.MiddlewareWithRoundTripper(upstreamResolverFor(res, cfg), logger, serveClientACLOptions(cfg))
}

// rulesVersionPrefixWarnOnce gates warnIfRulesHaveVersionPrefix to a single
// emission per process, like labelACLWarnOnce. The guard before once.Do means
// the Once is only consumed when there is actually a prefixed rule to warn
// about, so a hot reload that introduces one still warns.
var rulesVersionPrefixWarnOnce sync.Once

// warnIfRulesHaveVersionPrefix flags rule patterns that begin with a Docker API
// version prefix (e.g. "/v1.45/..."). NormalizePath strips version prefixes from
// the request path before matching, so such a pattern can never match real
// traffic — the rule is silently dead, an intent gap worth surfacing.
func warnIfRulesHaveVersionPrefix(cfg *config.Config, logger *slog.Logger) {
	warnRulesVersionPrefixOnce(cfg, logger, &rulesVersionPrefixWarnOnce)
}

func warnRulesVersionPrefixOnce(cfg *config.Config, logger *slog.Logger, once *sync.Once) {
	var prefixed []string
	for _, r := range cfg.Rules {
		if filter.HasVersionPrefix(r.Match.Path) {
			prefixed = append(prefixed, r.Match.Path)
		}
	}
	if len(prefixed) == 0 {
		return
	}
	once.Do(func() {
		logger.Warn("one or more rule patterns begin with a Docker API version prefix (e.g. /v1.45/...); "+
			"sockguard strips version prefixes before matching, so these patterns never match real traffic — write the unversioned path",
			"patterns", prefixed,
		)
	})
}

// labelACLWarnOnce gates warnIfLabelACLEnabled to a single emission per
// process. The handler chain is rebuilt on every config hot-reload, so an
// unguarded warning at the chain-build site would repeat on each reload.
var labelACLWarnOnce sync.Once

// warnIfLabelACLEnabled reminds operators that container-label ACLs are only
// trustworthy when sockguard is the exclusive path to the Docker socket: a
// workload that can reach the raw socket can create a container carrying
// arbitrary <label_prefix>* permission labels and self-grant access the
// policy never approved. Sockguard cannot detect other socket consumers, so
// the invariant is stated rather than enforced — once per process, on the
// first chain build (startup or hot-reload) that has the feature enabled.
func warnIfLabelACLEnabled(cfg *config.Config, logger *slog.Logger) {
	warnLabelACLOnce(cfg, logger, &labelACLWarnOnce)
}

// warnLabelACLOnce is the testable core of warnIfLabelACLEnabled: the Once is
// injected so tests can verify both the enable-check and the once-per-process
// gating without racing other tests for the package-level guard.
func warnLabelACLOnce(cfg *config.Config, logger *slog.Logger, once *sync.Once) {
	if !cfg.Clients.ContainerLabels.Enabled {
		return
	}
	once.Do(func() {
		logger.Warn("container-label ACLs are enabled: label grants are only trustworthy if sockguard is the ONLY consumer of the Docker socket — any workload with raw socket access can self-grant permissions via labels",
			"label_prefix", cfg.Clients.ContainerLabels.LabelPrefix,
		)
	})
}

// withAdminClientACL applies ONLY the client CIDR allowlist to the dedicated
// admin listener. The dedicated admin chain intentionally omits the full
// clientacl middleware — container-label ACLs and per-profile selection are
// Docker-API concepts with no meaning for admin endpoints — but a TCP admin
// listener must still enforce the same clients.allowed_cidrs gate the main
// listener applies (#21). Passing only AllowedCIDRs yields a CIDR-only
// middleware; when no CIDRs are configured clientacl.Middleware compiles to a
// pass-through, so this is a no-op until an operator sets clients.allowed_cidrs.
//
// Because container-label ACLs are never enabled here, the middleware never
// resolves a client by source IP and so never dials the upstream — the socket
// argument is inert (it is not the shared resolver, by design, and is never
// used to reach Docker). It stays on the single-socket constructor deliberately
// so the admin trust boundary carries no dependency on the upstream resolver.
func withAdminClientACL(cfg *config.Config, logger *slog.Logger) func(http.Handler) http.Handler {
	return clientacl.Middleware(cfg.Upstream.Socket, logger, clientacl.Options{
		AllowedCIDRs: cfg.Clients.AllowedCIDRs,
	})
}

// mountOnGate restricts an in-band admin middleware (#149) to fire only on
// the listener named by cfg.Admin.MountOn. Every main listener shares ONE
// handler chain (reload.SwappableHandler), so without this gate an in-band
// admin endpoint mounted anywhere would be reachable from every main
// listener regardless of MountOn — silently widening the admin attack
// surface in proportion to listener count.
//
// The restriction is active exactly when config.validateAdminMountOn
// requires (and therefore guarantees, once Validate has passed) a non-empty,
// listener-matching MountOn: admin rides a main listener (no dedicated
// admin.listen) and there are 2+ effective main listeners. With <=1
// effective listener — every configuration that predates #149 — mw is
// returned unwrapped, preserving today's zero-config "admin rides the sole
// main listener" behavior byte-for-byte, including not requiring inbound
// identity to be present in request context.
func mountOnGate(cfg *config.Config, mw func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	if cfg.Admin.Listen.Configured() {
		return func(next http.Handler) http.Handler { return next }
	}
	if len(cfg.EffectiveListeners()) <= 1 {
		return mw
	}
	mountOn := cfg.Admin.MountOn
	return func(next http.Handler) http.Handler {
		gated := mw(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, ok := inbound.FromContext(r.Context())
			if ok && identity.Name == mountOn {
				gated.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func withAdminEndpoint(cfg *config.Config, logger *slog.Logger) func(http.Handler) http.Handler {
	return admin.NewValidateInterceptor(admin.Options{
		Path:            cfg.Admin.Path,
		MaxRequestBytes: cfg.Admin.MaxRequestBytes,
		Validate:        buildAdminValidator(logger),
		Logger:          logger,
	})
}

// withPolicyVersionEndpoint mounts the read-only GET admin.policy_version_path
// handler. The versioner pointer is captured by reference so updates the
// reload coordinator publishes after a successful swap are observable to the
// next caller without re-wrapping the chain.
func withPolicyVersionEndpoint(cfg *config.Config, logger *slog.Logger, versioner *admin.PolicyVersioner) func(http.Handler) http.Handler {
	return admin.NewPolicyVersionInterceptor(admin.PolicyVersionOptions{
		Path:   cfg.Admin.PolicyVersionPath,
		Source: versioner.Snapshot,
		Logger: logger,
	})
}

// verifyPolicyBundleAtStartup runs the bundle verifier against the raw
// YAML bytes of the on-disk config file. Returns (nil, nil) when
// policy_bundle is disabled so the caller can skip stamping bundle
// metadata onto the initial snapshot. Otherwise returns (*VerifyResult,
// nil) on success or (nil, err) on any failure — startup must abort in
// that case because the trust gate is the whole point of the feature.
//
// The supplied ctx is the cobra command context; SIGINT/SIGTERM during
// startup verification must cancel the verifier rather than block until the
// per-bundle deadline expires.
// verifyPolicyBundleAtStartup verifies the signed policy bundle and, on success,
// returns the authoritative *config.Config parsed from the exact bytes that were
// verified. The signed YAML is read once: the same byte slice is both checked
// against the signature and parsed (via deps.loadConfigBytes, which applies no
// SOCKGUARD_* environment overlay). This closes the verify-then-load TOCTOU
// (#8) — verification and application can no longer see different file contents
// — and stops environment variables from silently overriding signed policy
// (#16). When policy_bundle is disabled it returns (nil, nil, nil) and the
// caller keeps using the env-overlaid config.
func verifyPolicyBundleAtStartup(
	parent context.Context,
	cfg *config.Config,
	cfgFile string,
	deps *serveDeps,
	verifier policybundle.Verifier,
	logger *slog.Logger,
) (*policybundle.VerifyResult, *config.Config, error) {
	if !cfg.PolicyBundle.Enabled {
		return nil, nil, nil
	}
	if cfgFile == "" {
		return nil, nil, errors.New("policy_bundle.enabled=true but no --config file was supplied; sockguard cannot verify an in-memory default")
	}
	if cfg.PolicyBundle.SignaturePath == "" {
		return nil, nil, errors.New("policy_bundle.signature_path is required when policy_bundle.enabled=true")
	}

	yamlBytes, err := deps.readConfigBytes(cfgFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read config YAML for verification: %w", err)
	}
	entity, err := deps.loadBundleEntity(cfg.PolicyBundle.SignaturePath)
	if err != nil {
		return nil, nil, err
	}

	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, bundleVerifyDeadline(cfg.PolicyBundle))
	defer cancel()
	result, err := verifier.Verify(ctx, yamlBytes, entity)
	if err != nil {
		return nil, nil, err
	}

	signedCfg, err := deps.loadConfigBytes(yamlBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse verified config: %w", err)
	}

	logger.Info("policy bundle verified",
		"signature_path", cfg.PolicyBundle.SignaturePath,
		"signer", result.Signer,
		"digest", result.DigestHex,
		"elapsed_ms", result.ElapsedMS,
	)
	return &result, signedCfg, nil
}

// bundleVerifyDeadline returns the wall-clock budget for one verification
// attempt. The policybundle.BuildConfig parser is the authoritative source
// for the timeout but this helper avoids a second parse at the call site
// and degrades to the package default if the value is unset.
func bundleVerifyDeadline(pb config.PolicyBundleConfig) time.Duration {
	if pb.VerifyTimeout == "" {
		return policybundle.VerifyTimeout
	}
	d, err := time.ParseDuration(pb.VerifyTimeout)
	if err != nil || d <= 0 {
		return policybundle.VerifyTimeout
	}
	return d
}

// policyConfigHash returns a hex SHA-256 of the JSON encoding of the
// effective config. JSON marshaling of our config structs is deterministic
// because field order is fixed and no map[string]any leaks into the shape;
// that makes the hash a stable fingerprint operators can compare across
// scrapes to confirm two snapshots really represent the same config. An
// encoding failure is non-fatal — we return the empty string so the rest
// of the snapshot still publishes.
func policyConfigHash(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// buildAdminValidator returns the parse+validate+compile callback wired into
// the admin /admin/validate endpoint. It mirrors the offline `sockguard
// validate` command's pipeline (config.LoadBytes → ApplyCompat →
// validateAndCompileRules → compileClientProfiles) so an operator's CI gate
// and the running proxy reach the same verdict for the same YAML.
//
// ApplyCompat uses a discard logger here because compat-expansion log noise
// belongs to the proxy's own startup, not to a candidate-config validation
// request. The returned response still carries CompatActive so callers see
// whether legacy env aliases would have fired.
func buildAdminValidator(parentLogger *slog.Logger) admin.Validator {
	return func(yamlBody []byte) admin.ValidateResponse {
		cfg, err := config.LoadBytes(yamlBody)
		if err != nil {
			return admin.ValidateResponse{OK: false, Errors: []string{"parse: " + err.Error()}}
		}

		compatActive := config.ApplyCompat(cfg, discardLogger)

		compiled, compileErr := validateAndCompileRules(cfg)
		if compileErr != nil {
			return admin.ValidateResponse{
				OK:           false,
				Errors:       splitValidationError(compileErr),
				CompatActive: compatActive,
			}
		}

		return admin.ValidateResponse{
			OK:           true,
			Rules:        len(compiled),
			Profiles:     len(cfg.Clients.Profiles),
			CompatActive: compatActive,
		}
	}
}

// splitValidationError unwraps a *config.ValidationError into its
// per-issue lines so the admin endpoint can return a structured list
// instead of one wrapped string. Non-validation errors (e.g. rule-compile
// failures from filter.CompileRule) fall through as a single-element slice.
func splitValidationError(err error) []string {
	var vErr *config.ValidationError
	if errors.As(err, &vErr) {
		out := make([]string, 0, len(vErr.Errors))
		out = append(out, vErr.Errors...)
		return out
	}
	return []string{err.Error()}
}

func withRequestID() func(http.Handler) http.Handler {
	return logging.RequestIDMiddleware()
}

func withTraceContext() func(http.Handler) http.Handler {
	return logging.TraceContextMiddleware()
}

func withAccessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return logging.AccessLogMiddleware(logger)
}

func withAuditLog(auditLogger *logging.AuditLogger, cfg *config.Config) func(http.Handler) http.Handler {
	return logging.AuditLogMiddleware(auditLogger, logging.AuditOptions{
		Listener:          auditListener(cfg),
		OwnershipOwner:    cfg.Ownership.Owner,
		OwnershipLabelKey: cfg.Ownership.LabelKey,
	})
}

func auditListener(cfg *config.Config) string {
	if cfg != nil && cfg.Listen.Socket != "" {
		return "unix"
	}
	return "tcp"
}

func serveResponseFilterOptions(cfg *config.Config) responsefilter.Options {
	return responsefilter.Options{
		RedactContainerEnv:         cfg.Response.RedactContainerEnv,
		RedactMountPaths:           cfg.Response.RedactMountPaths,
		RedactNetworkTopology:      cfg.Response.RedactNetworkTopology,
		RedactSensitiveData:        cfg.Response.RedactSensitiveData,
		RedactHostTopology:         cfg.Response.RedactHostTopology,
		AllowAttestationStatements: cfg.Response.AllowAttestationStatements,
	}
}

func serveFilterOptions(cfg *config.Config, res *upstream.Resolver, clientProfiles map[string]filter.Policy) filter.Options {
	return filter.Options{
		PolicyConfig:   servePolicyConfig(cfg, res),
		Profiles:       clientProfiles,
		ResolveProfile: clientacl.RequestProfile,
		Mutation:       cfg.Mutations.ToFilterOptions(),
	}
}

func servePolicyConfig(cfg *config.Config, res *upstream.Resolver) filter.PolicyConfig {
	policy := cfg.RequestBody.ToFilterOptions()
	policy.DenyResponseVerbosity = filter.ParseDenyResponseVerbosity(cfg.Response.DenyVerbosity)
	return attachRuntimeInspectors(cfg, res, policy)
}

// withResourceLimitGuard returns the #152 post-ownership resource-limit guard
// layer (internal/filter/resource_limit_guard.go). It reuses the same
// PolicyConfig/profile map/ResolveProfile wiring servePolicyConfig and
// clientProfiles already provide to withFilter, plus two runtime inspectors
// (container/service state GETs) issued through the shared upstream resolver.
func withResourceLimitGuard(cfg *config.Config, res *upstream.Resolver, logger *slog.Logger, clientProfiles map[string]filter.Policy) func(http.Handler) http.Handler {
	warnIfResourceLimitRequireWithoutAllowResourceUpdates(cfg, logger)
	rt := upstreamResolverFor(res, cfg)
	return filter.ResourceLimitGuardWithOptions(logger, filter.ResourceLimitGuardOptions{
		PolicyConfig:     servePolicyConfig(cfg, res),
		Profiles:         clientProfiles,
		ResolveProfile:   clientacl.RequestProfile,
		InspectContainer: filter.NewDockerContainerUpdateInspectorWithRoundTripper(rt),
		InspectService:   filter.NewDockerServiceInspectorWithRoundTripper(rt),
	})
}

// resourceLimitRequireWarnOnce gates warnIfResourceLimitRequireWithoutAllowResourceUpdates
// to a single emission per process, like labelACLWarnOnce — the handler chain
// is rebuilt on every config hot-reload, so an unguarded warning at the
// chain-build site would repeat on each reload.
var resourceLimitRequireWarnOnce sync.Once

// warnIfResourceLimitRequireWithoutAllowResourceUpdates surfaces the likely-
// confusion case from ContainerUpdateRequestBodyConfig's doc comment: a
// require_* resource-limit flag enabled while allow_resource_updates is
// false is not a config error (the existing blanket deny already provides
// the guarantee those flags would otherwise add), but an operator who set
// require_memory_limit: true expecting it to do something almost certainly
// also meant to set allow_resource_updates: true.
func warnIfResourceLimitRequireWithoutAllowResourceUpdates(cfg *config.Config, logger *slog.Logger) {
	warnResourceLimitRequireOnce(cfg, logger, &resourceLimitRequireWarnOnce)
}

// warnResourceLimitRequireOnce is the testable core of
// warnIfResourceLimitRequireWithoutAllowResourceUpdates: the Once is injected
// so tests can verify both the enable-check and the once-per-process gating
// without racing other tests for the package-level guard.
func warnResourceLimitRequireOnce(cfg *config.Config, logger *slog.Logger, once *sync.Once) {
	misconfigured := resourceLimitRequireWithoutGate(cfg.RequestBody.ContainerUpdate)
	for _, profile := range cfg.Clients.Profiles {
		if resourceLimitRequireWithoutGate(profile.RequestBody.ContainerUpdate) {
			misconfigured = true
			break
		}
	}
	if !misconfigured {
		return
	}
	once.Do(func() {
		logger.Warn("request_body.container_update (default policy and/or one or more client profiles) has a require_* resource-limit flag enabled while allow_resource_updates is false: the flag is currently a no-op there — the existing blanket deny of resource-control fields already blocks every resource update, so set allow_resource_updates: true to activate the require_* check, or drop the require_* flag to avoid confusion")
	})
}

func resourceLimitRequireWithoutGate(cu config.ContainerUpdateRequestBodyConfig) bool {
	if cu.AllowResourceUpdates {
		return false
	}
	return cu.RequireMemoryLimit || cu.RequireCPULimit || cu.RequireCPULimitHard || cu.RequirePidsLimit
}

func serveClientACLOptions(cfg *config.Config) clientacl.Options {
	return clientacl.Options{
		AllowedCIDRs: cfg.Clients.AllowedCIDRs,
		ContainerLabels: clientacl.ContainerLabelOptions{
			Enabled:     cfg.Clients.ContainerLabels.Enabled,
			LabelPrefix: cfg.Clients.ContainerLabels.LabelPrefix,
		},
		Profiles: clientacl.ProfileOptions{
			DefaultProfile: cfg.Clients.DefaultProfile,
			SourceIPs:      clientSourceIPProfiles(cfg.Clients.SourceIPProfiles),
			ClientCertificates: clientCertificateProfiles(
				cfg.Clients.ClientCertificateProfiles,
			),
			UnixPeers: clientUnixPeerProfiles(cfg.Clients.UnixPeerProfiles),
		},
		ProfileModes: clientProfileModes(cfg.Clients.Profiles),
	}
}

// clientProfileModes flattens cfg.Clients.Profiles into the
// (profileName -> rolloutMode) map clientacl uses to stamp meta.RolloutMode
// when a profile is selected. Modes that fail to parse fall back to enforce;
// the config validator already rejects unknown values at startup, so the
// fallback is a defense-in-depth no-op under normal operation.
func clientProfileModes(profiles []config.ClientProfileConfig) map[string]string {
	if len(profiles) == 0 {
		return nil
	}
	modes := make(map[string]string, len(profiles))
	for _, p := range profiles {
		mode, _ := config.ParseRolloutMode(p.Mode)
		modes[p.Name] = mode.String()
	}
	return modes
}

func clientSourceIPProfiles(values []config.ClientSourceIPProfileAssignmentConfig) []clientacl.SourceIPProfileAssignment {
	assignments := make([]clientacl.SourceIPProfileAssignment, 0, len(values))
	for _, value := range values {
		assignments = append(assignments, clientacl.SourceIPProfileAssignment{
			Profile: value.Profile,
			CIDRs:   value.CIDRs,
		})
	}
	return assignments
}

func clientCertificateProfiles(values []config.ClientCertificateProfileAssignmentConfig) []clientacl.ClientCertificateProfileAssignment {
	assignments := make([]clientacl.ClientCertificateProfileAssignment, 0, len(values))
	for _, value := range values {
		assignments = append(assignments, clientacl.ClientCertificateProfileAssignment{
			Profile:             value.Profile,
			CommonNames:         value.CommonNames,
			DNSNames:            value.DNSNames,
			IPAddresses:         value.IPAddresses,
			URISANs:             value.URISANs,
			SPIFFEIDs:           value.SPIFFEIDs,
			PublicKeySHA256Pins: value.PublicKeySHA256Pins,
		})
	}
	return assignments
}

func clientUnixPeerProfiles(values []config.ClientUnixPeerProfileAssignmentConfig) []clientacl.UnixPeerProfileAssignment {
	assignments := make([]clientacl.UnixPeerProfileAssignment, 0, len(values))
	for _, value := range values {
		assignments = append(assignments, clientacl.UnixPeerProfileAssignment{
			Profile: value.Profile,
			UIDs:    value.UIDs,
			GIDs:    value.GIDs,
			PIDs:    value.PIDs,
		})
	}
	return assignments
}

func clientVisibilityProfiles(values []config.ClientProfileConfig) map[string]visibility.Policy {
	profiles := make(map[string]visibility.Policy, len(values))
	for _, value := range values {
		profiles[value.Name] = visibility.Policy{
			VisibleResourceLabels: value.Response.VisibleResourceLabels,
			NamePatterns:          value.Response.NamePatterns,
			ImagePatterns:         value.Response.ImagePatterns,
		}
	}
	return profiles
}

// buildAdminHandlerChain composes the http.Handler used by the dedicated
// admin listener (admin.listen configured). It mounts the validate and
// policy-version interceptors over a 404 terminator and wraps the result in
// the observability layers (request-id, trace context, optional audit log,
// optional access log) so the admin surface still emits the same kind of
// telemetry as the main listener.
//
// Note: rate-limit, client ACL, ownership, visibility, hijack, and the
// Docker-API filter are intentionally NOT applied — the admin listener is a
// distinct trust boundary whose access control is the bind target plus
// admin.listen.tls, not the per-profile policy that gates Docker-API
// traffic on the main listener.
func buildAdminHandlerChain(cfg *config.Config, logger *slog.Logger, auditLogger *logging.AuditLogger, versioner *admin.PolicyVersioner) http.Handler {
	terminal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		logging.SetDeniedWithCode(w, r, "admin_unknown_path", "unknown admin path", nil)
		_ = httpjson.Write(w, http.StatusNotFound, httpjson.ErrorResponse{Message: "not found"})
	})

	var h http.Handler = terminal
	h = withAdminEndpoint(cfg, logger)(h)
	if versioner != nil {
		h = withPolicyVersionEndpoint(cfg, logger, versioner)(h)
	}

	if cfg.Admin.Listen.Address != "" {
		h = withAdminClientACL(cfg, logger)(h)
	}
	if cfg.Log.Audit.Enabled && auditLogger != nil {
		h = withAuditLog(auditLogger, cfg)(h)
	}
	h = withRequestID()(h)
	h = withTraceContext()(h)
	if cfg.Log.AccessLog {
		h = withAccessLog(logger)(h)
	}
	return h
}

// newAdminHTTPServer returns the http.Server for the dedicated admin
// listener. Unlike the main server it sets explicit Read/Write timeouts:
// admin endpoints never stream and never hijack, so a runaway client cannot
// be allowed to hold a goroutine open forever. The timeout has to be generous
// enough that the validator (which compiles regex/glob inputs and parses TLS
// material) still finishes on a contented box — 30s is comfortably above
// observed validation latencies.
func newAdminHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ConnContext:       clientacl.ConnContext,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}

// warnIfAdminListenerWideOpen emits a startup warning when the dedicated admin
// listener is a non-loopback plaintext (non-mTLS) TCP listener with no client
// CIDR allowlist. In that configuration the admin endpoints — which accept YAML
// for parsing and expose policy metadata — are reachable by any host that can
// route to the port, with neither authentication nor an IP backstop (#21). The
// CIDR guard in buildAdminHandlerChain closes the gap when clients.allowed_cidrs
// is set. Config validation now rejects this shape outright unless
// admin.listen.insecure_allow_wide_open acknowledges it, so by the time this
// warning fires the operator has explicitly opted in — it keeps the exposure
// visible in the logs rather than gating startup.
func warnIfAdminListenerWideOpen(cfg *config.Config, logger *slog.Logger) {
	listen := cfg.Admin.Listen
	if listen.Address == "" || listen.TLS.Complete() {
		return
	}
	if config.IsLoopbackTCPAddress(listen.Address) {
		return
	}
	if len(cfg.Clients.AllowedCIDRs) > 0 {
		return
	}
	logger.Warn("admin listener is non-loopback plaintext TCP with no client CIDR allowlist: admin endpoints are reachable without authentication from any source IP — configure admin.listen.tls (mutual TLS) or clients.allowed_cidrs",
		"address", listen.Address,
	)
}

// adminListenerAddr returns a human-readable address for the dedicated admin
// listener so logging can show operators where the admin endpoints are
// bound. Mirrors listenerAddr.
func adminListenerAddr(cfg *config.Config) string {
	if cfg.Admin.Listen.Socket != "" {
		return "unix:" + cfg.Admin.Listen.Socket
	}
	return "tcp://" + cfg.Admin.Listen.Address
}

func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:     handler,
		ConnContext: clientacl.ConnContext,

		ReadTimeout:       0,
		WriteTimeout:      0,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}

// applyFlagOverrides applies CLI flags that were explicitly set.
func applyFlagOverrides(cmd *cobra.Command, cfg *config.Config) error {
	return applyStringFlagOverrides(cmd, []stringFlagOverride{
		{
			name: "listen-socket",
			set: func(v string) {
				cfg.Listen.Socket = v
			},
		},
		{
			name: "upstream-socket",
			set: func(v string) {
				cfg.Upstream.Socket = v
			},
		},
		{
			name: "log-level",
			set: func(v string) {
				cfg.Log.Level = v
			},
		},
		{
			name: "log-format",
			set: func(v string) {
				cfg.Log.Format = v
			},
		},
		{
			name: "deny-verbosity",
			set: func(v string) {
				cfg.Response.DenyVerbosity = v
			},
		},
	})
}

type stringFlagOverride struct {
	name string
	set  func(string)
}

func applyStringFlagOverrides(cmd *cobra.Command, overrides []stringFlagOverride) error {
	for _, override := range overrides {
		if err := applyStringFlagOverride(cmd, override.name, override.set); err != nil {
			return err
		}
	}
	return nil
}

func applyStringFlagOverride(cmd *cobra.Command, name string, set func(string)) error {
	if !cmd.Flags().Changed(name) {
		return nil
	}

	v, err := cmd.Flags().GetString(name)
	if err != nil {
		return fmt.Errorf("get %s flag: %w", name, err)
	}
	set(v)
	return nil
}

// createListener creates a Unix socket or TCP listener based on config.
func socketCreateUmask(mode os.FileMode) int {
	return int(0o777 &^ mode.Perm())
}

func isAddrInUse(err error) bool {
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr) && errors.Is(opErr.Err, syscall.EADDRINUSE)
}

// pathInterceptor short-circuits GET requests matching path to target,
// passing all other requests to next.
//
// Used for health and metrics endpoints, which both sit ahead of Docker-API
// filtering in the middleware chain and share identical dispatch logic.
func pathInterceptor(path string, target, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == path {
			target.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// listenerAddr returns a human-readable address for logging.
func listenerAddr(cfg *config.Config) string {
	if cfg.Listen.Socket != "" {
		return "unix:" + cfg.Listen.Socket
	}
	return "tcp://" + cfg.Listen.Address
}

// withListenerAdmission enforces each effective listener's allowed_profiles
// scope (#149). It must run after clientacl's middleware has resolved the
// request's profile (clientacl.RequestProfile) — see the layer ordering
// comment in buildServeHandlerLayersWithRuntime — and reads the connection's
// listener identity from context (inbound.FromContext), never from a
// request header, so a client cannot forge which listener it arrived on.
//
// A listener whose AllowedProfiles is exactly the wildcard ("*", the legacy
// synthesized default and the explicit opt-in) admits every profile,
// including the unprofiled default-policy path, matching pre-#149 global
// behavior byte-for-byte — the gate is skipped entirely rather than
// evaluated against a permit-everything set. A concrete AllowedProfiles list
// only ever narrows: a resolved profile outside that list is denied with
// reason_code listener_profile_not_allowed. This function never retries
// against a weaker identity selector — the profile clientacl already
// resolved (certificate > unix peer > source IP > default) is final.
//
// Missing or unrecognized connection identity — the ConnContext hook did not
// run, or named a listener this config no longer knows about — is a
// programming/wiring error, not a client-controllable condition, so it fails
// closed with 500 rather than either silently admitting or silently
// denying.
func withListenerAdmission(cfg *config.Config) func(http.Handler) http.Handler {
	if len(cfg.Listeners) == 0 {

		return func(next http.Handler) http.Handler { return next }
	}

	byName := make(map[string]config.ListenerConfig, len(cfg.Listeners))
	for _, l := range cfg.Listeners {
		byName[l.Name] = l
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, ok := inbound.FromContext(r.Context())
			if !ok || identity.Role != inbound.RoleMain {
				denyListenerAdmission(w, r, http.StatusInternalServerError,
					"listener_identity_missing", "listener identity missing or invalid")
				return
			}

			entry, ok := byName[identity.Name]
			if !ok {
				denyListenerAdmission(w, r, http.StatusInternalServerError,
					"listener_config_missing", "listener configuration not found")
				return
			}

			if entry.Wildcard() {
				next.ServeHTTP(w, r)
				return
			}

			profile, ok := clientacl.RequestProfile(r)
			if !ok || !allowedProfileContains(entry.AllowedProfiles, profile) {
				denyListenerAdmission(w, r, http.StatusForbidden,
					"listener_profile_not_allowed", "client profile not allowed on this listener")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func allowedProfileContains(allowed []string, profile string) bool {
	for _, p := range allowed {
		if p == profile {
			return true
		}
	}
	return false
}

func denyListenerAdmission(w http.ResponseWriter, r *http.Request, status int, reasonCode, reason string) {
	logging.SetDeniedWithCode(w, r, reasonCode, reason, filter.NormalizePath)
	_ = httpjson.Write(w, status, httpjson.ErrorResponse{Message: reason})
}

type serveDeps struct {
	loadConfig          func(string) (*config.Config, error)
	loadConfigBytes     func([]byte) (*config.Config, error)
	readConfigBytes     func(string) ([]byte, error)
	newLogger           func(string, string, string) (*slog.Logger, io.Closer, error)
	newAuditLogger      func(string, string) (*logging.AuditLogger, io.Closer, error)
	validateRules       func(*config.Config) ([]*filter.CompiledRule, error)
	dialUpstream        func(string, string, time.Duration) (net.Conn, error)
	listenNetwork       func(string, string) (net.Listener, error)
	lstatPath           func(string) (os.FileInfo, error)
	isAddrInUse         func(error) bool
	createServeListener func(*config.Config) (net.Listener, error)
	createAdminListener func(*config.Config) (net.Listener, error)
	// createNamedListener binds one explicit listeners[*] entry (#149). Only
	// used when len(cfg.Listeners) > 0 — the legacy single-listener path
	// keeps going through createServeListener above so its existing test
	// doubles keep working unchanged.
	createNamedListener func(*config.Config, config.ListenerConfig) (net.Listener, error)
	// probeUnixSocket returns the result of connecting to a unix socket path
	// found at bind time (EADDRINUSE). Only an error matching ECONNREFUSED is
	// proof that the socket is stale; nil means live and every other error is
	// ambiguous and must preserve the path (#149).
	probeUnixSocket     func(string) error
	chown               func(string, int, int) error
	buildBundleVerifier func(config.PolicyBundleConfig) (policybundle.Verifier, error)
	loadBundleEntity    func(string) (verify.SignedEntity, error)
	notifySignals       func(chan<- os.Signal, ...os.Signal)
	startServing        func(*http.Server, net.Listener, chan<- error)
	shutdownServer      func(*http.Server, context.Context) error
	removePath          func(string) error
	now                 func() time.Time
	shutdownGracePeriod time.Duration
	umask               func(int) int
	umaskMu             *sync.Mutex
}

var processUmaskMu sync.Mutex

func newServeDeps() *serveDeps {
	deps := &serveDeps{
		loadConfig:          config.Load,
		loadConfigBytes:     config.LoadBytes,
		readConfigBytes:     os.ReadFile,
		newLogger:           logging.New,
		newAuditLogger:      logging.NewAudit,
		validateRules:       validateAndCompileRules,
		dialUpstream:        net.DialTimeout,
		listenNetwork:       net.Listen,
		lstatPath:           os.Lstat,
		isAddrInUse:         isAddrInUse,
		probeUnixSocket:     defaultProbeUnixSocket,
		chown:               os.Chown,
		buildBundleVerifier: defaultBuildBundleVerifier,
		loadBundleEntity:    policybundle.LoadBundle,
		notifySignals:       signal.Notify,
		startServing:        defaultServeStart,
		shutdownServer:      defaultServeShutdown,
		removePath:          os.Remove,
		now:                 time.Now,
		shutdownGracePeriod: 30 * time.Second,
		umask:               syscall.Umask,
		umaskMu:             &processUmaskMu,
	}
	deps.createServeListener = deps.createListener
	deps.createAdminListener = deps.createAdminListenerImpl
	deps.createNamedListener = deps.createNamedListenerImpl
	return deps
}

// defaultBuildBundleVerifier compiles a policy_bundle config into a
// runtime Verifier. The result is bound at startup and reused across every
// reload because policy_bundle's trust material is reload-immutable.
//
// When pb.Enabled=false the returned Verifier rejects calls — wiring code
// must guard on Enabled before invoking Verify.
func defaultBuildBundleVerifier(pb config.PolicyBundleConfig) (policybundle.Verifier, error) {
	raw := policybundle.RawConfig{
		Enabled:               pb.Enabled,
		RequireRekorInclusion: pb.RequireRekorInclusion,
		VerifyTimeoutStr:      pb.VerifyTimeout,
	}
	for _, k := range pb.AllowedSigningKeys {
		raw.AllowedSigningKeys = append(raw.AllowedSigningKeys, policybundle.SigningKeyConfig{PEM: k.PEM})
	}
	for _, kl := range pb.AllowedKeyless {
		raw.AllowedKeyless = append(raw.AllowedKeyless, policybundle.KeylessConfig{
			Issuer:         kl.Issuer,
			SubjectPattern: kl.SubjectPattern,
		})
	}
	cfg, err := policybundle.BuildConfig(raw)
	if err != nil {
		return nil, err
	}

	if len(cfg.AllowedKeyless) > 0 && cfg.TrustedMaterial == nil {
		return nil, errors.New("policy_bundle.allowed_keyless is configured but the production TUF trust root is not yet wired; configure allowed_signing_keys for now")
	}
	return policybundle.New(cfg)
}

func defaultServeStart(server *http.Server, ln net.Listener, errCh chan<- error) {
	errCh <- server.Serve(ln)
}

func defaultServeShutdown(server *http.Server, ctx context.Context) error {
	return server.Shutdown(ctx)
}

func (d *serveDeps) verifyUpstreamReachable(upstreamSocket string, logger *slog.Logger) error {
	conn, err := d.dialUpstream("unix", upstreamSocket, 5*time.Second)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("upstream socket not found (%s): %w", upstreamSocket, err)
		case errors.Is(err, os.ErrPermission):
			return fmt.Errorf("permission denied on upstream socket (%s): %w", upstreamSocket, err)
		default:
			return fmt.Errorf("upstream socket unreachable (%s): %w", upstreamSocket, err)
		}
	}
	if closeErr := conn.Close(); closeErr != nil {
		logger.Debug("failed to close upstream check connection", "error", closeErr)
	}
	return nil
}

func (d *serveDeps) createListener(cfg *config.Config) (net.Listener, error) {
	if cfg.Listen.Socket != "" {
		return d.createSocketListener("listen", cfg.Listen.Socket, cfg.Listen.SocketMode, cfg.Listen.SocketUID, cfg.Listen.SocketGID)
	}

	return d.createTCPListener(cfg.Listen.Address, cfg.Listen.TLS)
}

// createAdminListenerImpl builds the dedicated admin listener described by
// cfg.Admin.Listen. It reuses createSocketListener / createTCPListener so the
// hardened socket-mode and mTLS posture stays in lockstep with the main
// listener — the only difference is which config sub-block feeds the inputs.
// Callers must guard with cfg.Admin.Listen.Configured(); calling this with
// an unconfigured Listen returns an error rather than silently binding 0.0.0.0.
func (d *serveDeps) createAdminListenerImpl(cfg *config.Config) (net.Listener, error) {
	listen := cfg.Admin.Listen
	if !listen.Configured() {
		return nil, fmt.Errorf("admin listener not configured")
	}
	if listen.Socket != "" {
		return d.createSocketListener("admin.listen", listen.Socket, listen.SocketMode, listen.SocketUID, listen.SocketGID)
	}
	return d.createTCPListener(listen.Address, listen.TLS)
}

// createNamedListenerImpl binds one explicit listeners[*] entry (#149). It is
// only reached when cfg.Listeners is non-empty — see EffectiveListeners and
// the createNamedListener field doc.
func (d *serveDeps) createNamedListenerImpl(cfg *config.Config, entry config.ListenerConfig) (net.Listener, error) {
	if entry.Socket != "" {
		return d.createSocketListener(fmt.Sprintf("listeners[%s]", entry.Name), entry.Socket, entry.SocketMode, entry.SocketUID, entry.SocketGID)
	}
	return d.createTCPListener(entry.Address, entry.TLS)
}

// createSocketListener binds a unix-socket listener under the hardened
// (0600, the default) or group-readable (0660, requires socket_gid) mode —
// see config.validateSocketOwnership, which is the authoritative validator;
// this is a defense-in-depth check that should never fire against a config
// that already passed config.Validate(). uid/gid, when non-nil, chown the
// freshly bound socket after listen succeeds.
func (d *serveDeps) createSocketListener(prefix, path, modeValue string, uid, gid *int) (net.Listener, error) {
	fileMode, err := socketListenFileMode(prefix, modeValue, gid)
	if err != nil {
		return nil, err
	}

	var ln net.Listener
	if fileMode == config.HardenedListenSocketFileMode {

		ln, err = d.listenUnixSocket(path)
	} else {
		ln, err = d.listenUnixSocketWithMode(path, fileMode)
	}
	if err != nil {
		return nil, err
	}

	if uid == nil && gid == nil {
		return ln, nil
	}
	if err := d.chownSocket(path, uid, gid); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// socketListenFileMode maps a validated socket_mode string to its
// os.FileMode, requiring an explicit gid for the group-readable mode —
// mirrors config.validateSocketOwnership so the runtime check and the
// config-time validator can never disagree about which combinations are
// legal.
func socketListenFileMode(prefix, modeValue string, gid *int) (os.FileMode, error) {
	switch strings.TrimSpace(modeValue) {
	case config.HardenedListenSocketMode:
		return config.HardenedListenSocketFileMode, nil
	case config.GroupReadableListenSocketMode:
		if gid == nil {
			return 0, fmt.Errorf("%s.socket_mode %q requires %s.socket_gid to be set explicitly; omit socket_gid and use %q for the default owner-only mode",
				prefix, config.GroupReadableListenSocketMode, prefix, config.HardenedListenSocketMode)
		}
		return config.GroupReadableListenSocketFileMode, nil
	default:
		return 0, fmt.Errorf("%s.socket_mode must be %q or %q (the latter requires %s.socket_gid), got %q",
			prefix, config.HardenedListenSocketMode, config.GroupReadableListenSocketMode, prefix, modeValue)
	}
}

func (d *serveDeps) chownSocket(path string, uid, gid *int) error {
	resolvedUID, resolvedGID := -1, -1
	if uid != nil {
		resolvedUID = *uid
	}
	if gid != nil {
		resolvedGID = *gid
	}
	if err := d.chown(path, resolvedUID, resolvedGID); err != nil {
		return fmt.Errorf("chown socket %q: %w", path, err)
	}
	return nil
}

func (d *serveDeps) createTCPListener(address string, tlsCfg config.ListenTLSConfig) (net.Listener, error) {
	ln, err := d.listenNetwork("tcp", address)
	if err != nil {
		return nil, err
	}
	if !tlsCfg.Complete() {
		return ln, nil
	}

	return d.wrapListenerWithTLS(ln, tlsCfg)
}

func (d *serveDeps) wrapListenerWithTLS(ln net.Listener, tlsCfg config.ListenTLSConfig) (net.Listener, error) {
	tlsConfig, err := config.BuildMutualTLSServerConfig(tlsCfg)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}

	return tls.NewListener(ln, tlsConfig), nil
}

func (d *serveDeps) listenUnixSocket(path string) (net.Listener, error) {
	return d.listenUnixSocketWithMode(path, config.HardenedListenSocketFileMode)
}

// listenUnixSocketWithMode binds a unix socket at the given file mode,
// replacing a stale socket left behind by a crashed previous instance.
//
// "Stale" is no longer inferred from EADDRINUSE alone (#149). Before
// unlinking anything, probeUnixSocket dials the path. A successful dial proves
// another process is actively serving. Only ECONNREFUSED proves the existing
// socket is dead; timeouts, ENOENT races, permission failures, and every other
// result are ambiguous and fail startup without removal. After the refused
// probe, a second Lstat must still identify the same socket inode/device that
// was inspected before the probe.
func (d *serveDeps) listenUnixSocketWithMode(path string, fileMode os.FileMode) (net.Listener, error) {
	return d.withUmask(socketCreateUmask(fileMode), func() (net.Listener, error) {
		ln, err := d.listenNetwork("unix", path)
		if err == nil {
			return ln, nil
		}
		if !d.isAddrInUse(err) {
			return nil, err
		}

		info, statErr := d.lstatPath(path)
		if statErr != nil {
			return nil, fmt.Errorf("socket path already in use and could not inspect %q: %w", path, statErr)
		}
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("socket path %q exists and is not a socket", path)
		}
		before := socketIdentityFromFileInfo(info)
		probeErr := d.probeUnixSocket(path)
		if probeErr == nil {
			return nil, fmt.Errorf("socket path %q is actively serving another process; refusing to steal a live listener", path)
		}
		if !errors.Is(probeErr, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("socket path %q probe result is ambiguous; refusing to remove it: %w", path, probeErr)
		}
		afterInfo, afterErr := d.lstatPath(path)
		if afterErr != nil {
			return nil, fmt.Errorf("socket path %q changed during stale-socket probe: %w", path, afterErr)
		}
		if afterInfo.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("socket path %q changed during stale-socket probe and is no longer a socket", path)
		}
		after := socketIdentityFromFileInfo(afterInfo)
		if !before.valid || !after.valid || before != after {
			return nil, fmt.Errorf("socket path %q changed during stale-socket probe; refusing to remove it", path)
		}
		if removeErr := d.removePath(path); removeErr != nil {
			if !os.IsNotExist(removeErr) {
				return nil, fmt.Errorf("remove stale socket: %w", removeErr)
			}
		}

		ln, err = d.listenNetwork("unix", path)
		if err != nil {
			return nil, err
		}
		return ln, nil
	})
}

// defaultProbeUnixSocket dials path with a short timeout and returns the exact
// connect result so the caller can distinguish a proven ECONNREFUSED stale
// socket from every ambiguous failure.
func defaultProbeUnixSocket(path string) error {
	conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func (d *serveDeps) withUmask(mask int, fn func() (net.Listener, error)) (net.Listener, error) {
	d.umaskMu.Lock()
	defer d.umaskMu.Unlock()

	previous := d.umask(mask)
	ln, err := fn()
	d.umask(previous)

	return ln, err
}

// listenerStatusBoard tracks each configured listener's lifecycle state
// (#149) for the /health response (health.ListenerStatus). Safe for
// concurrent use: writes come from the bind/publish/shutdown call sites
// below, reads come from whichever goroutine is currently serving a
// /health request — both can run concurrently with each other and with
// writes from other listeners' goroutines.
type listenerStatusBoard struct {
	mu      sync.Mutex
	entries map[string]health.ListenerStatus
}

func newListenerStatusBoard() *listenerStatusBoard {
	return &listenerStatusBoard{entries: make(map[string]health.ListenerStatus)}
}

// register creates (or overwrites) a board entry with identity's Name/Role/
// Network and the given state. Called once per listener when its full
// identity first becomes known — at bind time for main listeners, at
// startup for the admin listener.
func (b *listenerStatusBoard) register(identity inbound.Identity, state string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries[identity.Name] = health.ListenerStatus{
		Name:    identity.Name,
		Role:    string(identity.Role),
		Network: string(identity.Network),
		State:   state,
	}
}

// setState updates only the State field of an already-registered entry,
// leaving Name/Role/Network untouched. A no-op if name was never
// registered — callers that only have a name (e.g. the error fan-in, which
// carries listenerResult, not a full inbound.Identity) can't accidentally
// fabricate an entry with an empty Network/Role.
func (b *listenerStatusBoard) setState(name, state string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.entries[name]
	if !ok {
		return
	}
	entry.State = state
	b.entries[name] = entry
}

// snapshot returns every tracked listener's current state, sorted by name
// for deterministic /health output. Implements health.Monitor.ListenersFunc.
func (b *listenerStatusBoard) snapshot() []health.ListenerStatus {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]health.ListenerStatus, 0, len(b.entries))
	for _, entry := range b.entries {
		out = append(out, entry)
	}
	slices.SortFunc(out, func(a, c health.ListenerStatus) int {
		return cmp.Compare(a.Name, c.Name)
	})
	return out
}

// listenerMember is one bound-and-served main listener: the result of
// EffectiveListeners() (#149) turned into a live net.Listener plus the
// http.Server dedicated to it. Every main listener shares the same handler
// (reload.SwappableHandler) — only the identity stamped into ConnContext and
// the bind target differ between members.
type listenerMember struct {
	identity   inbound.Identity
	listener   net.Listener
	server     *http.Server
	hijacked   *hijackedConnTracker
	socketPath string
	// socketIdentity is the (dev, ino) pair captured immediately after bind,
	// for explicit listeners[*] entries only (see bindMainListeners). It
	// guards shutdown-time removal: a socket path is only unlinked if it
	// still resolves to the exact inode this process created.
	socketIdentity socketIdentity
}

// hijackedConnTracker owns connections removed from net/http's lifecycle by
// a successful Hijack (Docker attach/exec streaming). http.Server.Shutdown
// intentionally does not close them, so listener-group shutdown must do so
// explicitly to keep the single 30-second drain deadline meaningful.
type hijackedConnTracker struct {
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

func trackHijackedConnections(server *http.Server) *hijackedConnTracker {
	tracker := &hijackedConnTracker{conns: make(map[net.Conn]struct{})}
	previous := server.ConnState
	server.ConnState = func(conn net.Conn, state http.ConnState) {
		if previous != nil {
			previous(conn, state)
		}
		tracker.transition(conn, state)
	}
	return tracker
}

func (t *hijackedConnTracker) transition(conn net.Conn, state http.ConnState) {
	if t == nil || conn == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	switch state {
	case http.StateHijacked:
		if t.closed {
			_ = conn.Close()
			return
		}
		t.conns[conn] = struct{}{}
	case http.StateClosed:
		delete(t.conns, conn)
	}
}

func (t *hijackedConnTracker) closeAll() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.closed = true
	connections := make([]net.Conn, 0, len(t.conns))
	for conn := range t.conns {
		connections = append(connections, conn)
	}
	clear(t.conns)
	t.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

// socketIdentity is a unix filesystem identity (device + inode). The zero
// value is "unknown/not captured" (valid == false), which callers must treat
// conservatively — see removeSocketIfOwned.
type socketIdentity struct {
	dev, ino uint64
	valid    bool
}

func statSocketIdentity(lstat func(string) (os.FileInfo, error), path string) socketIdentity {
	if path == "" || lstat == nil {
		return socketIdentity{}
	}
	info, err := lstat(path)
	if err != nil {
		return socketIdentity{}
	}
	return socketIdentityFromFileInfo(info)
}

func socketIdentityFromFileInfo(info os.FileInfo) socketIdentity {
	if info == nil {
		return socketIdentity{}
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return socketIdentity{}
	}

	return socketIdentity{dev: uint64(st.Dev), ino: uint64(st.Ino), valid: true}
}

// removeSocketIfOwned unlinks path only when it still identifies the same
// inode captured at bind time (want). An unknown identity (want.valid ==
// false — e.g. explicit listeners bound before this hardening, or a legacy
// member which does not record one) falls back to unconditional removal,
// matching pre-#149 behavior for those paths.
func removeSocketIfOwned(deps *serveDeps, path string, want socketIdentity) error {
	if path == "" {
		return nil
	}
	if !want.valid {
		return deps.removePath(path)
	}
	got := statSocketIdentity(deps.lstatPath, path)
	if !got.valid || got != want {

		return nil
	}
	return deps.removePath(path)
}

// networkFor reports the inbound.Network a ListenConfig binds to.
func networkFor(listen config.ListenConfig) inbound.Network {
	if listen.Socket != "" {
		return inbound.NetworkUnix
	}
	return inbound.NetworkTCP
}

// listenerAddrFor renders a human-readable "unix:<path>" / "tcp://<addr>"
// string for one effective listener entry, for logs and the startup banner.
func listenerAddrFor(listen config.ListenConfig) string {
	if listen.Socket != "" {
		return "unix:" + listen.Socket
	}
	return "tcp://" + listen.Address
}

// bindMainListeners binds every effective main listener (#149) — the legacy
// singular listen: block synthesized into one entry, or every listeners[*]
// entry — before any of them starts serving. Two-phase: prepare (this
// function) computes and binds every member; the caller starts Serve only
// after every member here (and the admin listener, bound separately) is
// live. Any bind failure closes every member already bound, in reverse
// order, and returns a wrapped error — there is never an instant where a
// strict non-empty subset of the configured main listeners is live.
func bindMainListeners(cfg *config.Config, deps *serveDeps, handler http.Handler, board *listenerStatusBoard) ([]*listenerMember, error) {
	effective := cfg.EffectiveListeners()
	explicit := len(cfg.Listeners) > 0

	members := make([]*listenerMember, 0, len(effective))
	for _, entry := range effective {
		var ln net.Listener
		var err error
		if explicit {
			ln, err = deps.createNamedListener(cfg, entry)
		} else {

			ln, err = deps.createServeListener(cfg)
		}
		if err != nil {
			closeMembersReverse(members)
			if explicit {
				return nil, fmt.Errorf("listener %q: %w", entry.Name, err)
			}

			return nil, fmt.Errorf("listener: %w", err)
		}

		identity := inbound.Identity{
			Name:    entry.Name,
			Role:    inbound.RoleMain,
			Network: networkFor(entry.ListenConfig),
		}
		server := newHTTPServerForIdentity(handler, identity)
		member := &listenerMember{
			identity:   identity,
			listener:   ln,
			server:     server,
			hijacked:   trackHijackedConnections(server),
			socketPath: entry.Socket,
		}
		if explicit && entry.Socket != "" {
			member.socketIdentity = statSocketIdentity(deps.lstatPath, entry.Socket)
		}
		board.register(identity, health.ListenerStateBound)
		members = append(members, member)
	}
	return members, nil
}

// closeMembersReverse closes every bound member's listener in reverse bind
// order — the standard two-phase-bind rollback shape. Closing a
// *net.UnixListener also unlinks its socket file (Go's default
// SetUnlinkOnClose behavior), so no separate removePath call is needed here.
func closeMembersReverse(members []*listenerMember) {
	for i := len(members) - 1; i >= 0; i-- {
		_ = members[i].listener.Close()
	}
}

// publishMainListeners starts the Serve goroutine for every bound member,
// relaying each one's terminal error into fanIn tagged with the member's
// name. fanIn must be buffered to at least len(members) so a member's
// forwarder never blocks on a fanIn send that the caller isn't ready to
// receive yet (e.g. during shutdown, once the caller has already stopped
// selecting on it).
func publishMainListeners(deps *serveDeps, members []*listenerMember, fanIn chan<- listenerResult, board *listenerStatusBoard) {
	for _, member := range members {
		publishListenerMember(deps, member, fanIn, board)
	}
}

func publishListenerMember(deps *serveDeps, member *listenerMember, fanIn chan<- listenerResult, board *listenerStatusBoard) {
	memberErrCh := make(chan error, 1)
	go deps.startServing(member.server, member.listener, memberErrCh)
	board.setState(member.identity.Name, health.ListenerStateServing)
	go func() {
		err := <-memberErrCh
		fanIn <- listenerResult{name: member.identity.Name, role: member.identity.Role, err: err}
	}()
}

// setListenersUp publishes the sockguard_listener_up{listener,role,network}
// gauge (#149) for every member at once. Called with up=true immediately
// after publishMainListeners has started every member's Serve() goroutine,
// and with up=false at the start of shutdown — see Registry.SetListenerUp
// for why the series is created once and never removed.
func setListenersUp(registry *metrics.Registry, members []*listenerMember, up bool) {
	for _, member := range members {
		registry.SetListenerUp(member.identity.Name, string(member.identity.Role), string(member.identity.Network), up)
	}
}

// listenerResult is one member's terminal Serve() outcome, fanned into a
// shared channel so the caller's select statement has a single case to
// watch regardless of how many listeners are configured.
type listenerResult struct {
	name string
	role inbound.Role
	err  error
}

// shutdownMainListeners concurrently shuts down every member's http.Server
// within ctx's deadline, then removes any unix socket files this process
// owns (see removeSocketIfOwned). Log message text ("shutdown error" /
// "remove socket error") is kept identical to the pre-#149 single-listener
// wording — only the added "listener" attr is new — so existing log-based
// test assertions keep matching regardless of listener count.
func shutdownMainListeners(ctx context.Context, deps *serveDeps, members []*listenerMember, board *listenerStatusBoard, logger *slog.Logger) {
	for _, member := range members {
		board.setState(member.identity.Name, health.ListenerStateDraining)
	}

	var wg sync.WaitGroup
	for _, member := range members {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := deps.shutdownServer(member.server, ctx); err != nil {
				logger.Error("shutdown error", "listener", member.identity.Name, "error", err)
				if ctx.Err() != nil {
					_ = member.server.Close()
					_ = member.listener.Close()
				}
			}
			member.hijacked.closeAll()
		}()
	}
	wg.Wait()

	for _, member := range members {
		board.setState(member.identity.Name, health.ListenerStateStopped)
	}

	for _, member := range members {
		if member.socketPath == "" {
			continue
		}
		if err := removeSocketIfOwned(deps, member.socketPath, member.socketIdentity); err != nil && !os.IsNotExist(err) {
			logger.Error("remove socket error", "listener", member.identity.Name, "socket", member.socketPath, "error", err)
		}
	}
}

// bannerListenerLines renders one banner.Info.Listeners entry per bound main
// listener in bind order, matching the "name unix:<path>" / "name
// tcp://<addr>" shape documented on banner.Info.Listeners.
func bannerListenerLines(members []*listenerMember, effective []config.ListenerConfig) []string {
	byName := make(map[string]config.ListenerConfig, len(effective))
	for _, e := range effective {
		byName[e.Name] = e
	}
	lines := make([]string, 0, len(members))
	for _, m := range members {
		entry := byName[m.identity.Name]
		lines = append(lines, fmt.Sprintf("%s %s", m.identity.Name, listenerAddrFor(entry.ListenConfig)))
	}
	return lines
}

// newHTTPServerForIdentity builds the http.Server for one listener member,
// composing inbound.ConnContext (stamped first, so it can never be spoofed
// by anything clientacl's own ConnContext reads later) with clientacl's
// existing per-connection identity capture. newHTTPServer keeps calling this
// with a synthesized main/default identity so every existing call site (and
// its tests, which only assert timeout/limit fields and ConnContext
// non-nil-ness) keeps compiling and passing unmodified.
func newHTTPServerForIdentity(handler http.Handler, identity inbound.Identity) *http.Server {
	srv := newHTTPServer(handler)
	srv.ConnContext = inbound.ConnContext(identity, clientacl.ConnContext)
	return srv
}

// warnAssignedProfilesWithoutLimits flags profiles that operators bound to a
// caller identity (mTLS, source IP, unix peer, default) but did not give any
// rate or concurrency configuration. Once any profile has limits configured,
// an unlimited assigned profile is almost always a config oversight, not an
// intentional carve-out — surface it at startup so operators notice before
// the proxy ships traffic.
func warnAssignedProfilesWithoutLimits(cfg *config.Config, limitedProfiles map[string]ratelimit.ProfileOptions, logger *slog.Logger) {
	assigned := make(map[string]struct{})
	if cfg.Clients.DefaultProfile != "" {
		assigned[cfg.Clients.DefaultProfile] = struct{}{}
	}
	for _, a := range cfg.Clients.SourceIPProfiles {
		if a.Profile != "" {
			assigned[a.Profile] = struct{}{}
		}
	}
	for _, a := range cfg.Clients.ClientCertificateProfiles {
		if a.Profile != "" {
			assigned[a.Profile] = struct{}{}
		}
	}
	for _, a := range cfg.Clients.UnixPeerProfiles {
		if a.Profile != "" {
			assigned[a.Profile] = struct{}{}
		}
	}
	for name := range assigned {
		if _, ok := limitedProfiles[name]; ok {
			continue
		}
		logger.Warn(
			"client profile is assigned to callers but has no rate or concurrency limits configured",
			slog.String("profile", name),
			slog.String("recommendation",
				"add clients.profiles[...].limits.rate, .concurrency, or .priority — or remove the assignment if unlimited access is intended"),
		)
	}
}

// configLimitsToRateLimitOptions converts a per-profile LimitsConfig to the
// ratelimit package's ProfileOptions. Returns zero-valued options (both nil)
// when no limits are configured.
func configLimitsToRateLimitOptions(profileName string, cfg config.LimitsConfig, logger *slog.Logger) ratelimit.ProfileOptions {
	var opts ratelimit.ProfileOptions
	if cfg.Priority != "" {
		var ok bool
		opts.Priority, ok = ratelimit.ParsePriority(cfg.Priority)
		if !ok {
			logger.Warn("unrecognized priority value in client profile; falling back to normal",
				slog.String("profile", profileName),
				slog.String("priority", cfg.Priority),
			)
		}
	}
	if cfg.Rate != nil {
		burst := cfg.Rate.Burst
		if burst == 0 {
			burst = cfg.Rate.TokensPerSecond
		}
		var costs []ratelimit.EndpointCost
		if len(cfg.Rate.EndpointCosts) > 0 {
			costs = make([]ratelimit.EndpointCost, 0, len(cfg.Rate.EndpointCosts))
			for _, ec := range cfg.Rate.EndpointCosts {
				costs = append(costs, ratelimit.EndpointCost{
					PathGlob: ec.Path,
					Methods:  ec.Methods,
					Cost:     ec.Cost,
				})
			}
		}
		opts.Rate = &ratelimit.RateOptions{
			TokensPerSecond: cfg.Rate.TokensPerSecond,
			Burst:           burst,
			EndpointCosts:   costs,
		}
	}
	if cfg.Concurrency != nil {
		opts.Concurrency = &ratelimit.ConcurrencyOptions{
			MaxInflight: cfg.Concurrency.MaxInflight,
		}
	}
	return opts
}

// discardLogger is a package-level slog.Logger that writes to io.Discard.
// Used in hot-reload paths (e.g. ApplyCompat) where compat-expansion noise
// must be suppressed without allocating a new handler per reload call.
var discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// reloadCoordinator owns the hot-reload state for a running sockguard
// process: the current chain teardown, the active config snapshot, and
// the swappable handler the http.Server routes through. It serializes
// reloads with a mutex — at most one OnReload is in flight at any time —
// and updates the metrics registry with the outcome.
type reloadCoordinator struct {
	mu sync.Mutex

	// chainTeardown halts goroutines belonging to the CURRENT chain
	// (rate-limit sampler, per-profile Limiter eviction). The reload
	// path replaces it with the new chain's teardown and invokes the
	// old one. The shutdown path invokes whatever is current.
	chainTeardown func()
	activeCfg     *config.Config

	// rootCtx is the cobra command context; bundle re-verification on
	// reload must derive its timeout from this so SIGTERM cancels an
	// in-flight verifier rather than blocking on the per-bundle deadline.
	// Nil is tolerated for test fixtures that don't exercise verifyBundle.
	rootCtx context.Context

	// Bindings that live for the whole process lifetime. None of these
	// change across reloads — the immutable-field gate rejects any
	// reload whose YAML would mutate these inputs.
	swappable   *reload.SwappableHandler
	cfgFile     string
	logger      *slog.Logger
	auditLogger *logging.AuditLogger
	deps        *serveDeps
	runtime     *serveRuntime
	// versioner is shared with the admin policy-version handler. Updating it
	// after a successful swap is what makes the new generation visible to
	// GET /admin/policy/version and to sockguard_policy_version. Nil-safe so
	// tests can construct a coordinator without one.
	versioner *admin.PolicyVersioner
	// bundleVerifier is the reload-immutable signed-bundle verifier. Nil
	// means policy_bundle.enabled=false; the reload path skips verification
	// in that case. When non-nil and policy_bundle.enabled=true, every
	// reload must clear the verifier before any other work — otherwise the
	// trust gate would be bypassable by anyone with write access to the
	// YAML file.
	bundleVerifier policybundle.Verifier
}

// reloadCoordinatorParams bundles the inputs newReloadCoordinator needs.
// The set is large because the coordinator pulls together every piece of
// reload-time state — the running config, the swappable handler, every
// per-process singleton — and grouping them here keeps call sites compact.
type reloadCoordinatorParams struct {
	RootCtx         context.Context
	Cfg             *config.Config
	CfgFile         string
	Swappable       *reload.SwappableHandler
	InitialTeardown func()
	Logger          *slog.Logger
	AuditLogger     *logging.AuditLogger
	Deps            *serveDeps
	Runtime         *serveRuntime
	Versioner       *admin.PolicyVersioner
	BundleVerifier  policybundle.Verifier
}

// newReloadCoordinator returns a coordinator wired up with the initial
// chain teardown and current config snapshot. The caller must arrange for
// stop to be invoked once at process shutdown.
func newReloadCoordinator(p reloadCoordinatorParams) *reloadCoordinator {
	if p.InitialTeardown == nil {
		p.InitialTeardown = func() {}
	}
	return &reloadCoordinator{
		chainTeardown:  p.InitialTeardown,
		activeCfg:      p.Cfg,
		rootCtx:        p.RootCtx,
		swappable:      p.Swappable,
		cfgFile:        p.CfgFile,
		logger:         p.Logger,
		auditLogger:    p.AuditLogger,
		deps:           p.Deps,
		runtime:        p.Runtime,
		versioner:      p.Versioner,
		bundleVerifier: p.BundleVerifier,
	}
}

// stop halts the current chain's goroutines. Idempotent so it is safe
// to call from a defer at shutdown.
func (c *reloadCoordinator) stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.chainTeardown == nil {
		return
	}
	c.chainTeardown()
	c.chainTeardown = nil
}

// reload runs one full reload pass: load → ApplyCompat → validate →
// immutable-diff → swap. Outcomes are surfaced via the metrics registry
// and the slog logger; the running config is never replaced on failure.
//
// Called from the reload.Reloader goroutine. The mutex serializes against
// shutdown and against future reload triggers that race during a long
// validation.
func (c *reloadCoordinator) reload() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.chainTeardown == nil {

		return
	}

	bundleResult, verifiedBytes, err := c.verifyBundle()
	if err != nil {
		c.logger.Warn("config reload rejected: signature verification failed",
			"result", "reject_signature",
			"path", c.cfgFile,
			"signature_path", c.activeCfg.PolicyBundle.SignaturePath,
			"error", err.Error(),
		)
		c.runtime.metrics.ObserveConfigReload("reject_signature")
		return
	}

	// When a bundle is enabled, parse the EXACT bytes that were just verified
	// (no env overlay) so the applied config matches the signature and cannot be
	// diverted by a concurrent file swap (#8) or SOCKGUARD_* env vars (#16).
	// Without a bundle, fall back to the normal file+env load.
	var newCfg *config.Config
	if verifiedBytes != nil {
		newCfg, err = c.deps.loadConfigBytes(verifiedBytes)
	} else {
		newCfg, err = c.deps.loadConfig(c.cfgFile)
	}
	if err != nil {
		c.logger.Warn("config reload rejected: load failed",
			"result", "reject_load",
			"path", c.cfgFile,
			"error", err.Error(),
		)
		c.runtime.metrics.ObserveConfigReload("reject_load")
		return
	}

	if changed := reload.ImmutableDiff(c.activeCfg, newCfg); len(changed) > 0 {

		c.logger.Warn("config reload rejected: immutable fields changed; restart required to apply",
			"result", "reject_immutable",
			"path", c.cfgFile,
			"changed_fields", strings.Join(changed, ","),
		)
		c.runtime.metrics.ObserveConfigReload("reject_immutable")
		return
	}

	compatActive := config.ApplyCompat(newCfg, discardLogger)

	newRules, err := c.deps.validateRules(newCfg)
	if err != nil {
		c.logger.Warn("config reload rejected: validation failed",
			"result", "reject_validation",
			"path", c.cfgFile,
			"error", err.Error(),
		)
		c.runtime.metrics.ObserveConfigReload("reject_validation")
		return
	}

	newHandler, newTeardown := buildServeHandlerChainWithRuntime(serveHandlerBuild{
		Cfg:         newCfg,
		Logger:      c.logger,
		AuditLogger: c.auditLogger,
		Rules:       newRules,
		Deps:        c.deps,
		Runtime:     c.runtime,
		Versioner:   c.versioner,
	})

	// Capture the old concurrency-capped profile set before activeCfg
	// advances. Only profiles with a concurrency cap can have contributed
	// in-flight gauge series (SetInflight is called only after a successful
	// Acquire, which only happens when cp.tracker != nil, which only exists
	// when opts.Concurrency != nil && MaxInflight > 0).
	var oldInflightProfiles map[string]struct{}
	if c.runtime.metrics != nil {
		oldInflightProfiles = profileNamesWithConcurrency(c.activeCfg)
	}

	oldTeardown := c.chainTeardown
	c.chainTeardown = newTeardown
	c.activeCfg = newCfg

	c.swappable.Swap(newHandler)

	if c.runtime.metrics != nil {
		newInflightProfiles := profileNamesWithConcurrency(newCfg)
		for _, name := range removedProfiles(oldInflightProfiles, newInflightProfiles) {
			c.runtime.metrics.DeleteInflightProfile(name)
		}
	}

	oldTeardown()

	// Publish the new generation AFTER the swap so an admin GET to
	// /admin/policy/version that races with a reload either sees the
	// pre-reload version (handler still pointing at the old chain) or
	// the post-reload version (handler is the new chain) — never a half
	// state where the version ticked but the active handler is stale.
	var newVersion int64
	if c.versioner != nil {
		snap := admin.PolicySnapshot{
			LoadedAt:     c.deps.now(),
			Rules:        len(newRules),
			Profiles:     len(newCfg.Clients.Profiles),
			CompatActive: compatActive,
			Source:       "reload",
			ConfigSHA256: policyConfigHash(newCfg),
		}
		if bundleResult != nil {
			snap.BundleSource = filepath.Base(newCfg.PolicyBundle.SignaturePath)
			snap.BundleSigner = bundleResult.Signer
			snap.BundleDigest = bundleResult.DigestHex
		}
		newVersion = c.versioner.Update(snap)
		c.runtime.metrics.SetPolicyVersion(newVersion)
	}

	c.logger.Info("config reload applied",
		"result", "ok",
		"path", c.cfgFile,
		"rules", len(newRules),
		"profiles", len(newCfg.Clients.Profiles),
		"policy_version", newVersion,
	)
	c.runtime.metrics.ObserveConfigReload("ok")
}

// verifyBundle returns (nil, nil, nil) when bundle verification is disabled,
// (*VerifyResult, verifiedBytes, nil) on a clean accept, or (nil, nil, err) on
// any failure (missing file, malformed bundle, signature mismatch). The bound
// verifier is the same instance produced at startup and reused across every
// reload because policy_bundle's trust material is reload-immutable.
//
// The verified bytes are returned so the caller parses the EXACT bytes that
// were signed rather than re-reading the file: that closes the verify-then-load
// TOCTOU (#8) and keeps environment variables from overriding signed policy on
// reload (#16).
func (c *reloadCoordinator) verifyBundle() (*policybundle.VerifyResult, []byte, error) {
	if c.bundleVerifier == nil || !c.activeCfg.PolicyBundle.Enabled {
		return nil, nil, nil
	}
	yamlBytes, err := c.deps.readConfigBytes(c.cfgFile)
	if err != nil {
		return nil, nil, err
	}

	candidate, err := c.deps.loadConfigBytes(yamlBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse candidate config for signature_path: %w", err)
	}
	signaturePath := candidate.PolicyBundle.SignaturePath
	if signaturePath == "" {
		return nil, nil, errors.New("policy_bundle.signature_path is empty")
	}
	entity, err := c.deps.loadBundleEntity(signaturePath)
	if err != nil {
		return nil, nil, err
	}
	parent := c.rootCtx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, bundleVerifyDeadline(c.activeCfg.PolicyBundle))
	defer cancel()
	res, err := c.bundleVerifier.Verify(ctx, yamlBytes, entity)
	if err != nil {
		return nil, nil, err
	}
	return &res, yamlBytes, nil
}

// profileNamesWithConcurrency returns the set of profile names in cfg that
// have a concurrency cap configured (Limits.Concurrency != nil with
// MaxInflight > 0). Only these profiles contribute in-flight gauge series
// because SetInflight is only called from checkProfileConcurrency after a
// successful Acquire, which only occurs when opts.Concurrency != nil.
func profileNamesWithConcurrency(cfg *config.Config) map[string]struct{} {
	if cfg == nil {
		return nil
	}
	out := make(map[string]struct{}, len(cfg.Clients.Profiles))
	for _, p := range cfg.Clients.Profiles {
		if p.Limits.Concurrency != nil && p.Limits.Concurrency.MaxInflight > 0 {
			out[p.Name] = struct{}{}
		}
	}
	return out
}

// removedProfiles returns the profile names present in oldSet but absent from
// newSet. These are profiles whose in-flight gauge series are orphaned and
// should be cleared.
func removedProfiles(oldSet, newSet map[string]struct{}) []string {
	if len(oldSet) == 0 {
		return nil
	}
	var removed []string
	for name := range oldSet {
		if _, stillPresent := newSet[name]; !stillPresent {
			removed = append(removed, name)
		}
	}
	return removed
}

// startReloader wires the coordinator into a reload.Reloader and runs it
// in a goroutine. Returns a stop function that cancels the watcher loop
// and returns once it has exited. Callers must invoke stop before
// invoking coordinator.stop() so a reload-in-progress can't race the
// teardown.
func startReloader(ctx context.Context, cfgFile string, debounce, pollInterval time.Duration, coordinator *reloadCoordinator, logger *slog.Logger) (func(), error) {
	if cfgFile == "" {
		return nil, errors.New("reload: cfgFile is required")
	}
	rl, err := reload.New(reload.Options{
		Path:         cfgFile,
		Debounce:     debounce,
		PollInterval: pollInterval,
		OnReload:     coordinator.reload,
		Logger:       logger,
	})
	if err != nil {
		return nil, err
	}

	loopCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if runErr := rl.Run(loopCtx); runErr != nil && !errors.Is(runErr, context.Canceled) {
			logger.Warn("config reloader stopped with error", "error", runErr)
		}
	}()

	stop := func() {
		cancel()
		<-done
	}
	return stop, nil
}

// upstreamReachableTimeout bounds the startup reachability probe across all
// endpoints so a hung TLS handshake to one remote daemon cannot stall boot.
const upstreamReachableTimeout = 10 * time.Second

// resolveUpstreamSpecs determines the ordered endpoint specs for the upstream
// and whether this is the legacy single-local-socket case (which keeps the
// original fail-fast reachability check and log/banner wording). Precedence:
// explicit upstream.endpoints > DOCKER_HOST (tcp) env > upstream.socket.
func resolveUpstreamSpecs(cfg *config.Config, getenv func(string) string, logger *slog.Logger) (specs []upstream.EndpointSpec, legacySocket bool) {
	if len(cfg.Upstream.Endpoints) > 0 {
		specs = make([]upstream.EndpointSpec, len(cfg.Upstream.Endpoints))
		for i, ep := range cfg.Upstream.Endpoints {
			specs[i] = upstream.EndpointSpec{
				Address:               ep.Address,
				CAFile:                ep.TLS.CAFile,
				CertFile:              ep.TLS.CertFile,
				KeyFile:               ep.TLS.KeyFile,
				ServerName:            ep.TLS.ServerName,
				InsecureAllowPlainTCP: ep.InsecureAllowPlainTCP,
				InsecureSkipTLSVerify: ep.InsecureSkipTLSVerify,
			}
		}
		warnInsecureUpstreamSpecs(logger, specs, "upstream.endpoints config")
		return specs, false
	}
	if spec, ok := upstream.SpecsFromDockerEnv(getenv); ok {
		logger.Info("using remote upstream from DOCKER_HOST environment", "address", spec.Address)
		warnInsecureUpstreamSpecs(logger, []upstream.EndpointSpec{spec}, "DOCKER_HOST environment")
		return []upstream.EndpointSpec{spec}, false
	}
	return []upstream.EndpointSpec{{Address: cfg.Upstream.Socket}}, true
}

// warnInsecureUpstreamSpecs logs a startup warning for each endpoint that
// transports Docker API traffic without proper TLS — plaintext TCP, or TLS with
// certificate verification disabled. Both leave exec streams, secrets, and
// container data exposed (unencrypted, or encrypted but MITM-susceptible), so an
// operator who reaches them via a DOCKER_HOST drop-in (not just explicit config)
// gets a visible breadcrumb rather than a silent downgrade.
func warnInsecureUpstreamSpecs(logger *slog.Logger, specs []upstream.EndpointSpec, source string) {
	if logger == nil {
		return
	}
	for _, spec := range specs {
		switch {
		case spec.InsecureAllowPlainTCP:
			logger.Warn("upstream Docker endpoint uses plaintext TCP with no TLS; "+
				"Docker API traffic (exec streams, secrets, container data) is unencrypted and unauthenticated on the wire",
				"address", spec.Address, "source", source)
		case spec.InsecureSkipTLSVerify:
			logger.Warn("upstream Docker endpoint skips TLS certificate verification; "+
				"the connection is encrypted but the daemon's identity is not checked (MITM-susceptible)",
				"address", spec.Address, "source", source)
		}
	}
}

// buildUpstreamResolver constructs the shared upstream resolver from config,
// loading any per-endpoint TLS material. It returns the resolver, whether the
// legacy single-socket path was taken, and an error for any unbuildable
// endpoint (bad address, missing/invalid TLS files).
func buildUpstreamResolver(cfg *config.Config, logger *slog.Logger, getenv func(string) string) (*upstream.Resolver, bool, error) {
	specs, legacy := resolveUpstreamSpecs(cfg, getenv, logger)
	endpoints := make([]upstream.Endpoint, 0, len(specs))
	for _, spec := range specs {
		ep, err := upstream.BuildEndpoint(spec)
		if err != nil {
			return nil, legacy, err
		}
		endpoints = append(endpoints, ep)
	}
	res, err := upstream.New(endpoints, upstream.Options{
		Interval: durationOrZero(cfg.Upstream.Failover.HealthInterval),
		Timeout:  durationOrZero(cfg.Upstream.Failover.HealthTimeout),
		Logger:   logger,
	})
	return res, legacy, err
}

// durationOrZero parses a Go duration, returning 0 for empty or invalid input
// so the resolver falls back to its built-in defaults. Validation has already
// rejected malformed values by the time this runs in production.
func durationOrZero(s string) time.Duration {
	if s == "" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d
}

// upstreamResolverFor returns res when non-nil, otherwise a single-socket
// resolver built from cfg. It lets request-chain helpers accept an optional
// shared resolver (production threads the real one; tests can pass nil to get
// the legacy single-socket behavior without constructing a resolver).
func upstreamResolverFor(res *upstream.Resolver, cfg *config.Config) *upstream.Resolver {
	if res != nil {
		return res
	}
	return upstream.NewSingleSocket(cfg.Upstream.Socket)
}

// runtimeResolver returns the runtime's shared resolver, falling back to a
// single-socket resolver built from cfg when the runtime (or its resolver) is
// absent — the latter only happens in tests that construct a bare serveRuntime.
func runtimeResolver(runtime *serveRuntime, cfg *config.Config) *upstream.Resolver {
	if runtime == nil {
		return upstreamResolverFor(nil, cfg)
	}
	return upstreamResolverFor(runtime.resolver, cfg)
}

// verifyUpstreamReachableForRuntime runs the startup reachability probe against
// the resolved upstream. The legacy single-local-socket path keeps the original
// fail-fast unix-dial check (which classifies not-found / permission errors for
// a precise operator message); the endpoints / DOCKER_HOST path probes every
// configured endpoint, seeds their health state, and fails only when none are
// reachable, so a multi-endpoint failover set can boot with one daemon down.
func verifyUpstreamReachableForRuntime(ctx context.Context, deps *serveDeps, runtime *serveRuntime, cfg *config.Config, logger *slog.Logger) error {
	if runtime == nil || runtime.legacyUpstreamSocket || runtime.resolver == nil {
		return deps.verifyUpstreamReachable(cfg.Upstream.Socket, logger)
	}
	probeCtx, cancel := context.WithTimeout(ctx, upstreamReachableTimeout)
	defer cancel()
	return runtime.resolver.CheckReachable(probeCtx)
}

// upstreamDisplayFromConfig renders the upstream for human-facing output (the
// validate header) directly from config, without constructing a resolver.
// Configured endpoints take precedence over the legacy socket and show a
// failover count when more than one is listed; DOCKER_* env resolution is a
// serve-time fallback and is intentionally not reflected here.
func upstreamDisplayFromConfig(cfg *config.Config) string {
	eps := cfg.Upstream.Endpoints
	switch len(eps) {
	case 0:
		return cfg.Upstream.Socket
	case 1:
		return eps[0].Address
	default:
		return fmt.Sprintf("%s (+%d failover)", eps[0].Address, len(eps)-1)
	}
}

// upstreamLabel is the short identifier used in health logs/metrics for the
// upstream: the sole endpoint's name, or the primary with a failover count.
func upstreamLabel(res *upstream.Resolver) string {
	eps := res.Endpoints()
	switch len(eps) {
	case 0:
		return "upstream"
	case 1:
		return eps[0].Name
	default:
		return eps[0].Name + " (+failover)"
	}
}

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration file",
	Long:  "Parse and validate the sockguard configuration file, then print the effective rule set.",
	RunE:  runValidate,
}

func init() {
	rootCmd.AddCommand(validateCmd)
}

func runValidate(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	errOut := cmd.ErrOrStderr()
	stdoutP := ui.New(out)
	stderrP := ui.New(errOut)

	if err := requireExplicitConfigFile(cmd, cfgFile); err != nil {
		wrapped := fmt.Errorf("config preflight: %w", err)
		printValidationFailure(errOut, stderrP, wrapped)
		return wrapped
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		wrapped := fmt.Errorf("config load: %w", err)
		printValidationFailure(errOut, stderrP, wrapped)
		return wrapped
	}

	compatActive := config.ApplyCompat(cfg, discardLogger)

	compiled, err := newServeDeps().validateRules(cfg)
	if err != nil {
		printValidationFailure(errOut, stderrP, err)
		return err
	}

	printHeader(out, stdoutP, cfg, compatActive)
	printRules(out, stdoutP, cfg, len(compiled))
	printClientProfiles(out, stdoutP, cfg)
	fmt.Fprintf(out, "  %s %s\n", stdoutP.Green(ui.Check), stdoutP.Green("validation passed"))
	return nil
}

func printHeader(out io.Writer, p *ui.Printer, cfg *config.Config, compatActive bool) {
	fmt.Fprintf(out, "  %s  %s\n", p.Dim("Config  "), cfgFile)
	fmt.Fprintf(out, "  %s  %s\n", p.Dim("Listen  "), listenerAddr(cfg))
	fmt.Fprintf(out, "  %s  %s\n", p.Dim("Upstream"), upstreamDisplayFromConfig(cfg))
	if compatActive {
		fmt.Fprintf(out, "  %s  %s\n", p.Dim("Mode    "), "tecnativa compatibility")
	}
	fmt.Fprintln(out)
}

func printRules(out io.Writer, p *ui.Printer, cfg *config.Config, count int) {
	fmt.Fprintf(out, "  %s\n", p.Bold(fmt.Sprintf("Rules (%d)", count)))
	for _, r := range cfg.Rules {
		glyph := p.Green(ui.Check)
		action := p.Green("allow")
		if r.Action == "deny" {
			glyph = p.Red(ui.Cross)
			action = p.Red("deny ")
		}
		method := r.Match.Method
		if method == "" {
			method = "*"
		}
		fmt.Fprintf(out, "    %s %s  %-6s %s\n", glyph, action, method, r.Match.Path)
	}
	fmt.Fprintln(out)
}

func printClientProfiles(out io.Writer, p *ui.Printer, cfg *config.Config) {
	if len(cfg.Clients.Profiles) == 0 {
		return
	}

	fmt.Fprintf(out, "  %s\n", p.Bold(fmt.Sprintf("Client Profiles (%d)", len(cfg.Clients.Profiles))))
	for _, profile := range cfg.Clients.Profiles {
		name := profile.Name
		if cfg.Clients.DefaultProfile == profile.Name {
			name += " (default)"
		}
		fmt.Fprintf(out, "    %s\n", p.Bold(name))
		for _, r := range profile.Rules {
			glyph := p.Green(ui.Check)
			action := p.Green("allow")
			if r.Action == "deny" {
				glyph = p.Red(ui.Cross)
				action = p.Red("deny ")
			}
			method := r.Match.Method
			if method == "" {
				method = "*"
			}
			fmt.Fprintf(out, "      %s %s  %-6s %s\n", glyph, action, method, r.Match.Path)
		}
	}
	fmt.Fprintln(out)
}

func printValidationFailure(out io.Writer, p *ui.Printer, err error) {
	fmt.Fprintf(out, "  %s %s\n", p.Red(ui.Cross), p.Red("validation failed"))
	fmt.Fprintf(out, "    %s\n", err)
}

var versionOutput string

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	RunE:  runVersion,
}

func init() {
	rootCmd.AddCommand(versionCmd)
	versionCmd.Flags().StringVarP(&versionOutput, "output", "o", "text", "output format: text or json")
}

func runVersion(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	switch versionOutput {
	case "text":
		p := ui.New(out)
		fmt.Fprintf(out, "  %s %s\n", p.Bold("sockguard"), p.Dim(version.Version))
		fmt.Fprintf(out, "  %s  %s\n", p.Dim("commit"), shortCommit(version.Commit))
		fmt.Fprintf(out, "  %s  %s\n", p.Dim("built "), version.BuildDate)
		fmt.Fprintf(out, "  %s  %s\n", p.Dim("go    "), runtime.Version())
		return nil
	case "json":
		fmt.Fprintf(out, "{\"version\":%q,\"commit\":%q,\"built\":%q,\"go\":%q}\n",
			version.Version, version.Commit, version.BuildDate, runtime.Version())
		return nil
	default:
		return fmt.Errorf("unknown output format %q (want text or json)", versionOutput)
	}
}

func shortCommit(c string) string {
	const n = 7
	if len(c) > n {
		return c[:n]
	}
	return c
}
