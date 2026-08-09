package filter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/codeswhat/sockguard/internal/upstream"
)

const maxExecBodyBytes = 64 << 10 // 64 KiB

var (
	errExecMissingCmd     = errors.New("missing Cmd")
	errExecEmptyCmdArray  = errors.New("empty Cmd array")
	errExecEmptyCmdString = errors.New("empty Cmd string")
)

// ExecInspectResult captures the effective exec command metadata Docker stores
// after POST /containers/{id}/exec and returns from GET /exec/{id}/json.
//
// Env is populated only on the exec-create path: Docker's GET /exec/{id}/json
// ProcessConfig does not expose the exec's environment, so the exec-start
// re-check (inspectExisting) always leaves it nil. That is safe rather than a
// gap — exec instances are immutable after creation (same reasoning already
// documented for Cmd/Privileged/User above inspectExisting), so there is
// nothing for a start-time Env re-check to catch that create-time didn't
// already see.
type ExecInspectResult struct {
	Command    []string
	Privileged bool
	User       string
	Env        []string
}

// ExecInspectFunc looks up an existing exec instance by id.
type ExecInspectFunc func(context.Context, string) (ExecInspectResult, bool, error)

// ExecOptions configures request-body policy checks for exec creation/start.
type ExecOptions struct {
	AllowPrivileged bool
	AllowRootUser   bool
	// AllowedCommands is an allowlist of exec argv templates. Each token is a
	// sockguard glob (see internal/glob): "*" matches a run of non-slash
	// characters, "**" matches any sequence. A command is allowed when its
	// token count equals an entry's and every token matches the glob at that
	// position. Empty (the default) denies every exec unless AllowBlindWrites
	// is also set.
	AllowedCommands [][]string
	// AllowedEnvVars, when non-empty, restricts the exec-create Env array to
	// these variable names. Matching is by name only — the substring before
	// the first "=" in each Env entry — exact string comparison,
	// case-sensitive; the value is never inspected. Default empty means no
	// restriction: unlike AllowedCommands, an empty AllowedEnvVars does NOT
	// deny all Env content — this is a deliberate zero-behavior-change
	// default, since enabling exec command allowlisting should not also
	// silently start denying every exec session's environment.
	AllowedEnvVars []string
	// DeniedEnvVars variable names are always blocked and are checked before
	// AllowedEnvVars, so a name present in both lists is denied — fail
	// closed on operator misconfiguration. Default empty means nothing is
	// blocked.
	DeniedEnvVars []string
	// AllowedEnvValues pins selected variables to exact NAME=VALUE entries.
	// When at least one entry is configured for a name, every occurrence of
	// that name must exactly match one of those entries. Values are never
	// included in denial reasons or logs. Default empty means no value checks.
	AllowedEnvValues []string
	// AllowBlindWrites wires the top-level insecure_allow_body_blind_writes
	// config flag: when true AND AllowedCommands is empty, exec create/start
	// is no longer hard-denied purely for lacking a command allowlist. This
	// ONLY lifts the "no commands are allowlisted" gate — AllowPrivileged,
	// AllowRootUser, and the AllowedEnvVars/DeniedEnvVars gates below still
	// apply exactly as configured, matching the documented scope of the
	// blind-write opt-in (it acknowledges "we cannot pin the argv", not "skip
	// every other exec check"). When AllowedCommands is non-empty this field
	// has no effect: an operator who pinned commands is inspecting the body,
	// so the blind-write concern the flag addresses does not apply.
	AllowBlindWrites bool
	InspectStart     ExecInspectFunc
	// InspectStartLibpod is InspectStart's counterpart for the libpod
	// exec-start path (POST /libpod/exec/{id}/start). It exists as a
	// separate field — rather than reusing InspectStart for both routes —
	// because the two constructors issue their upstream GET against
	// different URL families (GET /exec/{id}/json vs.
	// GET /libpod/exec/{id}/json); which one a given exec-start request
	// needs is decided by which path triggered it, not by anything
	// ExecInspectFunc's (context, id) signature carries. The exec-create
	// side needs no such split: it never calls upstream, it decodes the
	// POST body directly (see inspectCreate), and libpod exec-create bodies
	// decode with the identical Go handler Docker-compat exec-create bodies
	// do (#148 design doc decision C3) — see isLibpodExecCreatePath's
	// call site in inspect below.
	InspectStartLibpod ExecInspectFunc
}

type execPolicy struct {
	allowPrivileged    bool
	allowRootUser      bool
	allowedCommands    []execCommandMatcher
	allowedEnvVars     []string
	deniedEnvVars      []string
	allowedEnvValues   map[string][]string
	allowBlindWrites   bool
	inspectStart       ExecInspectFunc
	inspectStartLibpod ExecInspectFunc
}

// execCommandMatcher is a compiled allowlist entry: one anchored regex per
// argv token. A command matches only when its token count equals len(tokens)
// and every token matches positionally.
type execCommandMatcher struct {
	tokens []*regexp.Regexp
}

func (m execCommandMatcher) matches(command []string) bool {
	if len(command) != len(m.tokens) {
		return false
	}
	for i, tok := range m.tokens {
		if !tok.MatchString(command[i]) {
			return false
		}
	}
	return true
}

type execCreateRequest struct {
	Cmd        json.RawMessage `json:"Cmd"`
	Privileged bool            `json:"Privileged"`
	User       string          `json:"User"`
	// Env is strictly typed as []string, unlike Cmd's json.RawMessage dual
	// array/string decoding: Docker's exec Env has only ever been an array of
	// strings, so a request whose Env is present but not shaped that way
	// (an object, or an array of non-strings) fails the execCreateRequest
	// unmarshal entirely and falls into the existing fail-closed "request
	// body could not be inspected" branch in inspectCreate — the same
	// outcome as any other malformed exec-create body.
	Env []string `json:"Env"`
}

type execInspectResponse struct {
	ProcessConfig struct {
		Entrypoint string   `json:"entrypoint"`
		Arguments  []string `json:"arguments"`
		Privileged bool     `json:"privileged"`
		User       string   `json:"user"`
	} `json:"ProcessConfig"`
}

func newExecPolicy(opts ExecOptions) execPolicy {
	allowed := make([]execCommandMatcher, 0, len(opts.AllowedCommands))
	for _, command := range opts.AllowedCommands {
		if len(command) == 0 {
			continue
		}
		tokens := make([]*regexp.Regexp, len(command))
		for i, token := range command {
			// GlobToRegexString output is always valid regex — every byte is an
			// explicit glob token or regexp.QuoteMeta'd — so MustCompile cannot
			// panic on operator input. \A...\z anchors the whole token exactly;
			// $ would also match a trailing newline, letting "foo\n" satisfy a
			// "foo" entry.
			tokens[i] = regexp.MustCompile(`\A(?:` + GlobToRegexString(token) + `)\z`)
		}
		allowed = append(allowed, execCommandMatcher{tokens: tokens})
	}

	return execPolicy{
		allowPrivileged:    opts.AllowPrivileged,
		allowRootUser:      opts.AllowRootUser,
		allowedCommands:    allowed,
		allowedEnvVars:     normalizeExecEnvNames(opts.AllowedEnvVars),
		deniedEnvVars:      normalizeExecEnvNames(opts.DeniedEnvVars),
		allowedEnvValues:   normalizeExecEnvValues(opts.AllowedEnvValues),
		allowBlindWrites:   opts.AllowBlindWrites,
		inspectStart:       opts.InspectStart,
		inspectStartLibpod: opts.InspectStartLibpod,
	}
}

func normalizeExecEnvValues(values []string) map[string][]string {
	normalized := make(map[string][]string)
	for _, entry := range values {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || name == "" || slices.Contains(normalized[name], entry) {
			continue
		}
		normalized[name] = append(normalized[name], entry)
	}
	return normalized
}

// normalizeExecEnvNames trims whitespace and dedupes env-var name entries,
// preserving first-seen order. Matching is exact and case-sensitive per the
// v1 spec (no case-folding, no glob support) — literal-only, mirroring the
// convention used by allowed_capabilities/allowed_registries/allowed_runtimes
// elsewhere in the schema.
func normalizeExecEnvNames(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || slices.Contains(normalized, trimmed) {
			continue
		}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

func (p execPolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost {
		return "", nil
	}

	switch {
	// libpod's POST /libpod/containers/{name}/exec and POST
	// /libpod/exec/{id}/start route to the SAME Go handlers Docker-compat
	// exec create/start do (confirmed against Podman's own route table,
	// pkg/api/server/register_exec.go: both /containers/{name}/exec and
	// /libpod/containers/{name}/exec register compat.ExecCreateHandler; both
	// /exec/{id}/start and /libpod/exec/{id}/start register
	// compat.ExecStartHandler). Request bodies are therefore byte-identical
	// in shape between the two families — no libpod-specific decode struct
	// exists or is needed here, unlike every other libpod inspector in this
	// package (#148 design doc decision C3).
	case isExecCreatePath(normalizedPath) || isLibpodExecCreatePath(normalizedPath):
		return p.inspectCreate(logger, r)
	case isExecStartPath(normalizedPath) || isLibpodExecStartPath(normalizedPath):
		return p.inspectExisting(r.Context(), normalizedPath)
	default:
		return "", nil
	}
}

func (p execPolicy) inspectCreate(logger *slog.Logger, r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxExecBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("exec denied: request body exceeds %d byte limit", maxExecBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req execCreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "exec request body is not valid JSON; deferring to Docker validation", err)
		return "exec denied: request body could not be inspected", nil
	}

	command, err := decodeExecCommand(req.Cmd)
	if err != nil {
		logRequestError(logger, r, slog.LevelDebug, "exec request body has unparseable Cmd; denying", err)
		return "exec denied: request body could not be inspected", nil
	}

	return p.denyReason(ExecInspectResult{
		Command:    command,
		Privileged: req.Privileged,
		User:       req.User,
		Env:        req.Env,
	}), nil
}

func (p execPolicy) inspectExisting(ctx context.Context, normalizedPath string) (string, error) {
	execID, isLibpod, ok := execStartIdentifier(normalizedPath)
	if !ok {
		return "", nil
	}

	inspectStart := p.inspectStart
	if isLibpod {
		inspectStart = p.inspectStartLibpod
	}
	if inspectStart == nil {
		return "exec start denied: no exec inspection configured", nil
	}

	// Docker's exec instance is immutable after ContainerExecCreate — there is
	// no API to mutate Cmd, Privileged, or User on an existing exec — so the
	// values returned by /exec/{id}/json here are the same values Docker uses
	// when the start command runs. There is no TOCTOU on the exec config
	// itself. The container the exec is attached to can still change between
	// inspect and start (image swapped, process killed); operators that need
	// to constrain that surface should prefer container-level allowlists
	// (allowed_commands per profile) over per-exec inspection.
	result, found, err := inspectStart(ctx, execID)
	if err != nil {
		return "", fmt.Errorf("inspect exec %q: %w", execID, err)
	}
	if !found {
		return "", nil
	}
	return p.denyReason(result), nil
}

func (p execPolicy) denyReason(result ExecInspectResult) string {
	if len(p.allowedCommands) == 0 && !p.allowBlindWrites {
		return "exec denied: no commands are allowlisted"
	}
	if !p.allowPrivileged && result.Privileged {
		return "exec denied: privileged exec is not allowed"
	}
	if !p.allowRootUser && isRootUser(result.User) {
		return "exec denied: root exec user is not allowed"
	}
	if reason := p.envDenyReason(result.Env); reason != "" {
		return reason
	}
	if len(p.allowedCommands) == 0 {
		// allowBlindWrites is true here (the guard above would have returned
		// otherwise): no argv allowlist is configured, but every other gate —
		// privileged, root user, env — was just checked and passed, so this is
		// exactly the "acknowledged blind write" the flag documents, not an
		// unconditional bypass.
		return ""
	}
	for _, allowed := range p.allowedCommands {
		if allowed.matches(result.Command) {
			return ""
		}
	}
	return fmt.Sprintf("exec denied: command %q is not allowlisted", strings.Join(result.Command, " "))
}

// envDenyReason checks each exec-create Env entry's variable name — the
// substring before the first "=", or the whole entry when no "=" is present —
// against deniedEnvVars and then allowedEnvVars. deniedEnvVars is checked
// first, so a name present in both lists is denied (fail closed on operator
// misconfiguration). Values are never inspected or logged.
//
// When both lists are empty (the default), this always returns "" regardless
// of Env content — the core zero-behavior-change guarantee: enabling
// AllowedCommands must not also start filtering Env unless the operator
// opted into one of these two lists.
func (p execPolicy) envDenyReason(env []string) string {
	if len(p.allowedEnvVars) == 0 && len(p.deniedEnvVars) == 0 && len(p.allowedEnvValues) == 0 {
		return ""
	}
	for _, entry := range env {
		name := execEnvVarName(entry)
		if slices.Contains(p.deniedEnvVars, name) {
			return fmt.Sprintf("exec denied: environment variable %q is denylisted", name)
		}
		if len(p.allowedEnvVars) > 0 && !slices.Contains(p.allowedEnvVars, name) {
			return fmt.Sprintf("exec denied: environment variable %q is not allowlisted", name)
		}
		if allowedValues := p.allowedEnvValues[name]; len(allowedValues) > 0 && !slices.Contains(allowedValues, entry) {
			return fmt.Sprintf("exec denied: environment variable %q has a disallowed value", name)
		}
	}
	return ""
}

// execEnvVarName extracts an exec Env entry's variable name: the substring
// before the first "=", or the whole entry when no "=" is present — matching
// the os.Environ/Docker NAME=VALUE convention. The value half is discarded
// entirely; only the name is ever compared against allowed_env_vars /
// denied_env_vars, so a secret carried in a value can never leak into a
// deny reason.
func execEnvVarName(entry string) string {
	name, _, _ := strings.Cut(entry, "=")
	return name
}

func decodeExecCommand(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, fmt.Errorf("decode exec command: %w", errExecMissingCmd)
	}

	var argv []string
	if err := json.Unmarshal(raw, &argv); err == nil {
		if len(argv) == 0 {
			return nil, fmt.Errorf("decode exec command: %w", errExecEmptyCmdArray)
		}
		return argv, nil
	}

	var command string
	// Docker clients can send exec Cmd as argv or a shell-style string, so we prefer structured args and fall back for compatibility.
	if err := json.Unmarshal(raw, &command); err != nil {
		return nil, fmt.Errorf("decode Cmd string: %w", err)
	}
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return nil, fmt.Errorf("decode exec command: %w", errExecEmptyCmdString)
	}
	return fields, nil
}

// isRootUser reports whether the exec User selects (or defaults to) root. An
// empty value means Docker runs the exec as the container's configured user,
// which is root for most base images, so Sockguard conservatively treats empty
// as root — matching isNonRootUser on the container-create path. Numeric "0" /
// "0:N" and the literal name "root" (any case) are root.
func isRootUser(user string) bool {
	name, _, _ := strings.Cut(strings.TrimSpace(user), ":")
	name = strings.TrimSpace(name)
	if name == "" {
		return true
	}
	return strings.EqualFold(name, "root") || isNumericRootUID(name)
}

func isExecCreatePath(normalizedPath string) bool {
	if !strings.HasPrefix(normalizedPath, "/containers/") {
		return false
	}
	rest := strings.TrimPrefix(normalizedPath, "/containers/")
	_, tail, ok := strings.Cut(rest, "/")
	return ok && tail == "exec"
}

func isExecStartPath(normalizedPath string) bool {
	if !strings.HasPrefix(normalizedPath, "/exec/") {
		return false
	}
	rest := strings.TrimPrefix(normalizedPath, "/exec/")
	_, tail, ok := strings.Cut(rest, "/")
	return ok && tail == "start"
}

// execStartIdentifier extracts the exec ID from a normalized exec-start path,
// reporting whether it came from the libpod family
// (/libpod/exec/{id}/start) or the Docker-compat one (/exec/{id}/start) —
// the two upstream inspection constructors query different URL families
// (see ExecOptions.InspectStartLibpod's doc comment), so the caller needs to
// know which one to use.
func execStartIdentifier(normalizedPath string) (id string, isLibpod bool, ok bool) {
	prefix := "/exec/"
	if strings.HasPrefix(normalizedPath, libpodPathPrefix+"exec/") {
		prefix = libpodPathPrefix + "exec/"
		isLibpod = true
	} else if !strings.HasPrefix(normalizedPath, prefix) {
		return "", false, false
	}
	rest := strings.TrimPrefix(normalizedPath, prefix)
	id, tail, cut := strings.Cut(rest, "/")
	if !cut || id == "" || tail != "start" {
		return "", false, false
	}
	return id, isLibpod, true
}

// NewDockerExecInspector returns an exec inspector backed by the Docker unix
// socket. It is the single-local-socket shorthand; the multi-endpoint/remote
// path uses NewDockerExecInspectorWithRoundTripper.
func NewDockerExecInspector(upstreamSocket string) ExecInspectFunc {
	return NewDockerExecInspectorWithRoundTripper(upstream.NewSingleSocket(upstreamSocket))
}

// NewDockerExecInspectorWithRoundTripper returns an exec inspector that issues
// its short JSON GET through the shared upstream RoundTripper (typically an
// *upstream.Resolver), so exec-identity inspection follows the same active
// endpoint as the exec-create/start it guards under failover.
func NewDockerExecInspectorWithRoundTripper(rt http.RoundTripper) ExecInspectFunc {
	return newHTTPExecInspector(rt, "http://docker/exec/")
}

// NewLibpodExecInspector returns an exec inspector backed by the Podman unix
// socket, querying GET /libpod/exec/{id}/json rather than the Docker-compat
// GET /exec/{id}/json NewDockerExecInspector uses. It is the
// single-local-socket shorthand; the multi-endpoint/remote path uses
// NewLibpodExecInspectorWithRoundTripper. Both libpod and Docker-compat
// exec-start requests are checked against the SAME execPolicy/ExecOptions
// (#148 design doc decision C3) — this constructor only changes which
// upstream URL family the exec-start re-check queries, wired based on
// which path triggered the request (see execStartIdentifier).
func NewLibpodExecInspector(upstreamSocket string) ExecInspectFunc {
	return NewLibpodExecInspectorWithRoundTripper(upstream.NewSingleSocket(upstreamSocket))
}

// NewLibpodExecInspectorWithRoundTripper is NewDockerExecInspectorWithRoundTripper's
// libpod-path counterpart: same failover-aware transport, GET
// /libpod/exec/{id}/json instead of GET /exec/{id}/json. Podman routes both
// URLs to the identical compat.ExecInspectHandler internally (confirmed
// against Podman's own route table, pkg/api/server/register_exec.go), so the
// response shape decoded here is byte-identical to the Docker-compat path —
// see execInspectResponse, shared by both constructors.
func NewLibpodExecInspectorWithRoundTripper(rt http.RoundTripper) ExecInspectFunc {
	return newHTTPExecInspector(rt, "http://docker/libpod/exec/")
}

// newHTTPExecInspector is the shared GET-and-decode implementation behind
// both NewDockerExecInspectorWithRoundTripper and
// NewLibpodExecInspectorWithRoundTripper; only the URL prefix (and therefore
// which upstream route family is queried) differs between the two.
func newHTTPExecInspector(rt http.RoundTripper, urlPrefix string) ExecInspectFunc {
	client := &http.Client{Transport: rt}

	return func(ctx context.Context, id string) (ExecInspectResult, bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlPrefix+url.PathEscape(id)+"/json", nil)
		if err != nil {
			return ExecInspectResult{}, false, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return ExecInspectResult{}, false, err
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode == http.StatusNotFound {
			return ExecInspectResult{}, false, nil
		}
		if resp.StatusCode != http.StatusOK {
			return ExecInspectResult{}, false, fmt.Errorf("upstream returned %s", resp.Status)
		}

		body, err := readBoundedResponseBody(resp)
		if err != nil {
			return ExecInspectResult{}, false, err
		}

		var decoded execInspectResponse
		if err := json.Unmarshal(body, &decoded); err != nil {
			return ExecInspectResult{}, false, err
		}

		command := make([]string, 0, 1+len(decoded.ProcessConfig.Arguments))
		if decoded.ProcessConfig.Entrypoint != "" {
			command = append(command, decoded.ProcessConfig.Entrypoint)
		}
		command = append(command, decoded.ProcessConfig.Arguments...)

		return ExecInspectResult{
			Command:    command,
			Privileged: decoded.ProcessConfig.Privileged,
			User:       decoded.ProcessConfig.User,
		}, true, nil
	}
}
