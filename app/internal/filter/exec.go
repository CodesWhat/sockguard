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
	// position.
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
	InspectStart  ExecInspectFunc
}

type execPolicy struct {
	allowPrivileged bool
	allowRootUser   bool
	allowedCommands []execCommandMatcher
	allowedEnvVars  []string
	deniedEnvVars   []string
	inspectStart    ExecInspectFunc
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
		allowPrivileged: opts.AllowPrivileged,
		allowRootUser:   opts.AllowRootUser,
		allowedCommands: allowed,
		allowedEnvVars:  normalizeExecEnvNames(opts.AllowedEnvVars),
		deniedEnvVars:   normalizeExecEnvNames(opts.DeniedEnvVars),
		inspectStart:    opts.InspectStart,
	}
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
	case isExecCreatePath(normalizedPath):
		return p.inspectCreate(logger, r)
	case isExecStartPath(normalizedPath):
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
		if logger != nil {
			logger.DebugContext(r.Context(), "exec request body is not valid JSON; deferring to Docker validation", "error", err, "method", r.Method, "path", r.URL.Path)
		}
		return "exec denied: request body could not be inspected", nil
	}

	command, err := decodeExecCommand(req.Cmd)
	if err != nil {
		if logger != nil {
			logger.DebugContext(r.Context(), "exec request body has unparseable Cmd; denying", "error", err, "method", r.Method, "path", r.URL.Path)
		}
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
	execID, ok := execStartIdentifier(normalizedPath)
	if !ok {
		return "", nil
	}
	if p.inspectStart == nil {
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
	result, found, err := p.inspectStart(ctx, execID)
	if err != nil {
		return "", fmt.Errorf("inspect exec %q: %w", execID, err)
	}
	if !found {
		return "", nil
	}
	return p.denyReason(result), nil
}

func (p execPolicy) denyReason(result ExecInspectResult) string {
	if len(p.allowedCommands) == 0 {
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
	if len(p.allowedEnvVars) == 0 && len(p.deniedEnvVars) == 0 {
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

func execStartIdentifier(normalizedPath string) (string, bool) {
	if !strings.HasPrefix(normalizedPath, "/exec/") {
		return "", false
	}
	rest := strings.TrimPrefix(normalizedPath, "/exec/")
	id, tail, ok := strings.Cut(rest, "/")
	if !ok || id == "" || tail != "start" {
		return "", false
	}
	return id, true
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
	client := &http.Client{Transport: rt}

	return func(ctx context.Context, id string) (ExecInspectResult, bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/exec/"+url.PathEscape(id)+"/json", nil)
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

		var decoded execInspectResponse
		if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
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
