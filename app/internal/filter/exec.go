package filter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

const maxExecBodyBytes = 64 << 10 // 64 KiB

// ExecInspectResult captures the effective exec command metadata Docker stores
// after POST /containers/{id}/exec and returns from GET /exec/{id}/json.
type ExecInspectResult struct {
	Command    []string
	Privileged bool
	User       string
}

// ExecInspectFunc looks up an existing exec instance by id.
type ExecInspectFunc func(context.Context, string) (ExecInspectResult, bool, error)

// ExecOptions configures request-body policy checks for exec creation/start.
type ExecOptions struct {
	AllowPrivileged bool
	AllowRootUser   bool
	AllowedCommands [][]string
	InspectStart    ExecInspectFunc
}

type execPolicy struct {
	allowPrivileged bool
	allowRootUser   bool
	allowedCommands [][]string
	inspectStart    ExecInspectFunc
}

type execCreateRequest struct {
	Cmd        json.RawMessage `json:"Cmd"`
	Privileged bool            `json:"Privileged"`
	User       string          `json:"User"`
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
	allowed := make([][]string, 0, len(opts.AllowedCommands))
	for _, command := range opts.AllowedCommands {
		if len(command) == 0 {
			continue
		}
		copied := append([]string(nil), command...)
		allowed = append(allowed, copied)
	}

	return execPolicy{
		allowPrivileged: opts.AllowPrivileged,
		allowRootUser:   opts.AllowRootUser,
		allowedCommands: allowed,
		inspectStart:    opts.InspectStart,
	}
}

func (p execPolicy) inspect(r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost {
		return "", nil
	}

	switch {
	case isExecCreatePath(normalizedPath):
		return p.inspectCreate(r)
	case isExecStartPath(normalizedPath):
		return p.inspectExisting(r.Context(), normalizedPath)
	default:
		return "", nil
	}
}

func (p execPolicy) inspectCreate(r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxExecBodyBytes+1))
	if closeErr := r.Body.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	if int64(len(body)) > maxExecBodyBytes {
		return fmt.Sprintf("exec denied: request body exceeds %d byte limit", maxExecBodyBytes), nil
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	if len(body) == 0 {
		return "", nil
	}

	var req execCreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return "", nil
	}

	command, err := decodeExecCommand(req.Cmd)
	if err != nil {
		return "", nil
	}

	return p.denyReason(ExecInspectResult{
		Command:    command,
		Privileged: req.Privileged,
		User:       req.User,
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
	for _, allowed := range p.allowedCommands {
		if slices.Equal(result.Command, allowed) {
			return ""
		}
	}
	return fmt.Sprintf("exec denied: command %q is not allowlisted", strings.Join(result.Command, " "))
}

func decodeExecCommand(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, fmt.Errorf("missing Cmd")
	}

	var argv []string
	if err := json.Unmarshal(raw, &argv); err == nil {
		if len(argv) == 0 {
			return nil, fmt.Errorf("empty Cmd array")
		}
		return argv, nil
	}

	var command string
	if err := json.Unmarshal(raw, &command); err != nil {
		return nil, err
	}
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return nil, fmt.Errorf("empty Cmd string")
	}
	return fields, nil
}

func isRootUser(user string) bool {
	if user == "" {
		return false
	}
	name, _, _ := strings.Cut(user, ":")
	return name == "root" || name == "0"
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

// NewDockerExecInspector returns an exec inspector backed by the Docker unix socket.
func NewDockerExecInspector(upstreamSocket string) ExecInspectFunc {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", upstreamSocket)
		},
	}
	client := &http.Client{Transport: transport}

	return func(ctx context.Context, id string) (ExecInspectResult, bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/exec/"+url.PathEscape(id)+"/json", nil)
		if err != nil {
			return ExecInspectResult{}, false, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return ExecInspectResult{}, false, err
		}
		defer resp.Body.Close()

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
