package filter

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/codeswhat/sockguard/v3/app/internal/apipath"
	"github.com/codeswhat/sockguard/v3/app/internal/logging"
)

// ExecTargetInspectResult identifies the container whose exec policy was read.
type ExecTargetInspectResult struct {
	ContainerID string
	Protected   bool
	// ConfigUser is the container's configured Config.User. Docker stores it
	// as the User of any exec created without one, so the exec-start re-check
	// reads it back to tell "unset" from an explicit user.
	ConfigUser string
}

// ExecTargetInspectFunc resolves an exec target and its protection label.
type ExecTargetInspectFunc func(context.Context, string) (ExecTargetInspectResult, bool, error)

func (p execPolicy) targetDenyReason(ctx context.Context, id string) (ExecTargetInspectResult, string, error) {
	if p.inspectTarget == nil {
		return ExecTargetInspectResult{}, "", nil
	}
	if id == "" {
		return ExecTargetInspectResult{}, "exec denied: target container could not be resolved", nil
	}
	target, found, err := p.inspectTarget(ctx, id)
	if err != nil {
		return ExecTargetInspectResult{}, "", fmt.Errorf("inspect exec target: %w", err)
	}
	if !found {
		return ExecTargetInspectResult{}, "", newRequestRejectionError(http.StatusNotFound, "exec denied: target container was not found")
	}
	if target.Protected {
		return ExecTargetInspectResult{}, "exec denied: target container is protected by com.sockguard.exec=deny", nil
	}
	if _, err := hex.DecodeString(target.ContainerID); err != nil || len(target.ContainerID) != 64 {
		return ExecTargetInspectResult{}, "exec denied: target container identity could not be inspected", nil
	}
	return target, "", nil
}

func pinExecTarget(r *http.Request, id string) {
	// Pin the immutable inspected ID so a concurrent rename cannot swap a
	// protected container into an allowed name between inspection and exec.
	p := strings.TrimSuffix(apipath.CanonicalizePath(r.URL.Path), "/exec")
	r.URL.Path = p[:strings.LastIndexByte(p, '/')+1] + id + "/exec"
	r.URL.RawPath = ""
	if meta := logging.Meta(r.Context()); meta != nil {
		meta.NormPath = NormalizePath(r.URL.Path)
	}
}

// NewExecTargetInspectorWithRoundTripper reads target labels from the daemon.
// Podman exposes this compatibility inspect route for native exec targets too.
func NewExecTargetInspectorWithRoundTripper(rt http.RoundTripper) ExecTargetInspectFunc {
	client := &http.Client{Transport: rt}
	return func(ctx context.Context, id string) (ExecTargetInspectResult, bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/"+url.PathEscape(id)+"/json", nil) // #nosec G704 -- the fixed engine URL contains only a path-escaped container identifier.
		if err != nil {
			return ExecTargetInspectResult{}, false, err
		}
		resp, err := client.Do(req) // #nosec G704 -- the injected transport targets the configured container engine.
		if err != nil {
			return ExecTargetInspectResult{}, false, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusNotFound {
			return ExecTargetInspectResult{}, false, nil
		}
		if resp.StatusCode != http.StatusOK {
			return ExecTargetInspectResult{}, false, fmt.Errorf("upstream returned %s", resp.Status)
		}
		body, err := readBoundedResponseBody(resp)
		if err != nil {
			return ExecTargetInspectResult{}, false, err
		}
		var decoded struct {
			ID     string `json:"Id"`
			Config *struct {
				Labels map[string]string `json:"Labels"`
				User   string            `json:"User"`
			} `json:"Config"`
		}
		if err := json.Unmarshal(body, &decoded); err != nil {
			return ExecTargetInspectResult{}, false, err
		}
		if decoded.Config == nil {
			return ExecTargetInspectResult{}, false, fmt.Errorf("container inspect omitted Config")
		}
		return ExecTargetInspectResult{
			ContainerID: decoded.ID,
			Protected:   strings.EqualFold(strings.TrimSpace(decoded.Config.Labels["com.sockguard.exec"]), "deny"),
			ConfigUser:  decoded.Config.User,
		}, true, nil
	}
}
