package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/filter"
)

// Body verdicts reported by `sockguard match --body-file`.
const (
	matchBodyAllow   = "allow"
	matchBodyDeny    = "deny"
	matchBodyNoCheck = "not_inspected"
	matchBodySkipped = "skipped"
)

// matchBody is what the request-body inspectors said about the sample body.
// Decision is allow or deny when an inspector ran, not_inspected when no
// inspector covers the route, and skipped when the rules denied the request
// first (the proxy only inspects requests the rules allowed).
type matchBody struct {
	Source       string   `json:"source"`
	Decision     string   `json:"decision"`
	Reason       string   `json:"reason,omitempty"`
	ReasonCode   string   `json:"reason_code,omitempty"`
	Status       int      `json:"status,omitempty"`
	Hard         bool     `json:"hard,omitempty"`
	Note         string   `json:"note,omitempty"`
	NotEvaluated []string `json:"not_evaluated,omitempty"`
}

// offlinePolicyConfig takes the policy config the proxy would build for the
// selected scope and strips what only a live daemon can answer. The blind-write
// and image-load settings are wired the way serve wires them; the exec
// inspectors' daemon lookups stay unset, and InspectBodyOffline reports them.
func offlinePolicyConfig(cfg *config.Config, policy filter.PolicyConfig) filter.PolicyConfig {
	policy = attachRuntimeInspectors(cfg, nil, policy)
	policy.Exec.InspectTarget = nil
	policy.Exec.InspectStart = nil
	policy.Exec.InspectStartLibpod = nil
	return policy
}

// inspectMatchBody runs the body inspectors on the sample body named by
// source (a file path, or "-" for stdin). The request is rebuilt from req so
// the inspectors see the method, path and query the rules just evaluated.
func inspectMatchBody(cmd *cobra.Command, source string, req *http.Request, policy filter.PolicyConfig, mutation filter.MutationOptions, ruleDecision filter.Action) (*matchBody, error) {
	out := &matchBody{Source: source}
	if ruleDecision != filter.ActionAllow {
		out.Decision = matchBodySkipped
		out.Note = "the rules denied the request, so the proxy never reads its body"
		return out, nil
	}

	var reader io.ReadCloser
	size := int64(-1)
	if source == "-" {
		out.Source = "stdin"
		reader = io.NopCloser(cmd.InOrStdin())
	} else {
		f, err := os.Open(source) // #nosec G304 -- body file is an explicit local CLI argument.
		if err != nil {
			return nil, fmt.Errorf("body file: %w", err)
		}
		if info, err := f.Stat(); err == nil && info.Mode().IsRegular() {
			size = info.Size()
		}
		reader = f
	}

	r := req.Clone(cmd.Context())
	r.Body = reader
	r.ContentLength = size
	result := filter.InspectBodyOffline(nil, r, policy, mutation)
	_ = reader.Close()

	out.NotEvaluated = result.NotEvaluated
	switch {
	case !result.Inspected && len(result.NotEvaluated) > 0:
		out.Decision = matchBodyNoCheck
		out.Note = "no body was read"
	case !result.Inspected:
		out.Decision = matchBodyNoCheck
		out.Note = "no request-body inspector covers this method and path, so the body was not read"
	case result.Denied:
		out.Decision = matchBodyDeny
		out.Reason = result.Reason
		out.ReasonCode = result.ReasonCode
		out.Status = result.Status
		out.Hard = result.Hard
	default:
		out.Decision = matchBodyAllow
	}
	return out, nil
}

func writeMatchBody(w io.Writer, label func(string) string, b *matchBody) {
	if b == nil {
		return
	}
	fmt.Fprintf(w, "%s %s\n", label("Body:"), b.Source)
	line := b.Decision
	if b.Reason != "" {
		line += ": " + b.Reason
	}
	if b.ReasonCode != "" {
		line += " (" + b.ReasonCode + ")"
	}
	fmt.Fprintf(w, "%s %s\n", label("Body decision:"), line)
	if b.Note != "" {
		fmt.Fprintf(w, "%s %s\n", label(""), b.Note)
	}
	for _, note := range b.NotEvaluated {
		fmt.Fprintf(w, "%s %s\n", label("Not evaluated:"), note)
	}
}
