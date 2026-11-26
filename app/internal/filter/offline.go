package filter

import (
	"log/slog"
	"net/http"
)

// OfflineBodyResult is the outcome of running the request-body inspectors
// against a request without a daemon behind them.
type OfflineBodyResult struct {
	// Inspected is false when no inspector covers the request's method and
	// route, so the body was never read.
	Inspected bool
	// Denied is set when an inspector refused the request.
	Denied bool
	// Reason is the inspector's refusal text, empty unless Denied.
	Reason string
	// ReasonCode is the stable machine-readable code for the refusal
	// (request_body_policy_denied, request_body_too_large, ...).
	ReasonCode string
	// Status is the HTTP status the proxy would answer with, zero unless Denied.
	Status int
	// Hard is set when a warn or audit rollout would not pass the refusal through.
	Hard bool
	// NotEvaluated lists the checks that need the daemon and were skipped.
	NotEvaluated []string
}

// InspectBodyOffline runs the same inspector table the middleware runs, for
// one request, against cfg. normalizedPath must come from NormalizePath. The
// exec inspectors' live lookups (target protection label, existing exec
// instance) stay unset, so they are reported in NotEvaluated instead of
// guessed at. A POST /exec/{id}/start body carries nothing the policy decides
// on, so it is not inspected at all.
func InspectBodyOffline(logger *slog.Logger, r *http.Request, cfg PolicyConfig, mutation MutationOptions) OfflineBodyResult {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	normPath, _, _ := resolveNormalizedRoute(nil, r)

	var out OfflineBodyResult
	if r.Method == http.MethodPost && (isExecStartPath(normPath) || isLibpodExecStartPath(normPath)) {
		out.NotEvaluated = append(out.NotEvaluated, "exec start check (the proxy looks up the existing exec instance on the daemon)")
		return out
	}

	policy := compileRuntimePolicy(nil, cfg, newMutationEngine(mutation))
	for i := range policy.inspectPoliciesByMethod[r.Method] {
		p := &policy.inspectPoliciesByMethod[r.Method][i]
		if p.matches == nil || p.matches(normPath) {
			out.Inspected = true
			break
		}
	}
	if !out.Inspected {
		return out
	}
	if matchesExecInspection(normPath) {
		out.NotEvaluated = append(out.NotEvaluated, "exec target protection label (the proxy reads it from the container on the daemon)")
	}

	if matchesContainerCreateInspection(normPath) || matchesBuildInspection(normPath) || matchesImagePushInspection(normPath) {
		out.NotEvaluated = append(out.NotEvaluated, "upstream engine checks (Docker or Podman flavor and cgroup version are unknown offline, so engine-specific gates ran with their defaults)")
	}

	reason, code, status, hard := policy.inspectAllowedRequestDetail(logger, r, normPath)
	if removeSpooled := closeSpooledRequestBody(logger, r); removeSpooled != nil {
		defer removeSpooled()
	}
	if reason != "" {
		out.Denied = true
		out.Reason = reason
		out.ReasonCode = code
		out.Status = status
		out.Hard = hard
	}
	return out
}
