package filter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/v3/app/internal/httpjson"
	"github.com/codeswhat/sockguard/v3/app/internal/logging"
)

// service_network_guard.go closes the host-network bypass servicePolicy.inspect
// cannot: that inspector compares ServiceSpec.Networks[].Target and
// TaskTemplate.Networks[].Target against the literal name "host", but the
// daemon resolves a target by full ID, then name, then ID prefix. The host
// network's ID is readable through GET /networks/**, so a request naming that
// ID (or a prefix of it) reaches host networking without ever saying "host".
//
// The resolution needs the daemon, so it runs in ResourceLimitGuard, which sits
// after ownership. The literal-name fast path in servicePolicy.inspect stays.

// NetworkInspectResult carries the part of GET /networks/{target} the host
// network check needs.
type NetworkInspectResult struct {
	ID     string
	Name   string
	Driver string
}

// NetworkInspectFunc resolves a network reference (ID, ID prefix or name) the
// way the daemon does. found=false with err=nil means no network matches.
type NetworkInspectFunc func(ctx context.Context, target string) (NetworkInspectResult, bool, error)

// NewDockerNetworkInspectorWithRoundTripper returns a network inspector that
// issues its GET through the shared upstream RoundTripper.
func NewDockerNetworkInspectorWithRoundTripper(rt http.RoundTripper) NetworkInspectFunc {
	client := &http.Client{Transport: rt}
	return func(ctx context.Context, target string) (NetworkInspectResult, bool, error) {
		requestPath, ok := dockerresource.InspectPath(dockerresource.KindNetwork, target)
		if !ok {
			return NetworkInspectResult{}, false, fmt.Errorf("no inspect path for network %q", target)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+requestPath, nil) // #nosec G704 -- InspectPath escapes the identifier into a fixed /networks/ path.
		if err != nil {
			return NetworkInspectResult{}, false, err
		}
		resp, err := client.Do(req) // #nosec G704 -- the injected transport targets the local container-engine socket, not the URL host.
		if err != nil {
			return NetworkInspectResult{}, false, err
		}
		defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

		if resp.StatusCode == http.StatusNotFound {
			return NetworkInspectResult{}, false, nil
		}
		if resp.StatusCode != http.StatusOK {
			return NetworkInspectResult{}, false, fmt.Errorf("inspect network %q returned status %d", target, resp.StatusCode)
		}
		body, err := readBoundedResponseBody(resp)
		if err != nil {
			return NetworkInspectResult{}, false, err
		}
		var decoded struct {
			ID     string `json:"Id"`
			Name   string `json:"Name"`
			Driver string `json:"Driver"`
		}
		if err := json.Unmarshal(body, &decoded); err != nil {
			return NetworkInspectResult{}, false, err
		}
		return NetworkInspectResult{ID: decoded.ID, Name: decoded.Name, Driver: decoded.Driver}, true, nil
	}
}

type serviceNetworkTargets struct {
	TaskTemplate struct {
		Networks []serviceNetwork `json:"Networks"`
	} `json:"TaskTemplate"`
	Networks     []serviceNetwork `json:"Networks"`
	UpdateConfig *struct {
		FailureAction string `json:"FailureAction"`
	} `json:"UpdateConfig"`
}

// failureActionIsRollback reports whether the body asks for the daemon's
// automatic rollback, which reactivates the service's current (pre-update)
// spec when the update fails.
func (req serviceNetworkTargets) failureActionIsRollback() bool {
	return req.UpdateConfig != nil && strings.EqualFold(strings.TrimSpace(req.UpdateConfig.FailureAction), "rollback")
}

func (req serviceNetworkTargets) targets() []string {
	var out []string
	for _, group := range [][]serviceNetwork{req.Networks, req.TaskTemplate.Networks} {
		for _, network := range group {
			if target := strings.TrimSpace(network.Target); target != "" {
				out = append(out, target)
			}
		}
	}
	return out
}

// guardServiceNetworks denies a service create/update whose network targets
// resolve to the host network. It returns false when a response was written.
func (g *resourceLimitGuard) guardServiceNetworks(w http.ResponseWriter, r *http.Request, normalizedPath string, policy PolicyConfig) bool {
	if policy.Service.AllowHostNetwork {
		return true
	}
	if id, isUpdate := serviceUpdateIdentifier(normalizedPath); isUpdate {
		manual, valid := serviceManualRollbackQuery(r)
		// With a resource requirement configured, guardServiceWrite runs next
		// and refuses these same cases with its policy metadata attached.
		ownedByRequirements := serviceRequirementsList(policy.Service) != ""
		if !valid && !ownedByRequirements {
			// A repeated rollback value is ambiguous, so it can't be treated as
			// an ordinary update that skips the stored-spec check.
			g.denyServiceNetwork(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
				"service update denied: rollback query parameter must have exactly one value", policy.DenyResponseVerbosity)
			return false
		}
		if manual {
			if _, ok := serviceVersionQuery(r); !ok && !ownedByRequirements {
				// Without exactly one numeric version the rollback target can't be
				// pinned to the state the caller inspected.
				g.denyServiceNetwork(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
					"service update denied: a single numeric version query parameter is required", policy.DenyResponseVerbosity)
				return false
			}
			// The daemon ignores the body and re-applies the stored PreviousSpec,
			// so that is what gets resolved. Only an update does: create
			// ignores rollback and reads the body.
			if serviceRequirementsList(policy.Service) != "" {
				// guardServiceRollbackTarget inspects the service for the
				// resource requirements anyway and resolves these same
				// targets from that one snapshot.
				return true
			}
			return g.guardServiceRollbackNetworks(w, r, id, policy)
		}
	}
	body, err := readBoundedBodyUnchecked(r, maxServiceBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			g.denyServiceNetwork(w, r, http.StatusRequestEntityTooLarge, reasonCodeRequestBodyTooLarge,
				fmt.Sprintf("service denied: request body exceeds %d byte limit", maxServiceBodyBytes), policy.DenyResponseVerbosity)
			return false
		}
		g.denyServiceNetwork(w, r, http.StatusBadRequest, reasonCodeRequestBodyInspectionFailed,
			"service denied: request body could not be read", policy.DenyResponseVerbosity)
		return false
	}
	var req serviceNetworkTargets
	if len(bytes.TrimSpace(body)) == 0 || json.Unmarshal(body, &req) != nil {
		// An undecodable body is refused by the body inspector ahead of this
		// guard and by the daemon's own decoder; there are no targets to resolve.
		return true
	}

	if !g.guardNetworkTargets(w, r, req.targets(), policy.DenyResponseVerbosity) {
		return false
	}

	// An update with UpdateConfig.FailureAction=rollback can fail and make the
	// daemon reactivate the service's current spec, which this request never
	// carries. That spec may name the host network (created before the policy
	// tightened, or out of band), so its targets get the same resolution.
	// With a resource requirement configured, guardServiceWrite inspects the
	// service for the automatic rollback anyway and resolves them there.
	if id, isUpdate := serviceUpdateIdentifier(normalizedPath); isUpdate && req.failureActionIsRollback() &&
		serviceRequirementsList(policy.Service) == "" {
		return g.guardServiceAutomaticRollbackNetworks(w, r, id, policy)
	}
	return true
}

// guardServiceAutomaticRollbackNetworks resolves the networks of the service's
// current spec, which an automatic rollback re-applies. A missing inspector or
// a failed lookup fails closed with 502.
func (g *resourceLimitGuard) guardServiceAutomaticRollbackNetworks(w http.ResponseWriter, r *http.Request, id string, policy PolicyConfig) bool {
	if _, ok := serviceVersionQuery(r); !ok {
		// Docker requires exactly one numeric version on an update. Without it
		// the inspected spec can't be pinned to the state the caller saw.
		g.denyServiceNetwork(w, r, http.StatusBadRequest, reasonCodeResourceLimitRequestInvalid,
			"service update denied: a single numeric version query parameter is required", policy.DenyResponseVerbosity)
		return false
	}
	current, ok := g.inspectServiceForRollbackNetworks(w, r, id, policy, "automatic")
	if !ok {
		return false
	}
	if current == nil {
		return true
	}
	return g.guardNetworkTargets(w, r, current.SpecNetworkTargets, policy.DenyResponseVerbosity)
}

// inspectServiceForRollbackNetworks looks the service up for a rollback
// host-network check and pins it to the version the caller sent. It returns
// ok=false when a response was written, and a nil result with ok=true when the
// service does not exist (the daemon will 404 it itself).
func (g *resourceLimitGuard) inspectServiceForRollbackNetworks(w http.ResponseWriter, r *http.Request, id string, policy PolicyConfig, kind string) (*ServiceInspectResult, bool) {
	if g.inspectService == nil {
		g.denyServiceNetwork(w, r, http.StatusBadGateway, reasonCodeRequestBodyInspectionFailed,
			"service denied: network verification unavailable", policy.DenyResponseVerbosity)
		return nil, false
	}
	current, found, err := g.inspectService(r.Context(), id)
	if err != nil {
		logRequestError(g.logger, r, slog.LevelError, "failed to inspect service for "+kind+" rollback host-network guard", err)
		g.denyServiceNetwork(w, r, http.StatusBadGateway, reasonCodeRequestBodyInspectionFailed,
			"service denied: network verification unavailable", policy.DenyResponseVerbosity)
		return nil, false
	}
	if !found {
		return nil, true
	}
	// Pin the targets resolved here to the version the caller sent, so a
	// service that changed since the caller inspected it is refused rather
	// than judged on a spec the caller never saw.
	if version, ok := serviceVersionQuery(r); ok && version != current.Version {
		g.denyServiceNetwork(w, r, http.StatusConflict, reasonCodeResourceLimitPolicyStateChanged,
			"service update denied: the service state changed since it was inspected; retry with the current version", policy.DenyResponseVerbosity)
		return nil, false
	}
	return &current, true
}

// guardServiceRollbackNetworks resolves the networks of the service's stored
// PreviousSpec, which ?rollback=previous re-applies in place of the body. A
// missing inspector or a failed lookup fails closed with 502.
func (g *resourceLimitGuard) guardServiceRollbackNetworks(w http.ResponseWriter, r *http.Request, id string, policy PolicyConfig) bool {
	current, ok := g.inspectServiceForRollbackNetworks(w, r, id, policy, "manual")
	if !ok {
		return false
	}
	if current == nil {
		return true
	}
	return g.guardNetworkTargets(w, r, current.PreviousSpecNetworkTargets, policy.DenyResponseVerbosity)
}

// errNetworkVerificationUnavailable marks a host-network check that could not
// be completed, so the caller fails closed.
var errNetworkVerificationUnavailable = errors.New("network verification unavailable")

// resolvesToHostNetwork reports whether any target is, or resolves to, the
// host network. A target the daemon doesn't know is skipped, since the daemon
// rejects it itself. A missing inspector or a failed lookup is an error.
func (g *resourceLimitGuard) resolvesToHostNetwork(r *http.Request, targets []string) (bool, error) {
	for _, target := range targets {
		if strings.EqualFold(target, "host") {
			return true, nil
		}
		if g.inspectNetwork == nil {
			return false, errNetworkVerificationUnavailable
		}
		network, found, err := g.inspectNetwork(r.Context(), target)
		if err != nil {
			logRequestError(g.logger, r, slog.LevelError, "failed to inspect service network for host-network guard", err)
			return false, err
		}
		if !found {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(network.Driver), "host") || strings.EqualFold(strings.TrimSpace(network.Name), "host") {
			return true, nil
		}
	}
	return false, nil
}

// guardNetworkTargets denies when any target is, or resolves to, the host
// network. It returns false when a response was written.
func (g *resourceLimitGuard) guardNetworkTargets(w http.ResponseWriter, r *http.Request, targets []string, verbosity DenyResponseVerbosity) bool {
	host, err := g.resolvesToHostNetwork(r, targets)
	if err != nil {
		g.denyServiceNetwork(w, r, http.StatusBadGateway, reasonCodeRequestBodyInspectionFailed,
			"service denied: network verification unavailable", verbosity)
		return false
	}
	if host {
		return !g.denyServiceNetwork(w, r, http.StatusForbidden, reasonCodeRequestBodyPolicyDenied,
			"service denied: host network is not allowed", verbosity)
	}
	return true
}

// denyServiceNetwork writes the guard's denial. A 403 policy denial honors the
// profile's warn/audit pass-through like the body inspector it backs up; a
// lookup or read failure never does. It reports whether a response was
// written, so false means the request is to be forwarded.
func (g *resourceLimitGuard) denyServiceNetwork(w http.ResponseWriter, r *http.Request, status int, reasonCode, reason string, verbosity DenyResponseVerbosity) bool {
	if status == http.StatusForbidden && logging.MetaForRequest(w, r).AllowsPassThrough() {
		logging.SetWouldDenyWithCode(w, r, reasonCode, reason, nil)
		return false
	}
	logging.SetDeniedWithCode(w, r, reasonCode, reason, nil)
	if err := httpjson.Write(w, status, denyResponse(r, reason, verbosity)); err != nil {
		logRequestError(g.logger, r, slog.LevelError, "failed to encode service network denial response", err)
	}
	return true
}
