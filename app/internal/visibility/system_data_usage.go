package visibility

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/httpjson"
	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/responsefilter"
)

// handleVisibilitySystemDataUsageRequest applies the visibility policy to
// GET /system/df on the response side.
//
// Every other visibility-aware list endpoint is constrained by injecting the
// policy's label selectors into the upstream `filters` query parameter and
// letting the daemon do the work. /system/df defines no such parameter, so
// without this the endpoint returns every container, volume and image on the
// host to any caller a rule allows through — the Tecnativa-compat `SYSTEM=1`
// migration path generates exactly that rule.
//
// The whole request is intercepted whenever a policy exists, because a policy
// always has at least one axis by the time this runs (middlewareWithDeps
// short-circuits when it has none).
func handleVisibilitySystemDataUsageRequest(logger *slog.Logger, next http.Handler, w http.ResponseWriter, r *http.Request, policy *compiledPolicy) {
	filterResponseThroughWriter(logger, next, w, r, "visibility system data usage filter failed", func(fw *patternFilterWriter) error {
		dropped, err := fw.flushSystemDataUsage(policy)
		if fresh := responsefilter.FirstSightSystemDataUsageSections(dropped); len(fresh) > 0 {
			logger.WarnContext(r.Context(), "visibility system data usage filter dropped unclassifiable response sections",
				"sections", logging.SafeString(strings.Join(fresh, ",")),
				"note", "this build cannot apply the visibility policy to these sections, so they are hidden rather than forwarded",
				"path", logging.SafeString(r.URL.Path))
		}
		return err
	})
}

// denyLibpodSystemDataUsage refuses GET /libpod/system/df with a 403 without
// contacting the upstream, so the host inventory is never buffered.
//
// The status is 403 rather than the 404 handleVisibilityInspectRequest returns
// for a hidden resource. 404 exists there to deny an existence oracle for a
// caller-named resource; /libpod/system/df is a fixed endpoint of the Podman
// API whose existence is public, and pretending it is absent would send an
// operator debugging their rules in the wrong direction. Like every other
// response-side control in this package it applies regardless of rollout mode.
func denyLibpodSystemDataUsage(w http.ResponseWriter, r *http.Request) {
	reason := responsefilter.LibpodSystemDataUsageDenyReason
	logging.SetDeniedWithCode(w, r, reasonCodeVisibilityLibpodDataUsage, reason, nil)
	_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: reason})
}

// denyLibpodShowMounted refuses GET /libpod/containers/showmounted with a 403
// without contacting the upstream, so neither the daemon host's mount paths
// nor the cross-owner container ID set is ever read. The status and the
// rollout-mode independence are denyLibpodSystemDataUsage's, for the same
// reasons.
func denyLibpodShowMounted(w http.ResponseWriter, r *http.Request) {
	reason := filter.LibpodShowMountedDenyReason
	logging.SetDeniedWithCode(w, r, reasonCodeVisibilityLibpodShowMounted, reason, nil)
	_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: reason})
}

// flushSystemDataUsage filters the buffered /system/df object response item by
// item and writes the result to the underlying ResponseWriter.
//
// Unlike flushFiltered there is no "not the shape we expected, pass it through"
// branch: a /system/df body that will not decode is one we cannot prove is safe
// to forward, so the error propagates and the caller turns it into a 502.
// It returns the names of any top-level response sections this build could not
// classify and therefore removed, so the caller can log them once. See
// responsefilter.FilterSystemDataUsage.
func (p *patternFilterWriter) flushSystemDataUsage(policy *compiledPolicy) ([]string, error) {
	if committed, err := p.commitIfUnfilterable(); committed {
		return nil, err
	}

	filtered, dropped, err := responsefilter.FilterSystemDataUsage(p.body.Bytes(), func(section responsefilter.SystemDataUsageSection, item json.RawMessage) (bool, error) {
		return systemDataUsageItemVisible(section, item, policy)
	})
	if err != nil {
		return nil, err
	}
	return dropped, p.commitFilteredBody(filtered)
}

// systemDataUsageItemVisible applies the same policy axes to a /system/df item
// that the corresponding list endpoint already applies: label selectors for
// every section, plus the name/image pattern axes for containers and images
// (the only two kinds any pattern axis applies to in this package — see
// resourceMetaMatchesPatterns).
func systemDataUsageItemVisible(section responsefilter.SystemDataUsageSection, raw json.RawMessage, policy *compiledPolicy) (bool, error) {
	switch section {
	case responsefilter.SystemDataUsageContainers:
		return systemDataUsageContainerVisible(raw, policy)
	case responsefilter.SystemDataUsageImages:
		return systemDataUsageImageVisible(raw, policy)
	case responsefilter.SystemDataUsageVolumes:
		return systemDataUsageVolumeVisible(raw, policy)
	default:
		// Unreachable today: FilterSystemDataUsage only ever calls this with
		// the sections in its own shape table, and removes every other
		// top-level key outright. Kept fail-closed so that adding a section
		// there before adding it here hides the items rather than forwarding
		// them.
		return false, nil
	}
}

func systemDataUsageContainerVisible(raw json.RawMessage, policy *compiledPolicy) (bool, error) {
	visible, err := systemDataUsageLabelsMatch(raw, "container", policy)
	if err != nil || !visible {
		return false, err
	}
	if !policy.hasPatternAxes() {
		return true, nil
	}
	// /system/df container items are ContainerSummary objects, the same shape
	// /containers/json returns, so the identical pattern check applies.
	return containerItemVisibleByPatterns(raw, policy)
}

func systemDataUsageImageVisible(raw json.RawMessage, policy *compiledPolicy) (bool, error) {
	visible, err := systemDataUsageLabelsMatch(raw, "image", policy)
	if err != nil || !visible {
		return false, err
	}
	if !policy.hasPatternAxes() {
		return true, nil
	}
	// ImageSummary, the same shape /images/json returns.
	return imageItemVisibleByPatterns(raw, policy)
}

func systemDataUsageVolumeVisible(raw json.RawMessage, policy *compiledPolicy) (bool, error) {
	// Name/image pattern axes never apply to volumes — not on /volumes, not on
	// volume inspect (resourceMetaMatchesPatterns returns true for every kind
	// but containers and images). Matching that here keeps a patterns-only
	// policy behaving the same on /system/df as it does on /volumes rather
	// than inventing a volume pattern axis that exists nowhere else.
	return systemDataUsageLabelsMatch(raw, "volume", policy)
}

// systemDataUsageLabelsMatch applies the policy's label selectors to an item's
// Labels map. An item with no labels fails a non-empty selector set, matching
// both matchesSelectors and the daemon-side `label` filter the other list
// endpoints push upstream.
func systemDataUsageLabelsMatch(raw json.RawMessage, kind string, policy *compiledPolicy) (bool, error) {
	if len(policy.selectors) == 0 {
		return true, nil
	}
	var item struct {
		Labels map[string]string `json:"Labels"`
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		return false, fmt.Errorf("decode %s %s item: %w", responsefilter.SystemDataUsagePath, kind, err)
	}
	return matchesSelectors(item.Labels, policy.selectors), nil
}
