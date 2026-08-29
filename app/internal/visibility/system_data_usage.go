package visibility

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

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
		return fw.flushSystemDataUsage(policy)
	})
}

// flushSystemDataUsage filters the buffered /system/df object response item by
// item and writes the result to the underlying ResponseWriter.
//
// Unlike flushFiltered there is no "not the shape we expected, pass it through"
// branch: a /system/df body that will not decode is one we cannot prove is safe
// to forward, so the error propagates and the caller turns it into a 502.
func (p *patternFilterWriter) flushSystemDataUsage(policy *compiledPolicy) error {
	if committed, err := p.commitIfUnfilterable(); committed {
		return err
	}

	filtered, err := responsefilter.FilterSystemDataUsage(p.body.Bytes(), func(section responsefilter.SystemDataUsageSection, item json.RawMessage) (bool, error) {
		return systemDataUsageItemVisible(section, item, policy)
	})
	if err != nil {
		return err
	}
	return p.commitFilteredBody(filtered)
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
		// A section this build does not know how to classify is hidden rather
		// than forwarded: a future Engine API section would otherwise become an
		// unfiltered enumeration channel the moment a daemon started returning
		// it.
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
