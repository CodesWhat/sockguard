package filter

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/google/go-containerregistry/pkg/name"
)

// mutation.go implements fail-closed declarative admission mutations
// (#151): a bounded set of config-driven label-injection and image-remap
// rules applied to a request body before the corresponding
// container_create/service body inspector, image-trust verification, and
// ownership stamping run. See middleware.go's compileRuntimePolicy for the
// registration order this depends on: the two mutation entries are placed
// BEFORE container_create/service in the same inspectSeverityCritical
// bucket for the same paths, and inspectAllowedRequest runs every policy in
// a matched bucket in slice order (verified by reading middleware.go:448-486
// — not "first match wins", "every match, in order"). That ordering is what
// makes the mutated bytes get the FULL existing downstream inspection
// (privilege/mount/device/hardening/label checks, then registry policy,
// then image-trust verify+pin) automatically: every downstream inspector
// re-reads r.Body fresh via its own readBoundedBody call, so it cannot tell
// (and does not try to tell) whether the bytes it sees came from the client
// or from this stage.

// maxMutationBodyBytes caps the request body the mutation engine will read,
// matching every sibling per-surface cap (container-create, service).
const maxMutationBodyBytes = 1 << 20 // 1 MiB

// Mutation surface identifiers, matching the config.MutationRuleConfig
// `surfaces` enum vocabulary exactly. Duplicated here as plain strings
// (rather than imported from internal/config) because filter must not
// import config — the dependency runs the other way — matching how mode
// strings ("enforce"/"warn"/"audit") are already duplicated in a few
// packages rather than centralized.
const (
	mutationSurfaceContainerCreate = "container_create"
	mutationSurfaceServiceCreate   = "service_create"
	mutationSurfaceServiceUpdate   = "service_update"
)

// Mutation rule outcome vocabulary, matching the audit/access log schema.
const (
	mutationOutcomeApplied    = "applied"
	mutationOutcomeNoop       = "noop"
	mutationOutcomeWouldApply = "would_apply"
	mutationOutcomeWouldNoop  = "would_noop"
	mutationOutcomeFailed     = "failed"
)

// Mutation-specific reason codes (middleware.go's shared constant block also
// has the pre-existing request_body_* codes downstream inspectors continue
// to use unchanged).
const (
	reasonCodeMutationRequestInvalid      = "mutation_request_invalid"
	reasonCodeMutationRequestTooLarge     = "mutation_request_too_large"
	reasonCodeMutationApplyFailed         = "mutation_apply_failed"
	reasonCodeMutationPostconditionFailed = "mutation_postcondition_failed"
)

// MutationOptions configures declarative admission-mutation rules. It is
// global — carried on filter.Options, not filter.PolicyConfig — because
// mutation config is not part of per-client-profile overrides (v1 has a
// single mutation authority; see config.MutationsConfig's doc comment).
type MutationOptions struct {
	Rules []MutationRuleOptions
}

// MutationRuleOptions is one compiled-from-config declarative admission
// rule: exactly one of InjectLabels/RemapImage is expected to be set —
// config validation enforces this before it ever reaches the filter package.
type MutationRuleOptions struct {
	ID           string
	Mode         string // "enforce" | "warn" | "audit"; empty defaults to "enforce"
	Surfaces     []string
	InjectLabels *InjectLabelsMutationOptions
	RemapImage   *ImageRemapMutationOptions
}

// InjectLabelsMutationOptions unconditionally sets/replaces the configured
// labels on every request matching the rule's surfaces.
type InjectLabelsMutationOptions struct {
	Labels map[string]string
}

// ImageRemapMutationOptions rewrites a matched image reference.
type ImageRemapMutationOptions struct {
	Match string // "exact" | "prefix"
	From  string
	To    string
}

// mutationRuleKind discriminates the two mutation operations. Kept as an
// unexported int (rather than reusing a string) so compiledMutationRule's
// switch is exhaustive-checkable; String() renders the audit/log vocabulary.
type mutationRuleKind int

const (
	mutationRuleInjectLabels mutationRuleKind = iota
	mutationRuleRemapImage
)

func (k mutationRuleKind) String() string {
	if k == mutationRuleRemapImage {
		return "remap_image"
	}
	return "inject_labels"
}

// compiledMutationRule is one rule fanned out to one surface bucket.
type compiledMutationRule struct {
	id     string
	mode   string
	kind   mutationRuleKind
	labels map[string]string

	remapMatch string
	remapFrom  string
	remapTo    string
}

// mutationEngine is the compiled, immutable form of MutationOptions,
// bucketed by surface so each request's inspect() call does a single map
// lookup rather than re-filtering the full rule list. Compiled once per
// filter.MiddlewareWithOptions call (reload rebuilds the whole handler
// chain, including this) and shared read-only across the default policy and
// every client profile, since mutation config is global.
type mutationEngine struct {
	bySurface map[string][]compiledMutationRule
}

func newMutationEngine(opts MutationOptions) *mutationEngine {
	eng := &mutationEngine{bySurface: make(map[string][]compiledMutationRule)}
	for _, r := range opts.Rules {
		mode := strings.ToLower(strings.TrimSpace(r.Mode))
		if mode == "" {
			mode = "enforce"
		}

		var cr compiledMutationRule
		cr.id = r.ID
		cr.mode = mode
		switch {
		case r.InjectLabels != nil:
			cr.kind = mutationRuleInjectLabels
			cr.labels = r.InjectLabels.Labels
		case r.RemapImage != nil:
			cr.kind = mutationRuleRemapImage
			cr.remapMatch = strings.ToLower(strings.TrimSpace(r.RemapImage.Match))
			cr.remapFrom = r.RemapImage.From
			cr.remapTo = r.RemapImage.To
		default:
			// Config validation guarantees exactly one of the two blocks is
			// set before this ever runs; skip defensively rather than panic
			// if that invariant is ever violated by a future caller (e.g. a
			// test constructing MutationOptions directly).
			continue
		}

		for _, surface := range r.Surfaces {
			eng.bySurface[surface] = append(eng.bySurface[surface], cr)
		}
	}
	return eng
}

func (e *mutationEngine) rulesFor(surface string) []compiledMutationRule {
	if e == nil {
		return nil
	}
	return e.bySurface[surface]
}

// mutationPolicy is the requestInspectPolicy.inspect implementation shared
// by the container-create and service mutation entries; surface resolves
// the request to a bucket key in the engine.
type mutationPolicy struct {
	engine  *mutationEngine
	surface func(normalizedPath string) string
}

func newContainerCreateMutationPolicy(engine *mutationEngine) mutationPolicy {
	return mutationPolicy{
		engine:  engine,
		surface: func(string) string { return mutationSurfaceContainerCreate },
	}
}

func newServiceMutationPolicy(engine *mutationEngine) mutationPolicy {
	return mutationPolicy{
		engine: engine,
		surface: func(normalizedPath string) string {
			if normalizedPath == "/services/create" {
				return mutationSurfaceServiceCreate
			}
			return mutationSurfaceServiceUpdate
		},
	}
}

// inspect applies every enforce-mode rule to the actual document, records
// (without applying) every warn/audit-mode rule against an independent
// cloned document, and commits the mutated body only if an enforce rule
// actually changed something. It never itself produces a deny reason for a
// well-formed request — the eventual allow/deny verdict is still decided by
// container_create/service's own inspect(), which runs immediately after
// this in the same severity bucket and has never heard of "mutation": it
// just re-reads whatever bytes are in r.Body.
func (p mutationPolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || r.Body == nil {
		return "", nil
	}

	surface := p.surface(normalizedPath)
	rules := p.engine.rulesFor(surface)
	if len(rules) == 0 {
		// No configured rules for this surface: zero behavior change,
		// including at the byte level — the body is never read.
		return "", nil
	}

	body, err := readBoundedBody(r, maxMutationBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionErrorWithCode(
				http.StatusRequestEntityTooLarge,
				reasonCodeMutationRequestTooLarge,
				fmt.Sprintf("%s denied: request body exceeds %d byte limit", surface, maxMutationBodyBytes),
			)
		}
		return "", fmt.Errorf("read body: %w", err)
	}
	if len(body) == 0 {
		// Consistent with every downstream inspector: an empty body isn't
		// this layer's problem to reject; let the surface's own inspector
		// (and ultimately Docker) handle it.
		return "", nil
	}

	actual, err := parseMutationDocument(body, mutationMaxNodes(len(body)))
	if err != nil {
		logRequestError(logger, r, slog.LevelDebug, "mutation request body is not a well-formed, unambiguous JSON object; denying", nil)
		return "", newRequestRejectionErrorWithCode(
			http.StatusBadRequest,
			reasonCodeMutationRequestInvalid,
			fmt.Sprintf("%s denied: request body could not be safely parsed for admission mutation", surface),
		)
	}

	var shadow map[string]any
	for _, rule := range rules {
		if rule.mode != "enforce" {
			shadow, _ = deepCloneJSONValue(actual).(map[string]any)
			break
		}
	}

	trace := make([]logging.MutationRuleOutcome, 0, len(rules))
	changed := false
	warnEvaluated := false

	for _, rule := range rules {
		if rule.mode == "enforce" {
			outcome, applyErr := applyMutationRule(actual, surface, rule)
			if applyErr != nil {
				logRequestError(logger, r, slog.LevelDebug, "admission mutation rule failed to apply; denying", nil)
				return "", newRequestRejectionErrorWithCode(
					http.StatusBadRequest,
					reasonCodeMutationApplyFailed,
					fmt.Sprintf("%s denied: admission mutation rule %q could not be applied", surface, rule.id),
				)
			}
			if outcome == mutationOutcomeApplied {
				changed = true
			}
			trace = append(trace, logging.MutationRuleOutcome{ID: rule.id, Type: rule.kind.String(), Mode: rule.mode, Outcome: outcome})
			continue
		}

		if rule.mode == "warn" {
			warnEvaluated = true
		}
		outcome, applyErr := applyMutationRule(shadow, surface, rule)
		if applyErr != nil {
			trace = append(trace, logging.MutationRuleOutcome{ID: rule.id, Type: rule.kind.String(), Mode: rule.mode, Outcome: mutationOutcomeFailed})
			continue
		}
		dryOutcome := mutationOutcomeWouldNoop
		if outcome == mutationOutcomeApplied {
			dryOutcome = mutationOutcomeWouldApply
		}
		trace = append(trace, logging.MutationRuleOutcome{ID: rule.id, Type: rule.kind.String(), Mode: rule.mode, Outcome: dryOutcome})
	}

	if changed {
		final, merr := json.Marshal(actual)
		if merr != nil {
			return "", newRequestRejectionErrorWithCode(
				http.StatusInternalServerError,
				reasonCodeMutationPostconditionFailed,
				fmt.Sprintf("%s denied: admission mutation result could not be serialized", surface),
			)
		}
		// Mandatory re-parse of Sockguard's own output through the exact
		// same strict scanner/decoder used on the client's input. This
		// should be unreachable — the write primitives above only ever
		// collapse to one canonical key and set string/object leaves — but
		// it is cheap, load-bearing defense-in-depth against a future bug
		// in those primitives silently reintroducing an ambiguity, and it
		// is what "canonicalize... before forwarding" requires literally,
		// not just "canonicalize the input".
		if _, verr := parseMutationDocument(final, mutationMaxNodes(len(final))); verr != nil {
			return "", newRequestRejectionErrorWithCode(
				http.StatusInternalServerError,
				reasonCodeMutationPostconditionFailed,
				fmt.Sprintf("%s denied: admission mutation result failed postcondition verification", surface),
			)
		}
		replaceRequestBody(r, final)
	}
	// If nothing changed, r.Body/r.ContentLength already hold the exact
	// original bytes readBoundedBody restored — no action needed. A
	// warn/audit-only evaluation never reaches this branch's write path
	// regardless of what the shadow document looks like.

	recordMutationOutcome(r, trace, changed, warnEvaluated)

	return "", nil
}

// recordMutationOutcome attaches a pooled logging.MutationRecord to the
// request's logging.RequestMeta (stashed into r's context by
// MiddlewareWithOptions specifically so this — and any future inspector —
// can reach it without widening the inspectorFunc signature every existing
// inspector implements). A nil meta (e.g. in a unit test that drives
// inspect() directly without the outer middleware) is a silent no-op:
// mutation still applies/denies correctly, it just isn't recorded.
func recordMutationOutcome(r *http.Request, trace []logging.MutationRuleOutcome, changed, warnEvaluated bool) {
	if len(trace) == 0 {
		return
	}
	meta := logging.Meta(r.Context())
	if meta == nil {
		return
	}
	rec := logging.GetMutationRecord()
	rec.Rules = append(rec.Rules[:0], trace...)
	rec.ActualChanged = changed
	rec.HasWarnEvaluation = warnEvaluated
	meta.Mutation = rec
}

// applyMutationRule applies one rule to doc (either the actual document that
// will be committed, or an independent shadow clone for warn/audit modes)
// and reports whether it actually changed something.
func applyMutationRule(doc map[string]any, surface string, rule compiledMutationRule) (string, error) {
	if doc == nil {
		return mutationOutcomeNoop, nil
	}
	switch rule.kind {
	case mutationRuleInjectLabels:
		return applyInjectLabels(doc, surface, rule.labels)
	case mutationRuleRemapImage:
		return applyRemapImage(doc, surface, rule)
	default:
		return mutationOutcomeNoop, nil
	}
}

// mutationLabelTargets returns the label-map field paths a label-injection
// rule targets for surface, matching the v1 surface/action matrix exactly:
// container_create writes Config.Labels; service_create writes both
// Service.Labels and TaskTemplate.ContainerSpec.Labels (mirroring
// ownership.mutateServiceOwnershipBody, which stamps both for the identical
// reason — either alone is an incomplete label surface); service_update
// does not support label injection (config validation rejects an
// inject_labels rule naming it, so this returns nil defensively).
func mutationLabelTargets(surface string) [][]string {
	switch surface {
	case mutationSurfaceContainerCreate:
		return [][]string{{"Labels"}}
	case mutationSurfaceServiceCreate:
		return [][]string{{"Labels"}, {"TaskTemplate", "ContainerSpec", "Labels"}}
	default:
		return nil
	}
}

func applyInjectLabels(doc map[string]any, surface string, labels map[string]string) (string, error) {
	targets := mutationLabelTargets(surface)
	if len(targets) == 0 {
		return mutationOutcomeNoop, nil
	}

	changed := false
	for _, path := range targets {
		target, err := NestedObjectPath(doc, path...)
		if err != nil {
			return "", fmt.Errorf("inject_labels target %s: %w", strings.Join(path, "."), err)
		}
		for key, value := range labels {
			if existing, ok := target[key]; !ok || existing != value {
				changed = true
			}
			target[key] = value
		}
	}

	if changed {
		return mutationOutcomeApplied, nil
	}
	return mutationOutcomeNoop, nil
}

// mutationImagePath returns the image field path a remap-image rule targets
// for surface: container_create's root-level Image; service_create/
// service_update's TaskTemplate.ContainerSpec.Image.
func mutationImagePath(surface string) []string {
	switch surface {
	case mutationSurfaceContainerCreate:
		return []string{"Image"}
	case mutationSurfaceServiceCreate, mutationSurfaceServiceUpdate:
		return []string{"TaskTemplate", "ContainerSpec", "Image"}
	default:
		return nil
	}
}

func applyRemapImage(doc map[string]any, surface string, rule compiledMutationRule) (string, error) {
	path := mutationImagePath(surface)
	if len(path) == 0 {
		return mutationOutcomeNoop, nil
	}

	parent, ok := navigateFoldedObjectPath(doc, path[:len(path)-1]...)
	if !ok {
		// Absent TaskTemplate/ContainerSpec: nothing to remap. Downstream
		// container_create/service inspection (or Docker itself) is
		// responsible for rejecting a malformed/incomplete body; mutation
		// only ever acts on a field that is actually present.
		return mutationOutcomeNoop, nil
	}

	leaf := path[len(path)-1]
	current, present, isString := foldedStringLeaf(parent, leaf)
	if !present {
		return mutationOutcomeNoop, nil
	}
	if !isString {
		return "", fmt.Errorf("remap_image target %s is not a string", strings.Join(path, "."))
	}

	trimmed := strings.TrimSpace(current)
	next, matched := mutationRemapMatch(trimmed, rule.remapMatch, rule.remapFrom, rule.remapTo)
	if !matched {
		return mutationOutcomeNoop, nil
	}
	if err := validateMutationImageReference(next); err != nil {
		return "", fmt.Errorf("remap_image result: %w", err)
	}
	if next == current {
		return mutationOutcomeNoop, nil
	}

	setFoldedStringLeaf(parent, leaf, next)
	return mutationOutcomeApplied, nil
}

// mutationRemapMatch reports the remapped value (and whether from actually
// matched current) for one image-remap rule. exact replaces the whole
// reference; prefix replaces the leading from once and preserves the rest —
// no chaining, no case folding, no implicit docker.io/library alias
// expansion (documented deviation from Docker CLI convenience behavior:
// "nginx" and "docker.io/library/nginx" are different literal strings here).
func mutationRemapMatch(current, match, from, to string) (string, bool) {
	switch match {
	case "exact":
		if current != from {
			return "", false
		}
		return to, true
	case "prefix":
		if !strings.HasPrefix(current, from) {
			return "", false
		}
		return to + strings.TrimPrefix(current, from), true
	default:
		return "", false
	}
}

// validateMutationImageReference confirms a computed remap result parses as
// a plausible Docker image reference before it can ever reach a
// downstream inspector or the daemon. It reuses go-containerregistry's weak
// reference grammar (name.WeakValidation) — the exact rules
// imagefetch.PinnedReference already applies when pinning a verified
// image-trust digest — rather than inventing a second, potentially
// divergent validator. This runs only when a remap_image rule is both
// configured and its `from` actually matched the current image, mirroring
// how the (also opt-in) image-trust verifier is only ever invoked when
// image_trust is configured: go-containerregistry stays off every request
// that hasn't opted into a feature that needs it.
func validateMutationImageReference(ref string) error {
	if strings.TrimSpace(ref) == "" {
		return fmt.Errorf("remapped image reference is empty")
	}
	if _, err := name.ParseReference(ref, name.WeakValidation); err != nil {
		return fmt.Errorf("invalid image reference %q: %w", ref, err)
	}
	return nil
}
