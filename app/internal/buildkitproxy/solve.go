// Package buildkitproxy — this file carries Phase 3 (issue #185)'s per-
// message policy decision for moby.buildkit.v1.Control's two mediated RPCs:
// evaluateSolveRequest and evaluateStatusRequest. Both take an already-
// decoded message and a Policy and return nil (admit) or a *mediationDenial
// describing the gRPC status and audit reason code to use — pure decision
// functions bridge.go's forwardControlMediated calls after framing/decode
// succeeds, kept free of any http/gRPC-wire concerns so they're unit
// testable without a live bridge.
package buildkitproxy

import (
	"fmt"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/codeswhat/sockguard/internal/buildkitproto/control"
)

// mediationDenial carries the gRPC status code, audit reason code (one of
// the #185 synthesis's low-cardinality vocabulary — see bridge.go's audit),
// and human-readable message for a Solve/Status call Phase 3's per-message
// checks reject. message is sockguard's own fixed/templated text, or names
// only structural facts already validated as printable (a method/service
// name, a fixed field name) — never raw client-supplied content, per
// CLAUDE.md's "never log secret contents" constraint extended to gRPC status
// messages a client can read back.
type mediationDenial struct {
	code       int
	reasonCode string
	message    string
}

func deny(code int, reasonCode, message string) *mediationDenial {
	return &mediationDenial{code: code, reasonCode: reasonCode, message: message}
}

// BuildKit entitlement identifiers, as sent in SolveRequest.Entitlements.
// Reproduced as string constants rather than imported from moby/buildkit's
// util/entitlements package — this package must never import moby/buildkit's
// implementation graph (see registry.go's package doc).
const (
	entitlementNetworkHost      = "network.host"
	entitlementSecurityInsecure = "security.insecure"
)

// allowedSolveFrontends is Phase 3's fixed frontend allowlist — NOT an
// operator-facing config knob, matching registry.go's own fixed
// classification table convention for "no enabling knob" surfaces. "" is a
// raw LLB Solve with no external frontend image to resolve/execute at all;
// "dockerfile.v0" is BuildKit's built-in, in-process Dockerfile frontend.
// Every other frontend — most notably "gateway.v0", which lets a client name
// an arbitrary frontend IMAGE for buildkitd to pull and execute with control
// over the build via the moby.buildkit.v1.frontend.LLBBridge callback
// service — is denied: LLBBridge is hard-denied surface with no enabling
// knob (registry.go's DeniedExamples), so admitting the frontend that is
// LLBBridge's only way to get invoked would just relocate the same hole.
var allowedSolveFrontends = map[string]bool{
	"":              true,
	"dockerfile.v0": true,
}

// knownFrontendAttrKeys is Phase 3's fixed allowlist of FrontendAttrs keys
// sockguard recognizes well enough to have a policy opinion about. Per the
// #185 synthesis's strict divergence #3, any OTHER key denies the whole
// Solve (buildkit_schema_unsupported) rather than being silently forwarded
// unexamined — a permissive default here is exactly the silent-bypass
// channel divergence #3 rejects. Bumping this set for a new Buildx release
// is a reviewed, committed change, like registry.go's own table.
var knownFrontendAttrKeys = map[string]bool{
	"filename":           true, // path to the Dockerfile within the build context
	"context":            true, // build context: local path or remote URL — see isRemoteContextRef
	"target":             true, // multi-stage build target name
	"platform":           true, // requested output platform(s)
	"cmdline":            true, // frontend-selected alternate command line (e.g. syntax directive override)
	"no-cache":           true,
	"nocache":            true,
	"multi-platform":     true,
	"shm-size":           true,
	"ulimit":             true,
	"hostname":           true,
	"cgroup-parent":      true,
	"image-resolve-mode": true,
	"add-hosts":          true,
	"force-network-mode": true, // gated when the value is "host" — see checkSolveFrontend
}

// knownFrontendAttrPrefixes are FrontendAttrs key FAMILIES rather than exact
// keys: build-arg:<name>, label:<name>, and context:<name> (additional named
// build contexts) each carry an operator-irrelevant suffix chosen by the
// build invocation, not sockguard's schema.
var knownFrontendAttrPrefixes = []string{
	"build-arg:",
	"label:",
	"context:",
}

// isKnownFrontendAttrKey reports whether key is in Phase 3's fixed
// FrontendAttrs allowlist — an exact match in knownFrontendAttrKeys, or a
// member of one of knownFrontendAttrPrefixes' families.
func isKnownFrontendAttrKey(key string) bool {
	if knownFrontendAttrKeys[key] {
		return true
	}
	for _, prefix := range knownFrontendAttrPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// isRemoteContextRef reports whether a "context" or "context:<name>"
// FrontendAttrs value names a remote location (a URL-shaped git/http(s)
// context, mirroring classic POST /build's remote-context detection) rather
// than a path within the build context sockguard already treats as local.
func isRemoteContextRef(value string) bool {
	for _, prefix := range []string{"http://", "https://", "git://", "git@", "github.com/"} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return strings.Contains(value, "://")
}

// registryHostFromImageRef extracts the registry authority from an
// image-like reference, using the same disambiguation rule Docker's own
// reference grammar uses: split on the first '/'; if that first component
// contains neither '.' nor ':' and isn't exactly "localhost", it is NOT a
// registry host at all (it's the first path segment of a repository name on
// the default registry, e.g. "library/alpine") — so the ref resolves to
// "docker.io". Duplicated here in miniature rather than imported from
// internal/filter or internal/config: this package is a dependency-light
// leaf that must not import either (see registry.go's package doc for the
// same constraint applied to grpc-go). ok is false only for an empty ref.
func registryHostFromImageRef(ref string) (host string, ok bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", false
	}
	if idx := strings.Index(ref, "://"); idx >= 0 {
		ref = ref[idx+len("://"):]
	}

	first, _, hasSlash := strings.Cut(ref, "/")
	if !hasSlash || (!strings.ContainsAny(first, ".:") && first != "localhost") {
		return "docker.io", true
	}
	host = strings.ToLower(first)
	if host == "index.docker.io" {
		host = "docker.io"
	}
	return host, true
}

// evaluateSolveRequest decodes payload as a control.SolveRequest and runs
// every Phase 3 policy check against policy.Control.Solve, in the order the
// #185 synthesis lists them: unknown fields first (nothing else can be
// trusted to mean what it says otherwise), then entitlements, frontend +
// frontend attrs, cache, exporters, and source policy. Returns the decoded
// request (for the caller to read Ref off, for ref-registry admission) and a
// nil denial on success, or a nil request and non-nil denial on the first
// check that fails.
func evaluateSolveRequest(payload []byte, policy Policy) (*control.SolveRequest, *mediationDenial) {
	req := &control.SolveRequest{}
	if err := proto.Unmarshal(payload, req); err != nil {
		return nil, deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "malformed SolveRequest")
	}
	if hasUnknownFields(req) {
		return nil, deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
	}

	solvePolicy := policy.Control.Solve
	if d := checkSolveEntitlements(req.GetEntitlements(), solvePolicy); d != nil {
		return nil, d
	}
	if d := checkSolveFrontend(req, solvePolicy); d != nil {
		return nil, d
	}
	if d := checkSolveCache(req, solvePolicy); d != nil {
		return nil, d
	}
	if d := checkSolveExporters(req, solvePolicy); d != nil {
		return nil, d
	}
	if d := checkSolveSourcePolicy(req); d != nil {
		return nil, d
	}

	return req, nil
}

// checkSolveEntitlements enforces the #185 synthesis's entitlement rules:
// network.host requires AllowHostNetwork, security.insecure is denied
// outright regardless of policy (no v1.7 enabling knob), and any entitlement
// string sockguard doesn't recognize is denied rather than silently admitted
// — an unknown entitlement is a signal sockguard cannot evaluate, and per
// this package's default-deny identity an unevaluable signal must not pass.
func checkSolveEntitlements(entitlements []string, solvePolicy SolvePolicy) *mediationDenial {
	for _, e := range entitlements {
		switch e {
		case entitlementSecurityInsecure:
			return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "the security.insecure entitlement is denied")
		case entitlementNetworkHost:
			if !solvePolicy.AllowHostNetwork {
				return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "the network.host entitlement requires this profile's allow_host_network")
			}
		default:
			return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "unrecognized entitlement")
		}
	}
	return nil
}

// checkSolveFrontend enforces the frontend allowlist and, for each
// FrontendAttrs entry, the known-key allowlist plus the two attrs that map
// onto an existing request_body.build semantic: "context"/"context:<name>"
// naming a remote location requires AllowRemoteContext, and
// "force-network-mode" == "host" requires AllowHostNetwork (the frontend's
// own default-network-mode knob, independent of the Entitlements-level
// network.host check above — a Dockerfile build can request host networking
// for its RUN instructions this way without ever setting the SolveRequest
// entitlement itself).
func checkSolveFrontend(req *control.SolveRequest, solvePolicy SolvePolicy) *mediationDenial {
	if !allowedSolveFrontends[req.GetFrontend()] {
		return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "frontend is not permitted")
	}

	for key, value := range req.GetFrontendAttrs() {
		if !isKnownFrontendAttrKey(key) {
			return deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
		}
		switch {
		case (key == "context" || strings.HasPrefix(key, "context:")) && isRemoteContextRef(value):
			if !solvePolicy.AllowRemoteContext {
				return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "a remote build context requires this profile's allow_remote_context")
			}
		case key == "force-network-mode" && value == "host":
			if !solvePolicy.AllowHostNetwork {
				return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "force-network-mode=host requires this profile's allow_host_network")
			}
		}
	}
	return nil
}

// checkSolveCache enforces the cache import/export allowlists. The
// deprecated pre-0.4.0 singular cache-ref fields (CacheOptions.
// ExportRefDeprecated/ImportRefsDeprecated/ExportAttrsDeprecated) are denied
// outright rather than translated into the modern Exports/Imports shape the
// way buildkitd itself would: sockguard's allowlist enforcement below only
// ever inspects Exports/Imports, so silently accepting the deprecated
// fields unenforced would be a real bypass channel for an ostensibly
// unknown-but-actually-just-old wire shape, not a compatibility nicety.
func checkSolveCache(req *control.SolveRequest, solvePolicy SolvePolicy) *mediationDenial {
	if req.GetExporterDeprecated() != "" || len(req.GetExporterAttrsDeprecated()) > 0 {
		return deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
	}

	cache := req.GetCache()
	if cache == nil {
		return nil
	}
	if cache.GetExportRefDeprecated() != "" || len(cache.GetImportRefsDeprecated()) > 0 || len(cache.GetExportAttrsDeprecated()) > 0 {
		return deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
	}

	for _, entry := range cache.GetImports() {
		if d := checkCacheEntry(entry, solvePolicy.AllowedCacheImportTypes, solvePolicy.AllowedCacheRegistries); d != nil {
			return d
		}
	}
	for _, entry := range cache.GetExports() {
		if d := checkCacheEntry(entry, solvePolicy.AllowedCacheExportTypes, solvePolicy.AllowedCacheRegistries); d != nil {
			return d
		}
	}
	return nil
}

// checkCacheEntry validates one CacheOptionsEntry (an import or an export)
// against its direction's type allowlist and, for the "registry" type, the
// shared cache-registry allowlist.
func checkCacheEntry(entry *control.CacheOptionsEntry, allowedTypes, allowedRegistries []string) *mediationDenial {
	if entry == nil {
		return nil
	}
	if !slices.Contains(allowedTypes, entry.GetType()) {
		return deny(grpcCodePermissionDenied, "buildkit_policy_denied", fmt.Sprintf("cache type %q is not permitted", entry.GetType()))
	}
	if entry.GetType() != "registry" {
		return nil
	}
	host, ok := registryHostFromImageRef(entry.GetAttrs()["ref"])
	if !ok || !slices.Contains(allowedRegistries, host) {
		return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "cache registry is not permitted")
	}
	return nil
}

// checkSolveExporters enforces the exporter type allowlist, the exporter
// registry allowlist for an "image" exporter that pushes, and denies
// EnableSessionExporter outright: that flag opts into the session-based
// exporter negotiation handled by moby.exporter.v1.Exporter, which is
// hard-denied surface with no v1.7 enabling knob (registry.go's
// DeniedExamples) — admitting the flag here would just let a build declare
// intent to use a service the bridge only rejects once the daemon actually
// tries to call back into it.
func checkSolveExporters(req *control.SolveRequest, solvePolicy SolvePolicy) *mediationDenial {
	for _, exp := range req.GetExporters() {
		if exp == nil {
			continue
		}
		if !slices.Contains(solvePolicy.AllowedExporters, exp.GetType()) {
			return deny(grpcCodePermissionDenied, "buildkit_policy_denied", fmt.Sprintf("exporter type %q is not permitted", exp.GetType()))
		}
		attrs := exp.GetAttrs()
		if exp.GetType() == "image" && attrs["push"] == "true" {
			host, ok := registryHostFromImageRef(attrs["name"])
			if !ok || !slices.Contains(solvePolicy.AllowedExporterRegistries, host) {
				return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "exporter push registry is not permitted")
			}
		}
	}
	if req.GetEnableSessionExporter() {
		return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "session-based exporter negotiation is not supported")
	}
	return nil
}

// checkSolveSourcePolicy denies any Solve carrying a non-empty source
// policy outright: source policy rules can rewrite image references at
// solve time, which could otherwise be used to route around sockguard's own
// registry allowlists elsewhere in the proxy, and no phase has added a
// config surface to review/allow specific rewrite rules — matching the
// "no enabling knob" posture registry.go's DeniedExamples uses for other
// unaudited surfaces.
func checkSolveSourcePolicy(req *control.SolveRequest) *mediationDenial {
	if req.GetSourcePolicy() != nil && len(req.GetSourcePolicy().GetRules()) > 0 {
		return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "source policy rules are not supported")
	}
	return nil
}

// evaluateStatusRequest decodes payload as a control.StatusRequest and
// checks it for unknown fields. Ref-ownership (the #185 synthesis's "belongs
// to an admitted Solve from the same client identity + profile" rule) is
// deliberately NOT checked here — it needs the bridge's SessionRegistry and
// SessionKey, which this decode-only, bridge-independent function has no
// access to and shouldn't: see bridge.go's forwardControlMediated, which
// calls this first and then separately consults
// SessionRegistry.OwnsRef(b.session.Key, req.GetRef()) before admitting.
func evaluateStatusRequest(payload []byte) (*control.StatusRequest, *mediationDenial) {
	req := &control.StatusRequest{}
	if err := proto.Unmarshal(payload, req); err != nil {
		return nil, deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "malformed StatusRequest")
	}
	if hasUnknownFields(req) {
		return nil, deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
	}
	return req, nil
}
