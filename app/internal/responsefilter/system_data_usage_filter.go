package responsefilter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
)

// SystemDataUsagePath is the normalized path of the Docker Engine
// GET /system/df endpoint.
const SystemDataUsagePath = "/system/df"

// LibpodSystemDataUsagePath is the normalized path of Podman's NATIVE
// GET /libpod/system/df endpoint. It is not a spelling of
// SystemDataUsagePath: Podman registers the two on separate handlers that
// return different bodies (pkg/api/server/register_system.go at v5.8.1 wires
// /system/df to compat.GetDiskUsage and /libpod/system/df to
// libpod.DiskUsage), and NormalizePath strips the API version prefix but not
// the /libpod segment, so the two never collapse onto one another.
//
// The version-prefixed spelling a real client sends normalizes to exactly
// this constant. Podman reports its own release string as the libpod API
// version — version.APIVersion[Libpod][CurrentAPI] is version.Version, which
// is rawversion.RawVersion, "5.8.1" at that tag — and only the versioned
// route is registered for the native endpoint, so bindings issue
// /v5.8.1/libpod/system/df. stripVersionPrefix accepts the three-part semver
// Podman uses as well as any other /vN[.N[.N]]/ form the route regex
// (/v{version:[0-9][0-9A-Za-z.-]*}) admits, so /v5.0.0/libpod/system/df
// normalizes here too.
const LibpodSystemDataUsagePath = LibpodPathPrefix + SystemDataUsagePath

// LibpodShowMountedPath is the normalized path of Podman's native collection
// endpoint that returns every mounted container ID and daemon-host mount path.
const LibpodShowMountedPath = "/libpod/containers/showmounted"

// LibpodShowMountedDenyReason is shared by ownership and visibility when they
// refuse an inventory whose entries carry no labels or names those policies
// can use to scope the response safely.
const LibpodShowMountedDenyReason = "libpod mounted-container inventory denied: " +
	"/libpod/containers/showmounted returns every mounted container ID and daemon-host mount path, so it cannot be scoped to one caller"

// LibpodSystemDataUsageDenyReason is the operator-facing reason the ownership
// and visibility middlewares report when they refuse GET /libpod/system/df.
// Both share this string so the two layers cannot drift into explaining the
// same refusal differently.
//
// The refusal exists because the native endpoint's body cannot be classified
// at all, not because filtering it was merely unimplemented. libpod.DiskUsage
// serializes entities.SystemDfReport verbatim, and at Podman v5.8.1
// (pkg/domain/entities/types/system.go) that report is:
//
//	SystemDfReport          {ImagesSize, Images, Containers, Volumes}
//	SystemDfImageReport     {Repository, Tag, ImageID, Created, Size,
//	                         SharedSize, UniqueSize, Containers}
//	SystemDfContainerReport {ContainerID, Image, Command, LocalVolumes, Size,
//	                         RWSize, Created, Status, Names}
//	SystemDfVolumeReport    {VolumeName, Links, Size, ReclaimableSize}
//
// None of the three item structs carries a Labels field, and none of them
// carries a json tag either, so those Go field names are the wire names.
// Owner isolation and visibility policy both decide per item by reading a
// label off that item, which is why FilterSystemDataUsage can scope the
// Docker-compat shape: its Images/Containers/Volumes entries are
// ImageSummary/ContainerSummary/Volume objects, all of which have Labels.
// Nothing in the native report identifies a tenant, so every item in it is
// unclassifiable in exactly the sense a build-cache record is — and this
// package's answer to unclassifiable is already "hidden, never forwarded".
//
// Refusing is the honest form of that here rather than emptying the report.
// A rewritten body would report zero images, zero containers and zero volumes
// to `podman system df`, which is indistinguishable from an idle host and
// invites the operator to believe an isolation guarantee the shape cannot
// support. A refusal says which endpoint could not be scoped and why.
//
// Correlating the report against the label-filtered libpod list endpoints
// (/libpod/containers/json and friends) to recover an owned-ID set is the
// only mechanism that could isolate this shape. It is deliberately not what
// this does: it turns one client request into several upstream ones, it makes
// the result depend on ID-spelling agreement between two different Podman
// report types, and every aggregate in the response would still have to be
// zeroed. That is a different feature, not a completion of this one.
const LibpodSystemDataUsageDenyReason = "libpod system data usage denied: " +
	"/libpod/system/df returns Podman's native disk-usage report, whose image, container and volume " +
	"entries carry no labels, so it cannot be scoped to one caller"

// SystemDataUsageSection names the resource section of a /system/df response
// that an item was decoded from, so a caller's keep predicate can apply the
// right policy without re-deriving the item's kind from its fields.
type SystemDataUsageSection string

const (
	// SystemDataUsageContainers items are ContainerSummary objects — the same
	// shape GET /containers/json returns.
	SystemDataUsageContainers SystemDataUsageSection = "containers"
	// SystemDataUsageImages items are ImageSummary objects — the same shape
	// GET /images/json returns.
	SystemDataUsageImages SystemDataUsageSection = "images"
	// SystemDataUsageVolumes items are Volume objects — the same shape the
	// Volumes array of GET /volumes returns.
	SystemDataUsageVolumes SystemDataUsageSection = "volumes"
)

// SystemDataUsageKeepFunc reports whether one /system/df item stays in the
// filtered response. Returning an error aborts the whole filter, which callers
// turn into a fail-closed 502 rather than shipping a partially filtered body.
//
// It is never called for build-cache records; see FilterSystemDataUsage.
type SystemDataUsageKeepFunc func(SystemDataUsageSection, json.RawMessage) (bool, error)

// systemDataUsageShape maps one resource section onto the two response shapes
// the Docker Engine API has used for GET /system/df.
//
// Engine API <= 1.51 returns bare arrays at the top level:
//
//	{"LayersSize":N,"Images":[…],"Containers":[…],"Volumes":[…],"BuildCache":[…]}
//
// Engine API >= 1.52 replaced them with per-section usage objects and dropped
// LayersSize entirely:
//
//	{"ImageUsage":{"ActiveCount":N,"TotalCount":N,"Reclaimable":N,"TotalSize":N,"Items":[…]}, …}
//
// Both key sets are handled on every response, because the proxy has no
// reliable way to know which one it is looking at: the client's requested API
// version is advisory, the upstream may be Podman's Docker-compat API, and
// API v1.52 itself returns BOTH shapes at once so existing integrations can
// transition (the legacy fields stop being returned at v1.53). Absent keys are
// skipped, which also covers the ?type= query that lets a client ask for only
// some sections.
type systemDataUsageShape struct {
	section  SystemDataUsageSection
	usageKey string // Engine API >= 1.52 wrapper object
	arrayKey string // Engine API <= 1.51 bare array
}

var systemDataUsageShapes = []systemDataUsageShape{
	{section: SystemDataUsageContainers, usageKey: "ContainerUsage", arrayKey: "Containers"},
	{section: SystemDataUsageImages, usageKey: "ImageUsage", arrayKey: "Images"},
	{section: SystemDataUsageVolumes, usageKey: "VolumeUsage", arrayKey: "Volumes"},
}

const (
	buildCacheUsageKey = "BuildCacheUsage"
	buildCacheArrayKey = "BuildCache"
	layersSizeKey      = "LayersSize"
	usageItemsKey      = "Items"
	usageTotalCountKey = "TotalCount"
)

// zeroedSystemDataUsageAggregates are the per-section totals that describe the
// whole host and are NOT exactly derivable from the items that survive
// filtering, so they are zeroed rather than recomputed. See
// FilterSystemDataUsage for the reasoning.
var zeroedSystemDataUsageAggregates = [...]string{"ActiveCount", "Reclaimable", "TotalSize"}

var jsonZero = json.RawMessage("0")

// FilterSystemDataUsage rewrites a GET /system/df response body, keeping only
// the container, image and volume items for which keep returns true.
//
// It exists because /system/df accepts no `filters` query parameter, so the
// request-side label-injection both the ownership and visibility middlewares
// use for /containers/json cannot reach it. Every decision therefore has to be
// made on the response.
//
// Three deliberate choices, all fail-closed:
//
//   - Build-cache records are dropped wholesale whenever this runs. A
//     BuildCache/CacheRecord carries no Labels field at all (only ID, Parents,
//     Type, Description, InUse, Shared, Size, CreatedAt, LastUsedAt,
//     UsageCount), so no caller can classify one as owned or visible — and
//     Description quotes the originating Dockerfile/build step verbatim, which
//     is exactly the cross-tenant disclosure the item-level filter exists to
//     stop. Unclassifiable means hidden.
//
//   - TotalCount is recomputed as the number of surviving items. It is exactly
//     derivable from the body the client receives, so reporting it keeps the
//     response internally consistent rather than inventing a number.
//
//   - ActiveCount, Reclaimable, TotalSize and the legacy top-level LayersSize
//     are zeroed. The daemon computes each of them across every resource on the
//     host, so leaving them is a residual aggregate leak, and none can be
//     recomputed exactly from the surviving items: image sizes share layers,
//     and Reclaimable/ActiveCount encode daemon-internal in-use state that the
//     item summaries do not carry. A plausible-but-wrong total that
//     `docker system df` renders as authoritative is worse than an obviously
//     absent one, and per-item sizes are still present for a caller that wants
//     to total its own resources under semantics it controls.
//
//   - A top-level key this build does not recognize is REMOVED, and its name
//     is returned so the caller can say so. The section allowlist is the whole
//     mechanism: this function rewrites the body by deleting and replacing keys
//     in a decoded map and re-encoding it, so anything left in that map reaches
//     the client verbatim. A future Engine API section, or one only a
//     Docker-compat upstream emits, would therefore be a fully unfiltered
//     enumeration channel the moment a daemon started returning it, which is
//     exactly the disclosure the item-level filter exists to stop. Unknown
//     scalars go the same way: they are host-wide aggregates of a kind this
//     build cannot recompute, the same reason LayersSize is zeroed.
//
// Callers must only invoke this when an owner or visibility policy is actually
// active: it is not a no-op, and running it against an unconfigured proxy would
// zero totals nobody asked to hide.
//
// The returned body is a fresh buffer; the input is not modified. The returned
// section names are sorted and deduplicated.
func FilterSystemDataUsage(body []byte, keep SystemDataUsageKeepFunc) ([]byte, []string, error) {
	if keep == nil {
		return nil, nil, errors.New("system data usage filter requires a keep predicate")
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, nil, fmt.Errorf("decode %s response: %w", SystemDataUsagePath, err)
	}

	dropped := dropUnknownSystemDataUsageKeys(payload)

	for _, shape := range systemDataUsageShapes {
		keepItem := func(item json.RawMessage) (bool, error) { return keep(shape.section, item) }
		if err := filterSystemDataUsageSection(payload, shape.usageKey, shape.arrayKey, keepItem); err != nil {
			return nil, nil, err
		}
	}

	if err := filterSystemDataUsageSection(payload, buildCacheUsageKey, buildCacheArrayKey, dropSystemDataUsageItem); err != nil {
		return nil, nil, err
	}

	if _, ok := payload[layersSizeKey]; ok {
		payload[layersSizeKey] = jsonZero
	}

	filtered, err := marshalJSONPreservingEscapes(payload)
	if err != nil {
		return nil, nil, err
	}
	return filtered, dropped, nil
}

// knownSystemDataUsageKeys is every top-level key FilterSystemDataUsage knows
// how to rewrite, across both response shapes. It is derived from the shape
// table rather than written out again, so adding a section cannot leave the
// allowlist behind.
var knownSystemDataUsageKeys = func() map[string]struct{} {
	known := map[string]struct{}{
		buildCacheUsageKey: {},
		buildCacheArrayKey: {},
		layersSizeKey:      {},
	}
	for _, shape := range systemDataUsageShapes {
		known[shape.usageKey] = struct{}{}
		known[shape.arrayKey] = struct{}{}
	}
	return known
}()

// dropUnknownSystemDataUsageKeys removes every top-level key outside the
// allowlist and returns their names, sorted. See FilterSystemDataUsage.
func dropUnknownSystemDataUsageKeys(payload map[string]json.RawMessage) []string {
	var dropped []string
	for key := range payload {
		if _, known := knownSystemDataUsageKeys[key]; known {
			continue
		}
		dropped = append(dropped, key)
		delete(payload, key)
	}
	sort.Strings(dropped)
	return dropped
}

// unreportedSystemDataUsageKeys tracks which unknown section names have already
// been logged, so a dashboard polling /system/df does not restate the same
// drift on every scrape.
var unreportedSystemDataUsageKeys sync.Map

// FirstSightSystemDataUsageSections returns the subset of sections that have
// not been reported before in this process, marking them reported.
//
// The dropped-section set is a property of the daemon's API version rather than
// of any one request, so it is stable for the lifetime of a process and worth
// exactly one log record. Callers pass the names FilterSystemDataUsage
// returned; the empty case is the overwhelmingly common one and allocates
// nothing.
func FirstSightSystemDataUsageSections(sections []string) []string {
	var fresh []string
	for _, section := range sections {
		if _, seen := unreportedSystemDataUsageKeys.LoadOrStore(section, struct{}{}); !seen {
			fresh = append(fresh, section)
		}
	}
	return fresh
}

// dropSystemDataUsageItem is the keep predicate for build-cache records: they
// are unclassifiable, so they never survive. See FilterSystemDataUsage.
func dropSystemDataUsageItem(json.RawMessage) (bool, error) { return false, nil }

func filterSystemDataUsageSection(payload map[string]json.RawMessage, usageKey, arrayKey string, keepItem func(json.RawMessage) (bool, error)) error {
	if raw, ok := payload[usageKey]; ok && !isJSONNull(raw) {
		filtered, err := filterSystemDataUsageWrapper(raw, usageKey, keepItem)
		if err != nil {
			return err
		}
		payload[usageKey] = filtered
	}
	if raw, ok := payload[arrayKey]; ok && !isJSONNull(raw) {
		filtered, _, err := filterSystemDataUsageArray(raw, arrayKey, keepItem)
		if err != nil {
			return err
		}
		payload[arrayKey] = filtered
	}
	return nil
}

// filterSystemDataUsageWrapper filters the Items array of an Engine API >= 1.52
// per-section usage object and rewrites that object's aggregate totals.
func filterSystemDataUsageWrapper(raw json.RawMessage, key string, keepItem func(json.RawMessage) (bool, error)) (json.RawMessage, error) {
	var usage map[string]json.RawMessage
	if err := json.Unmarshal(raw, &usage); err != nil {
		return nil, fmt.Errorf("decode %s %s: %w", SystemDataUsagePath, key, err)
	}

	// Items is omitempty in the Engine API schema, so an absent or null Items
	// means the section disclosed nothing and the recomputed count is 0.
	kept := 0
	if items, ok := usage[usageItemsKey]; ok && !isJSONNull(items) {
		filtered, count, err := filterSystemDataUsageArray(items, key+"."+usageItemsKey, keepItem)
		if err != nil {
			return nil, err
		}
		usage[usageItemsKey] = filtered
		kept = count
	}

	for _, aggregate := range zeroedSystemDataUsageAggregates {
		if _, ok := usage[aggregate]; ok {
			usage[aggregate] = jsonZero
		}
	}
	if _, ok := usage[usageTotalCountKey]; ok {
		usage[usageTotalCountKey] = json.RawMessage(strconv.Itoa(kept))
	}

	return marshalJSONPreservingEscapes(usage)
}

func filterSystemDataUsageArray(raw json.RawMessage, label string, keepItem func(json.RawMessage) (bool, error)) (json.RawMessage, int, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, 0, fmt.Errorf("decode %s %s: %w", SystemDataUsagePath, label, err)
	}

	// Non-nil zero-length slice so an all-filtered section marshals to [] and
	// not null: Docker clients index the array without a nil check.
	kept := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		keep, err := keepItem(item)
		if err != nil {
			return nil, 0, fmt.Errorf("filter %s %s: %w", SystemDataUsagePath, label, err)
		}
		if keep {
			kept = append(kept, item)
		}
	}

	encoded, err := marshalJSONPreservingEscapes(kept)
	if err != nil {
		return nil, 0, err
	}
	return encoded, len(kept), nil
}

// marshalJSONPreservingEscapes encodes value without json.Marshal's HTML
// escaping, so item bytes we pass through unchanged reach the client exactly as
// the daemon wrote them. streamArrayResponse makes the same choice for the same
// reason.
func marshalJSONPreservingEscapes(value any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	// json.Encoder.Encode terminates every value with a newline.
	return json.RawMessage(bytes.TrimSuffix(buf.Bytes(), []byte("\n"))), nil
}

func isJSONNull(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}

// ClearUpstreamRepresentationHeaders strips the upstream response's
// representation metadata from header. Any path that abandons an upstream
// body and substitutes a rewritten or error payload must call this first,
// otherwise the client receives the daemon's Content-Encoding / ETag /
// Content-Range or Trailer announcement describing a body it will never see.
func ClearUpstreamRepresentationHeaders(header http.Header) {
	for _, name := range [...]string{
		"Accept-Ranges",
		"Content-Digest",
		"Content-Encoding",
		"Content-Language",
		"Content-Length",
		"Content-Location",
		"Content-MD5",
		"Content-Range",
		"Digest",
		"ETag",
		"Last-Modified",
		"Repr-Digest",
		"Trailer",
		"Transfer-Encoding",
	} {
		header.Del(name)
	}
}
