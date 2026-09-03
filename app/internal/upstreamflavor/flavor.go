// Package upstreamflavor identifies which container engine sits behind the
// upstream socket.
//
// Sockguard proxies the Docker API, and more than one engine speaks it. That
// is usually invisible, because Podman's Docker-compat API is a faithful
// translation for the endpoints sockguard mediates. It is not invisible for
// GET /events. Podman registers /events and /libpod/events on ONE handler
// (pkg/api/server/register_events.go at v5.8.1 puts compat.GetEvents behind
// both), and that handler evaluates several values under a single filter key
// disjunctively — libpod/events/filters.go's applyFilters carries the comment
// "Filters under the same key are disjunctive while each key must match
// (conjuctive)". dockerd ANDs them. A label filter that narrows a stream on
// one engine therefore widens it on the other, and nothing in the request
// itself says which engine will read it.
//
// So the engine has to be known before the filter is written. Detect answers
// that from the daemon's own GET /version: Podman reports a "Podman Engine"
// component (pkg/api/handlers/compat/version.go), dockerd reports "Engine"
// (daemon/info.go's SystemVersion).
package upstreamflavor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Flavor is the engine behind the upstream socket, as resolved from
// upstream.flavor and — for Auto — the startup probe.
type Flavor string

const (
	// Auto is the configured value that asks for the startup probe. It is
	// never a resolved result: Detect returns Docker or Podman or an error,
	// so no request path ever has to interpret "auto".
	Auto Flavor = "auto"
	// Docker is dockerd, or any engine that shares its conjunctive event
	// filter semantics. It is also the value a caller gets from the zero
	// Flavor, which is what keeps the pre-detection behavior intact for
	// every construction site that predates this package.
	Docker Flavor = "docker"
	// Podman is Podman's API service, whose event filter is disjunctive under
	// one key.
	Podman Flavor = "podman"
)

// ErrUnrecognized reports that the upstream answered GET /version but named
// no engine component this package knows. It is distinguished from a
// transport or status failure so an operator reading the startup error can
// tell "the daemon is not reachable" from "the daemon is reachable and is
// something else".
var ErrUnrecognized = errors.New("upstream flavor: unrecognized engine")

// ErrAmbiguous reports that the upstream's GET /version response named
// components matching both engines. Neither guess is safe to make silently
// — see classify — so this fails closed the same way ErrUnrecognized does,
// distinguished so an operator reading the startup error can tell "named
// nothing recognizable" from "named both".
var ErrAmbiguous = errors.New("upstream flavor: ambiguous engine")

// DetectTimeout bounds the whole probe: connect, request, and body read. The
// upstream has already passed its reachability check by the time the probe
// runs, and GET /version is the cheapest call either engine serves, so a
// probe that has not answered in this long is not going to.
const DetectTimeout = 5 * time.Second

// maxVersionBodyBytes caps the /version body sockguard will read. The real
// responses are well under a kilobyte; the limit exists so an upstream that
// streams forever cannot pin startup for DetectTimeout and then allocate.
const maxVersionBodyBytes = 1 << 20

// versionURL is the fixed side-channel URL every other upstream inspector in
// this codebase uses ("http://docker" + path); the host is a placeholder the
// shared RoundTripper discards in favor of its own endpoint routing.
const versionURL = "http://docker/version"

const (
	// dockerEngineComponent is the exact component name dockerd reports.
	dockerEngineComponent = "Engine"
	// podmanComponentMarker is matched as a case-insensitive substring rather
	// than against the exact "Podman Engine" literal. Substring matching can
	// only ever move the answer toward Podman, which is the fail-closed
	// direction here: reading Docker as Podman costs a refused /events, while
	// reading Podman as Docker reopens the disclosure this package exists to
	// close. No dockerd component name contains it ("Engine", "containerd",
	// "runc", "docker-init").
	podmanComponentMarker = "podman"
)

// Configured parses a configured upstream.flavor value. Surrounding
// whitespace is tolerated; casing is not, matching the existing enum style in
// internal/config (log.level, response.deny_verbosity, upstream.request_timeout's
// "off"). The empty string is rejected rather than treated as Auto: the Viper
// default already supplies "auto" for a config that omits the key, so an empty
// value can only come from an explicit `flavor:` with nothing after it, and
// silently reading that as "probe the daemon" hides a typo.
func Configured(value string) (Flavor, bool) {
	switch flavor := Flavor(strings.TrimSpace(value)); flavor {
	case Auto, Docker, Podman:
		return flavor, true
	default:
		return "", false
	}
}

// Detect probes GET /version through client and classifies the engine.
//
// Every failure mode — transport error, non-200, oversized or unparseable
// body, no recognized component — returns an error rather than a guess.
// There is no "probably Docker" answer, because the two possible guesses fail
// in opposite directions and neither is safe to make silently; the caller
// turns the error into a startup failure that names upstream.flavor.
func Detect(ctx context.Context, client *http.Client) (Flavor, error) {
	if client == nil {
		return "", errors.New("upstream flavor: no upstream client")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, versionURL, nil)
	if err != nil {
		return "", fmt.Errorf("upstream flavor: build GET /version: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("upstream flavor: GET /version: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("upstream flavor: GET /version returned HTTP %d", resp.StatusCode)
	}
	// Read one byte past the limit so at-limit and over-limit are
	// distinguishable, the same shape internal/ownership uses for request
	// bodies.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxVersionBodyBytes+1))
	if err != nil {
		return "", fmt.Errorf("upstream flavor: read /version response: %w", err)
	}
	if len(body) > maxVersionBodyBytes {
		return "", fmt.Errorf("upstream flavor: /version response exceeds %d bytes", maxVersionBodyBytes)
	}
	return classify(body)
}

// versionPayload is the only part of the /version response this package
// reads. Both engines populate Components; everything else in the document is
// ignored on purpose, so a schema change elsewhere cannot make the probe
// fail.
type versionPayload struct {
	Components []struct {
		Name string `json:"Name"`
	} `json:"Components"`
}

// classify maps a /version body onto a Flavor.
//
// Every component is scanned before deciding, rather than returning on the
// first hit, so the order components appear in never changes the answer. A
// response naming both engines is ambiguous rather than resolved to either
// one: silently picking Podman would refuse /events on what may be a real
// Docker deployment, and silently picking Docker would reopen the exact
// disclosure this package exists to close. Both guesses are wrong in a
// direction the operator can't see, so a dual match fails closed the same
// way naming neither engine does.
func classify(body []byte) (Flavor, error) {
	var payload versionPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("upstream flavor: decode /version response: %w", err)
	}
	podman, docker := false, false
	for _, component := range payload.Components {
		name := strings.TrimSpace(component.Name)
		if strings.Contains(strings.ToLower(name), podmanComponentMarker) {
			podman = true
		}
		if strings.EqualFold(name, dockerEngineComponent) {
			docker = true
		}
	}
	switch {
	case podman && docker:
		return "", fmt.Errorf("%w: GET /version named both a %q and a Podman component", ErrAmbiguous, dockerEngineComponent)
	case podman:
		return Podman, nil
	case docker:
		return Docker, nil
	default:
		return "", fmt.Errorf("%w: GET /version named no %q or Podman component", ErrUnrecognized, dockerEngineComponent)
	}
}
