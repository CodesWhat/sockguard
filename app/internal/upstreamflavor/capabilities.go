package upstreamflavor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Capabilities records engine identity and positively verified filter semantics.
// The zero volume capability keeps unknown Podman releases restricted.
type Capabilities struct {
	Flavor                         Flavor
	PodmanConjunctiveVolumeFilters bool
}

// Probe reads identity from /version and the Libpod product in Server headers.
// A positive Podman identity survives an error so an explicit Docker override
// cannot hide it. Errors never grant a volume-filter capability.
func Probe(ctx context.Context, client *http.Client) (Capabilities, error) {
	observed := Capabilities{}
	if client == nil {
		return observed, errors.New("upstream flavor: no upstream client")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, versionURL, nil)
	if err != nil {
		return observed, fmt.Errorf("upstream flavor: build GET /version: %w", err)
	}
	probeClient := *client
	probeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := probeClient.Do(req)
	if err != nil {
		return observed, fmt.Errorf("upstream flavor: GET /version: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	versions := podmanHeaderVersions(resp.Header.Values("Server"))
	if len(versions) > 0 {
		observed.Flavor = Podman
	}
	if resp.StatusCode != http.StatusOK {
		return observed, fmt.Errorf("upstream flavor: GET /version returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxVersionBodyBytes+1))
	if err != nil {
		return observed, fmt.Errorf("upstream flavor: read /version response: %w", err)
	}
	if len(body) > maxVersionBodyBytes {
		return observed, fmt.Errorf("upstream flavor: /version response exceeds %d bytes", maxVersionBodyBytes)
	}
	var payload versionPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return observed, fmt.Errorf("upstream flavor: decode /version response: %w", err)
	}
	for _, component := range payload.Components {
		if strings.Contains(strings.ToLower(strings.TrimSpace(component.Name)), podmanComponentMarker) {
			observed.Flavor = Podman
			versions = append(versions, component.Version)
		}
	}
	flavor, err := classifyPayload(payload)
	if observed.Flavor == Podman {
		if flavor == Docker {
			return observed, fmt.Errorf("%w: Libpod Server header contradicts Docker Engine component", ErrAmbiguous)
		}
		if err != nil && !errors.Is(err, ErrUnrecognized) {
			return observed, err
		}
		observed.PodmanConjunctiveVolumeFilters = len(versions) > 0
		for _, version := range versions {
			observed.PodmanConjunctiveVolumeFilters = observed.PodmanConjunctiveVolumeFilters && releasedPodmanSixOrNewer(version)
		}
		return observed, nil
	}
	observed.Flavor = flavor
	return observed, err
}

func podmanHeaderVersions(headers []string) []string {
	var versions []string
	for _, header := range headers {
		for _, product := range strings.Fields(header) {
			if strings.HasPrefix(strings.ToLower(product), "libpod/") {
				versions = append(versions, strings.TrimRight(product[len("Libpod/"):], ",;"))
			}
		}
	}
	return versions
}

var releasedPodmanVersion = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

func releasedPodmanSixOrNewer(version string) bool {
	match := releasedPodmanVersion.FindStringSubmatch(strings.TrimSpace(version))
	if match == nil {
		return false
	}
	major, err := strconv.ParseUint(match[1], 10, 64)
	return err == nil && major >= 6
}
