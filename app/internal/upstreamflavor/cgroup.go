package upstreamflavor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// maxInfoBodyBytes caps the /info body ProbeCgroupVersion will read. Real
// responses run to tens of kilobytes; the limit stops a hostile or broken
// upstream from streaming into memory.
const maxInfoBodyBytes = 4 << 20

const infoURL = "http://docker/info"

// ProbeCgroupVersion reads CgroupVersion from GET /info. It returns "1" or
// "2" as the daemon reports them, and an error for anything else, so a caller
// that only grants on "1" fails closed when the version is unknown. An empty
// CgroupVersion is an error: dockerd omits the field only when it cannot
// tell, and an older daemon that predates the field is cgroup v1 only in
// practice but says nothing, which this package does not guess at.
func ProbeCgroupVersion(ctx context.Context, client *http.Client) (string, error) {
	if client == nil {
		return "", errors.New("upstream cgroup version: no upstream client")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, infoURL, nil)
	if err != nil {
		return "", fmt.Errorf("upstream cgroup version: build GET /info: %w", err)
	}
	probeClient := *client
	probeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := probeClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("upstream cgroup version: GET /info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("upstream cgroup version: GET /info returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxInfoBodyBytes+1))
	if err != nil {
		return "", fmt.Errorf("upstream cgroup version: read /info response: %w", err)
	}
	if len(body) > maxInfoBodyBytes {
		return "", fmt.Errorf("upstream cgroup version: /info response exceeds %d bytes", maxInfoBodyBytes)
	}
	var payload struct {
		CgroupVersion json.RawMessage `json:"CgroupVersion"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("upstream cgroup version: decode /info response: %w", err)
	}
	var version string
	if err := json.Unmarshal(payload.CgroupVersion, &version); err != nil {
		return "", errors.New("upstream cgroup version: /info carries no string CgroupVersion")
	}
	switch version {
	case "1", "2":
		return version, nil
	default:
		return "", fmt.Errorf("upstream cgroup version: /info reported unrecognized CgroupVersion %q", version)
	}
}
