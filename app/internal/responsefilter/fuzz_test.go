package responsefilter

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"testing"
)

const maxResponseFuzzBytes = 16 << 10

func FuzzFilterModifyResponse(f *testing.F) {
	f.Add("/v1.53/containers/abc123/json", []byte(`{"Config":{"Env":["A=B"]},"HostConfig":{"Binds":["/srv/secrets:/run/secrets:ro"]},"Mounts":[{"Source":"/srv/secrets"}],"NetworkSettings":{"IPAddress":"172.18.0.5"}}`))
	f.Add("/v1.53/containers/json", []byte(`[{"Mounts":[{"Source":"/srv/secrets"}],"NetworkSettings":{"Networks":{"default":{"IPAddress":"172.18.0.5","NetworkID":"network-123"}}}}]`))
	f.Add("/v1.53/networks/net-123", []byte(`{"IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]},"Containers":{"abc":{"IPv4Address":"172.18.0.5/16"}},"Peers":[{"IP":"10.0.0.2"}]}`))
	f.Add("/v1.53/volumes", []byte(`{"Volumes":[{"Mountpoint":"/var/lib/docker/volumes/cache/_data"}]}`))
	f.Add("/v1.53/containers/abc123/json", []byte(`{"Config":`))
	f.Add("/_ping", []byte("not-json"))

	filter := New(Options{
		RedactContainerEnv:    true,
		RedactMountPaths:      true,
		RedactNetworkTopology: true,
	})

	f.Fuzz(func(t *testing.T, path string, body []byte) {
		body = truncateResponseFuzzBytes(body, maxResponseFuzzBytes)

		resp := &http.Response{
			StatusCode:    http.StatusOK,
			Header:        make(http.Header),
			Body:          io.NopCloser(bytes.NewReader(body)),
			ContentLength: int64(len(body)),
			Request: &http.Request{
				Method: http.MethodGet,
				URL:    &url.URL{Path: path},
			},
		}

		_ = filter.ModifyResponse(resp)

		if resp.Body != nil {
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
	})
}

func truncateResponseFuzzBytes(body []byte, max int) []byte {
	if len(body) > max {
		return body[:max]
	}
	return body
}
