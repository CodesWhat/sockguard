package filter_test

import (
	"bytes"
	"io"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/config"
	"github.com/codeswhat/sockguard/v2/app/internal/responsefilter"
)

// portainerInspectBody is a daemon-shaped GET /containers/{id}/json body with
// the fields Portainer Recreate replays: Config.Env, HostConfig.Binds and
// NetworkMode, and Networks[*].NetworkID/IPAddress (NetworkDisconnect uses the
// NetworkID, ContainerCreate gets Config and HostConfig back verbatim).
const portainerInspectBody = `{"Id":"abc123","Name":"/web","Image":"sha256:deadbeef",` +
	`"Config":{"Image":"nginx:1","Env":["DB_PASSWORD=hunter2","PATH=/usr/bin"]},` +
	`"HostConfig":{"Binds":["/srv/data:/data:rw"],"NetworkMode":"bridge",` +
	`"Mounts":[{"Type":"bind","Source":"/srv/cfg","Target":"/cfg"}]},` +
	`"NetworkSettings":{"Networks":{"bridge":{"NetworkID":"4f1c2a9d8b7e","EndpointID":"9e8d7c6b5a4f",` +
	`"IPAddress":"172.17.0.2","Gateway":"172.17.0.1","MacAddress":"02:42:ac:11:00:02"}}}}`

// TestPortainerPresetPassesInspectOutputThroughUnmodified pins that the
// shipped preset does not redact container inspect output. Portainer Recreate
// replays that output into container create, so placeholders or empty values
// would be written into the recreated container.
func TestPortainerPresetPassesInspectOutputThroughUnmodified(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "portainer.yaml"))
	if err != nil {
		t.Fatalf("Load(portainer.yaml): %v", err)
	}

	rf := responsefilter.New(responsefilter.Options{
		RedactContainerEnv:         cfg.Response.RedactContainerEnv,
		RedactMountPaths:           cfg.Response.RedactMountPaths,
		RedactNetworkTopology:      cfg.Response.RedactNetworkTopology,
		RedactSensitiveData:        cfg.Response.RedactSensitiveData,
		RedactHostTopology:         cfg.Response.RedactHostTopology,
		AllowAttestationStatements: cfg.Response.AllowAttestationStatements,
	})

	req, err := http.NewRequest(http.MethodGet, "http://sockguard.test/v1.45/containers/abc123/json", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader([]byte(portainerInspectBody))),
		ContentLength: int64(len(portainerInspectBody)),
		Request:       req,
	}
	if err := rf.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse: %v", err)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(got) != portainerInspectBody {
		t.Fatalf("inspect body changed by portainer preset:\n got: %s\nwant: %s", got, portainerInspectBody)
	}
}
