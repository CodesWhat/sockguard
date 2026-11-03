package filter_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/responsefilter"
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

	got := filterInspectBody(t, responsefilter.Options{
		RedactContainerEnv:         cfg.Response.RedactContainerEnv,
		RedactMountPaths:           cfg.Response.RedactMountPaths,
		RedactNetworkTopology:      cfg.Response.RedactNetworkTopology,
		RedactSensitiveData:        cfg.Response.RedactSensitiveData,
		RedactHostTopology:         cfg.Response.RedactHostTopology,
		AllowAttestationStatements: cfg.Response.AllowAttestationStatements,
	})
	if !sameJSON(t, got, []byte(portainerInspectBody)) {
		t.Fatalf("inspect body changed by portainer preset:\n got: %s\nwant: %s", got, portainerInspectBody)
	}
}

// TestDefaultRedactionRewritesPortainerInspectBody is the negative control for
// the pass-through test above: the same body through the default redaction
// settings must change, so the pass-through assertion cannot hold vacuously.
func TestDefaultRedactionRewritesPortainerInspectBody(t *testing.T) {
	def := config.Defaults()
	got := filterInspectBody(t, responsefilter.Options{
		RedactContainerEnv:         def.Response.RedactContainerEnv,
		RedactMountPaths:           def.Response.RedactMountPaths,
		RedactNetworkTopology:      def.Response.RedactNetworkTopology,
		RedactSensitiveData:        def.Response.RedactSensitiveData,
		RedactHostTopology:         def.Response.RedactHostTopology,
		AllowAttestationStatements: def.Response.AllowAttestationStatements,
	})
	if sameJSON(t, got, []byte(portainerInspectBody)) {
		t.Fatalf("default redaction left the inspect body unchanged: %s", got)
	}
}

// sameJSON compares decoded values: the filter re-encodes bodies it inspects,
// so key order can differ even when no field changed.
func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		t.Fatalf("decode got: %v", err)
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		t.Fatalf("decode want: %v", err)
	}
	return reflect.DeepEqual(av, bv)
}

func filterInspectBody(t *testing.T, opts responsefilter.Options) []byte {
	t.Helper()
	rf := responsefilter.New(opts)
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
	return got
}
