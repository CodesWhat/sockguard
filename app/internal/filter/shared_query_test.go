package filter

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/logging"
)

// withSharedQueryMeta attaches the per-request state the serve chain attaches,
// which is what lets the query-reading inspectors share one parse.
func withSharedQueryMeta(r *http.Request) *http.Request {
	return r.WithContext(logging.WithMeta(r.Context(), &logging.RequestMeta{}))
}

func newSharedQueryRequest(method, target string, body []byte, shared bool) *http.Request {
	var r *http.Request
	if len(body) == 0 {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, bytes.NewReader(body))
	}
	if shared {
		r = withSharedQueryMeta(r)
	}
	return r
}

// TestSwarmUpdateQueryReadsShareOneParse pins the largest per-request repeat in
// this package: swarmPolicy.inspect reads three separate rotate* flags off the
// query of a single POST /swarm/update, and each read used to re-parse it.
func TestSwarmUpdateQueryReadsShareOneParse(t *testing.T) {
	r := withSharedQueryMeta(httptest.NewRequest(http.MethodPost,
		"/swarm/update?version=11&rotateWorkerToken=1&rotateManagerToken=true&rotateManagerUnlockKey=0", nil))

	// Warm the memo so the measured runs cover only the repeats.
	_ = dockerBoolValue(r, "rotateWorkerToken")

	allocs := testing.AllocsPerRun(50, func() {
		_ = dockerBoolValue(r, "rotateWorkerToken")
		_ = dockerBoolValue(r, "rotateManagerToken")
		_ = dockerBoolValue(r, "rotateManagerUnlockKey")
	})
	if allocs != 0 {
		t.Fatalf("three rotate* query reads allocated %v times, want 0 (one shared parse)", allocs)
	}
}

// TestServiceGuardQueryReadsShareOneParse covers the resource-limit guard,
// which reads ?version= and ?rollback= off the same POST /services/{id}/update.
func TestServiceGuardQueryReadsShareOneParse(t *testing.T) {
	r := withSharedQueryMeta(httptest.NewRequest(http.MethodPost,
		"/services/svc1/update?version=42&rollback=previous&registryAuthFrom=spec", nil))

	_, _ = serviceVersionQuery(r)

	allocs := testing.AllocsPerRun(50, func() {
		_, _ = serviceVersionQuery(r)
		_, _ = serviceManualRollbackQuery(r)
	})
	if allocs != 0 {
		t.Fatalf("version+rollback query reads allocated %v times, want 0 (one shared parse)", allocs)
	}
}

// TestSharedQueryInspectorsDecideIdentically is the guard that matters most:
// routing every query-reading inspector through the shared parse must not move
// a single allow/deny decision. Each case runs the same request twice — once
// with the per-request state attached (memo live) and once without it (plain
// url.URL.Query()) — and requires the two verdicts to agree.
func TestSharedQueryInspectorsDecideIdentically(t *testing.T) {
	imagePull := newImagePullPolicy(ImagePullOptions{AllowedRegistries: []string{"ghcr.io"}})
	build := newBuildPolicy(BuildOptions{AllowRunInstructions: true})
	archive := newContainerArchivePolicy(ContainerArchiveOptions{AllowedPaths: []string{"/data"}})
	remove := newContainerRemovePolicy(ContainerRemoveOptions{})
	swarm := newSwarmPolicy(SwarmOptions{})
	plugin := newPluginPolicy(PluginOptions{AllowedRegistries: []string{"ghcr.io"}})
	libpodSecret := newLibpodSecretPolicy(SecretOptions{})
	containerUpdate := newContainerUpdatePolicy(ContainerUpdateOptions{})

	cases := []struct {
		name    string
		method  string
		target  string
		body    []byte
		inspect inspectorFunc
		// want pins the verdict itself, so a change that moved both the
		// shared and unshared paths together still fails here.
		want    string
		wantErr bool
	}{
		{"image_pull_allowed", http.MethodPost, "/images/create?fromImage=ghcr.io/org/app&tag=v1", nil, imagePull.inspect, "", false},
		{"image_pull_denied_registry", http.MethodPost, "/images/create?fromImage=evil.example.com/app&tag=v1", nil, imagePull.inspect, `image pull denied: registry "evil.example.com" is not allowlisted`, false},
		{"image_pull_denied_import", http.MethodPost, "/images/create?fromSrc=http://evil.example.com/x.tar", nil, imagePull.inspect, `image pull denied: importing images from "http://evil.example.com/x.tar" is not allowed`, false},
		{"libpod_image_pull_folded_key", http.MethodPost, "/libpod/images/pull?Reference=docker%3A%2F%2Fghcr.io%2Forg%2Fapp", nil, imagePull.inspectLibpod, "", false},
		{"libpod_image_import_denied", http.MethodPost, "/libpod/images/import?url=http%3A%2F%2Fevil.example.com%2Fx.tar", nil, imagePull.inspectLibpodImport, `libpod image import denied: importing images from "http://evil.example.com/x.tar" is not allowed`, false},
		{"build_remote_context_denied", http.MethodPost, "/build?t=app%3Alatest&dockerfile=Dockerfile&remote=https%3A%2F%2Fgit.example.com%2Fr.git&nocache=1", nil, build.inspect, `build denied: remote build context "https://git.example.com/r.git" is not allowed`, false},
		{"build_host_network_denied", http.MethodPost, "/build?t=app%3Alatest&networkmode=host&dockerfile=Dockerfile", nil, build.inspect, "build denied: host network mode is not allowed", false},
		{"container_archive_missing_path", http.MethodPut, "/containers/abc/archive", []byte("tar"), archive.inspect, "container archive denied: target path is required", false},
		{"container_archive_rename_denied", http.MethodPut, "/containers/abc/archive?path=%2Fdata&rename=%7B%7D", []byte("tar"), archive.inspect, "container archive denied: rename query is not allowed", false},
		{"container_remove_force_denied", http.MethodDelete, "/containers/abc?force=1&v=1", nil, remove.inspect, "container remove denied: force removal is not allowed", false},
		{"container_remove_malformed_query", http.MethodDelete, "/containers/abc?force=%zz", nil, remove.inspect, "", true},
		{"swarm_update_rotation_denied", http.MethodPost, "/swarm/update?version=11&rotateManagerToken=2", []byte(`{}`), swarm.inspect, "swarm update denied: manager token rotation is not allowed", false},
		{"plugin_pull_denied_registry", http.MethodPost, "/plugins/pull?remote=evil.example.com/net:latest", nil, plugin.inspect, `plugin pull denied: registry "evil.example.com" is not allowlisted`, false},
		{"plugin_upgrade_allowed_registry", http.MethodPost, "/plugins/abc/upgrade?remote=ghcr.io/org/net:latest", nil, plugin.inspect, "", false},
		{"libpod_secret_custom_driver_denied", http.MethodPost, "/libpod/secrets/create?driver=shell-driver&name=s1", []byte(`"c2VjcmV0"`), libpodSecret.inspect, `libpod secret create denied: driver "shell-driver" is not allowed`, false},
		{"libpod_container_update_restart_query", http.MethodPost, "/libpod/containers/abc/update?restartPolicy=always", []byte(`{}`), containerUpdate.inspectLibpod, "libpod container update denied: restart policy changes are not allowed (restartpolicy)", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plainReq := newSharedQueryRequest(tc.method, tc.target, tc.body, false)
			plainReason, plainErr := tc.inspect(slog.New(slog.DiscardHandler), plainReq, NormalizePath(plainReq.URL.Path))

			sharedReq := newSharedQueryRequest(tc.method, tc.target, tc.body, true)
			sharedReason, sharedErr := tc.inspect(slog.New(slog.DiscardHandler), sharedReq, NormalizePath(sharedReq.URL.Path))

			if sharedReason != plainReason {
				t.Fatalf("denyReason with the shared parse = %q, want the unshared %q", sharedReason, plainReason)
			}
			if (sharedErr == nil) != (plainErr == nil) {
				t.Fatalf("err with the shared parse = %v, want the unshared %v", sharedErr, plainErr)
			}
			if sharedReason != tc.want {
				t.Fatalf("denyReason = %q, want %q", sharedReason, tc.want)
			}
			if (sharedErr != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", sharedErr, tc.wantErr)
			}

			// Read-only half of the contract: every inspector on this
			// request reads the same url.Values, so one of them writing
			// to it would change what the next one sees.
			want, _ := url.ParseQuery(sharedReq.URL.RawQuery)
			if got := logging.RequestQuery(sharedReq); !reflect.DeepEqual(got, want) {
				t.Fatalf("shared query after inspection = %v, want the unmodified %v", got, want)
			}
		})
	}
}
