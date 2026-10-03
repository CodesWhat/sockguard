package filter

import (
	"archive/tar"
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mustDecoyBuildContextTar builds a context whose default Dockerfile runs a
// command and whose decoy file does not, so an inspector that reads the
// Dockerfile name the engine does not use inspects the wrong file.
func mustDecoyBuildContextTar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, file := range []struct{ name, body string }{
		{name: "Dockerfile", body: "FROM busybox\nRUN id\n"},
		{name: "decoy", body: "FROM busybox\nCOPY . /app\n"},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: file.name, Mode: 0o644, Size: int64(len(file.body))}); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write([]byte(file.body)); err != nil {
			t.Fatalf("write tar body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

// TestPolicyQueryReadsRefuseAmbiguousParameters covers every query read a
// policy decision depends on, on routes a Podman upstream decodes with
// gorilla/schema (case-folded key, last value) and dockerd reads by exact key
// and first value. A parameter repeated under any spelling, or sent in any
// spelling but the documented one, is refused as ambiguous whenever the check
// that reads it is enabled. Each read also has a positive control: the shape
// the Docker CLI, the SDKs and Podman's bindings send, once and spelled as
// documented, still passes.
func TestPolicyQueryReadsRefuseAmbiguousParameters(t *testing.T) {
	type inspectFunc func(r *http.Request) (string, error)
	via := func(inspect func(*slog.Logger, *http.Request, string) (string, error)) inspectFunc {
		return func(r *http.Request) (string, error) {
			return inspect(nil, r, NormalizePath(r.URL.Path))
		}
	}

	secret := newLibpodSecretPolicy(SecretOptions{})
	remove := newContainerRemovePolicy(ContainerRemoveOptions{})
	removeOpen := newContainerRemovePolicy(ContainerRemoveOptions{AllowForce: true, AllowRemoveVolumes: true, AllowRemoveLinks: true})
	build := newBuildPolicy(BuildOptions{})
	buildAck := newBuildPolicy(BuildOptions{AllowBlindWrites: true})
	pull := newImagePullPolicy(ImagePullOptions{AllowedRegistries: []string{"ghcr.io"}})
	pullAll := newImagePullPolicy(ImagePullOptions{AllowAllRegistries: true, AllowImports: true})
	archive := newContainerArchivePolicy(ContainerArchiveOptions{AllowedPaths: []string{"/app"}})

	benignBuild := mustBuildContextTar(t, "Dockerfile", "FROM busybox\nCOPY . /app\n")
	decoyBuild := mustDecoyBuildContextTar(t)
	archiveBody := mustContainerArchiveTar(t, containerArchiveTestEntry{name: "file.txt", body: "ok"})

	tests := []struct {
		name       string
		method     string
		target     string
		body       []byte
		inspect    inspectFunc
		wantReason string
	}{
		// POST /libpod/secrets/create, `driver`.
		{name: "secret driver in another spelling", method: http.MethodPost, target: "/libpod/secrets/create?name=s&Driver=shell", inspect: via(secret.inspect), wantReason: "ambiguous driver query parameter"},
		{name: "secret driver behind an empty first value", method: http.MethodPost, target: "/libpod/secrets/create?name=s&driver=&driver=shell", inspect: via(secret.inspect), wantReason: "ambiguous driver query parameter"},
		{name: "secret driver in two spellings", method: http.MethodPost, target: "/v5.0.0/libpod/secrets/create?driver=&DRIVER=pass", inspect: via(secret.inspect), wantReason: "ambiguous driver query parameter"},
		{name: "percent-encoded secret driver spelling", method: http.MethodPost, target: "/libpod/secrets/create?name=s&%44river=shell", inspect: via(secret.inspect), wantReason: "ambiguous driver query parameter"},
		{name: "secret custom driver", method: http.MethodPost, target: "/libpod/secrets/create?name=s&driver=shell", inspect: via(secret.inspect), wantReason: `driver "shell" is not allowed`},
		{name: "secret default driver", method: http.MethodPost, target: "/libpod/secrets/create?name=s", inspect: via(secret.inspect)},
		{name: "secret empty driver", method: http.MethodPost, target: "/libpod/secrets/create?name=s&driver=", inspect: via(secret.inspect)},

		// DELETE /containers/{id}, `force`, `v`, `link`.
		{name: "remove force in another spelling", method: http.MethodDelete, target: "/containers/app?Force=1", inspect: via(remove.inspect), wantReason: "ambiguous force query parameter"},
		{name: "remove force behind a false first value", method: http.MethodDelete, target: "/v1.41/containers/app?force=0&force=1", inspect: via(remove.inspect), wantReason: "ambiguous force query parameter"},
		{name: "percent-encoded remove force spelling", method: http.MethodDelete, target: "/containers/app?%46orce=1", inspect: via(remove.inspect), wantReason: "ambiguous force query parameter"},
		{name: "remove volumes in another spelling", method: http.MethodDelete, target: "/containers/app?V=1", inspect: via(remove.inspect), wantReason: "ambiguous v query parameter"},
		{name: "remove volumes behind a false first value", method: http.MethodDelete, target: "/containers/app?v=false&v=true", inspect: via(remove.inspect), wantReason: "ambiguous v query parameter"},
		{name: "remove link in another spelling", method: http.MethodDelete, target: "/containers/app?LINK=1", inspect: via(remove.inspect), wantReason: "ambiguous link query parameter"},
		{name: "remove link spelled with a Kelvin sign", method: http.MethodDelete, target: "/containers/app?lin%E2%84%AA=1", inspect: via(remove.inspect), wantReason: "ambiguous link query parameter"},
		{name: "remove force", method: http.MethodDelete, target: "/containers/app?force=1", inspect: via(remove.inspect), wantReason: "force removal is not allowed"},
		{name: "plain remove", method: http.MethodDelete, target: "/containers/app", inspect: via(remove.inspect)},
		{name: "remove with every flag false", method: http.MethodDelete, target: "/containers/app?v=False&link=False&force=False", inspect: via(remove.inspect)},
		{name: "repeated force with the gate open", method: http.MethodDelete, target: "/containers/app?force=0&Force=1", inspect: via(removeOpen.inspect)},

		// DELETE /libpod/containers/{id}, `force`, `volumes`, `v`, `depend`.
		{name: "libpod remove force in another spelling", method: http.MethodDelete, target: "/v5.0.0/libpod/containers/app?Force=1", inspect: via(remove.inspect), wantReason: "ambiguous force query parameter"},
		{name: "libpod remove volumes behind a false first value", method: http.MethodDelete, target: "/v5.0.0/libpod/containers/app?volumes=false&volumes=true", inspect: via(remove.inspect), wantReason: "ambiguous volumes query parameter"},
		{name: "libpod remove volumes in another spelling", method: http.MethodDelete, target: "/v5.0.0/libpod/containers/app?VOLUMES=true", inspect: via(remove.inspect), wantReason: "ambiguous volumes query parameter"},
		{name: "libpod remove depend in two spellings", method: http.MethodDelete, target: "/v5.0.0/libpod/containers/app?depend=false&Depend=true", inspect: via(remove.inspect), wantReason: "ambiguous depend query parameter"},
		{name: "libpod remove force", method: http.MethodDelete, target: "/v5.0.0/libpod/containers/app?force=true", inspect: via(remove.inspect), wantReason: "force removal is not allowed"},
		{name: "podman-remote rm shape", method: http.MethodDelete, target: "/v5.8.6/libpod/containers/app?depend=false&force=false&ignore=false&volumes=false", inspect: via(remove.inspect)},
		{name: "repeated libpod volumes with the gates open", method: http.MethodDelete, target: "/v5.0.0/libpod/containers/app?volumes=0&Volumes=1&depend=1", inspect: via(removeOpen.inspect)},

		// POST /build and POST /libpod/build.
		{name: "libpod build Dockerfile in another spelling", method: http.MethodPost, target: "/libpod/build?Dockerfile=decoy", body: decoyBuild, inspect: via(build.inspect), wantReason: "ambiguous dockerfile query parameter"},
		{name: "libpod build Dockerfile in two spellings", method: http.MethodPost, target: "/libpod/build?dockerfile=Dockerfile&Dockerfile=decoy", body: decoyBuild, inspect: via(build.inspect), wantReason: "ambiguous dockerfile query parameter"},
		{name: "compat build repeated Dockerfile", method: http.MethodPost, target: "/build?dockerfile=decoy&dockerfile=Dockerfile", body: decoyBuild, inspect: via(build.inspect), wantReason: "ambiguous dockerfile query parameter"},
		{name: "compat build rusagelogfile with a long s", method: http.MethodPost, target: "/build?rusage=1&ru%C5%BFagelogfile=%2Fetc%2Fcron.d%2Fx", body: benignBuild, inspect: via(build.inspect), wantReason: "ambiguous rusagelogfile query parameter"},
		{name: "libpod build rusagelogfile with a long s", method: http.MethodPost, target: "/libpod/build?ru%C5%BFagelogfile=%2Fetc%2Fcron.d%2Fx", body: benignBuild, inspect: via(build.inspect), wantReason: "ambiguous rusagelogfile query parameter"},
		{name: "build host network in another spelling", method: http.MethodPost, target: "/build?networkmode=bridge&NetworkMode=host", body: benignBuild, inspect: via(build.inspect), wantReason: "ambiguous networkmode query parameter"},
		{name: "build remote in another spelling", method: http.MethodPost, target: "/build?Remote=https%3A%2F%2Fexample.com%2Fc.tar", body: benignBuild, inspect: via(build.inspect), wantReason: "ambiguous remote query parameter"},
		{name: "build volume in two spellings", method: http.MethodPost, target: "/libpod/build?volume=%2Fa%3A%2Fb&Volume=%2Fc%3A%2Fd", body: benignBuild, inspect: via(build.inspect), wantReason: "host volume mounts"},
		{name: "build volumes spelled with a long s", method: http.MethodPost, target: "/build?volume%C5%BF=%2F%3A%2Fhost", body: benignBuild, inspect: via(build.inspect), wantReason: "host volume mounts"},
		{name: "build additional contexts in another spelling", method: http.MethodPost, target: "/libpod/build?AdditionalBuildContexts=x%3Dimage%3Aalpine", body: benignBuild, inspect: via(build.inspect), wantReason: "ambiguous additionalbuildcontexts query parameter"},
		{name: "compat build decoy Dockerfile read exactly", method: http.MethodPost, target: "/build?dockerfile=decoy", body: decoyBuild, inspect: via(build.inspect)},
		{name: "libpod build default Dockerfile with RUN", method: http.MethodPost, target: "/libpod/build", body: decoyBuild, inspect: via(build.inspect), wantReason: "RUN instructions are not allowed"},
		{name: "Docker CLI build shape", method: http.MethodPost, target: "/v1.45/build?t=a%3A1&t=b%3A1&dockerfile=Dockerfile&networkmode=bridge&labels=%7B%7D", body: benignBuild, inspect: via(build.inspect)},
		{name: "Podman bindings repeated volume with blind writes", method: http.MethodPost, target: "/libpod/build?volume=%2Fa%3A%2Fb&volume=%2Fc%3A%2Fd&rusage=1&rusagelogfile=%2Ftmp%2Fr", body: benignBuild, inspect: via(buildAck.inspect)},
		{name: "repeated volume spellings with blind writes", method: http.MethodPost, target: "/libpod/build?volume=%2Fa%3A%2Fb&Volume=%2Fc%3A%2Fd", body: benignBuild, inspect: via(buildAck.inspect)},

		// POST /images/create, `fromImage`, `fromSrc`.
		{name: "pull fromImage in another spelling", method: http.MethodPost, target: "/images/create?FromImage=ghcr.io%2Forg%2Fapp", inspect: via(pull.inspect), wantReason: "ambiguous fromImage query parameter"},
		{name: "pull repeated allowlisted fromImage", method: http.MethodPost, target: "/images/create?fromImage=ghcr.io%2Fa&fromImage=ghcr.io%2Fb", inspect: via(pull.inspect), wantReason: "ambiguous fromImage query parameter"},
		{name: "import source behind an empty first value", method: http.MethodPost, target: "/images/create?fromSrc=&fromSrc=http%3A%2F%2Fevil.example%2Fr.tar", inspect: via(pull.inspect), wantReason: "ambiguous fromSrc query parameter"},
		{name: "pull outside the allowlist", method: http.MethodPost, target: "/images/create?fromImage=evil.example%2Fx", inspect: via(pull.inspect), wantReason: "is not allowlisted"},
		{name: "Docker CLI pull shape", method: http.MethodPost, target: "/images/create?fromImage=ghcr.io%2Forg%2Fapp&tag=v1&platform=linux%2Famd64", inspect: via(pull.inspect)},
		{name: "repeated fromImage with every registry and imports allowed", method: http.MethodPost, target: "/images/create?fromImage=a&FromImage=b&fromSrc=-&fromSrc=x", inspect: via(pullAll.inspect)},

		// POST /libpod/images/pull, `reference`.
		{name: "libpod pull reference in another spelling", method: http.MethodPost, target: "/libpod/images/pull?Reference=ghcr.io%2Forg%2Fapp", inspect: via(pull.inspectLibpod), wantReason: "ambiguous reference query parameter"},
		{name: "libpod pull repeated allowlisted reference", method: http.MethodPost, target: "/libpod/images/pull?reference=ghcr.io%2Fa&reference=ghcr.io%2Fb", inspect: via(pull.inspectLibpod), wantReason: "ambiguous reference query parameter"},
		{name: "Podman bindings pull shape", method: http.MethodPost, target: "/v5.0.0/libpod/images/pull?reference=docker%3A%2F%2Fghcr.io%2Forg%2Fapp&tlsVerify=true&quiet=true", inspect: via(pull.inspectLibpod)},

		// PUT /containers/{id}/archive, `path`.
		{name: "archive path in another spelling", method: http.MethodPut, target: "/containers/app/archive?Path=%2Fapp", body: archiveBody, inspect: via(archive.inspect), wantReason: "ambiguous path query parameter"},
		{name: "archive path spelled as documented", method: http.MethodPut, target: "/libpod/containers/app/archive?path=%2Fapp&pause=true", body: archiveBody, inspect: via(archive.inspect)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.target, nil)
			if tt.body != nil {
				req = httptest.NewRequest(tt.method, tt.target, bytes.NewReader(tt.body))
			}
			reason, err := tt.inspect(req)
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if tt.wantReason == "" {
				if reason != "" {
					t.Fatalf("inspect(%s) denied with %q, want allow", tt.target, reason)
				}
				return
			}
			if !strings.Contains(reason, tt.wantReason) {
				t.Fatalf("inspect(%s) = %q, want a denial containing %q", tt.target, reason, tt.wantReason)
			}
		})
	}
}
