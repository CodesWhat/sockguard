package filter

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

const maxParserFuzzBytes = maxExecBodyBytes + 1024

func FuzzBuild(f *testing.F) {
	f.Add("", "application/x-tar", mustBuildContextTarSeed(f, "Dockerfile", "FROM busybox\nCOPY . /app\n"))
	f.Add("", "application/x-tar", mustBuildContextTarSeed(f, "Dockerfile", "FROM busybox\nRUN id\n"))
	f.Add("", "application/gzip", mustBuildContextGzipTarSeed(f, "Dockerfile", "FROM busybox\nCOPY . /app\n"))
	f.Add("remote=https%3A%2F%2Fgithub.com%2Facme%2Fapp.git", "", []byte("ignored"))
	f.Add("networkmode=host", "application/x-tar", mustBuildContextTarSeed(f, "Dockerfile", "FROM busybox\nCOPY . /app\n"))
	f.Add("", "text/plain", []byte("FROM busybox\nCOPY . /app\n"))
	f.Add("", "application/octet-stream", []byte("not-a-tar"))

	policy := newBuildPolicy(BuildOptions{})

	f.Fuzz(func(t *testing.T, rawQuery, contentType string, body []byte) {
		body = truncateParserFuzzBytes(body, maxParserFuzzBytes)

		fuzzVerdictOracle(t, "build", body, func(b []byte) (string, error) {
			req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(b))
			req.URL = &url.URL{Path: "/build", RawQuery: rawQuery}
			if contentType != "" {
				req.Header.Set("Content-Type", contentType)
			}
			defer func() {
				if req.Body != nil {
					_, _ = io.Copy(io.Discard, req.Body)
					_ = req.Body.Close()
				}
			}()
			return policy.inspect(nil, req, "/build")
		})
	})
}

func FuzzClassifyPodmanAdditionalBuildContexts(f *testing.F) {
	f.Add("docs=url:https://example.com/docs.tar")
	f.Add(`{"docs":{"IsURL":true,"Value":"https://example.com/docs.tar"}}`)
	f.Add("docs=localpath:/srv/docs")
	f.Add("docs=image:docker.io/library/alpine:3.22")
	f.Add("docs=unsupported:value")

	f.Fuzz(func(t *testing.T, value string) {
		remote, blind, malformed := classifyPodmanAdditionalBuildContexts([]string{value})
		if malformed != "" && (remote || blind) {
			t.Fatalf("malformed %q also reported remote=%v blind=%v", malformed, remote, blind)
		}
	})
}

func FuzzContainerCreate(f *testing.F) {
	f.Add([]byte(`{"Image":"busybox:1.37","HostConfig":{"Privileged":true}}`))
	f.Add([]byte(`{"Image":"busybox:1.37","HostConfig":{"NetworkMode":"host"}}`))
	f.Add([]byte(`{"Image":"busybox:1.37","HostConfig":{"Binds":["/srv/unsafe:/data:rw"],"Mounts":[{"Type":"bind","Source":"/srv/also-unsafe","Target":"/config"}]}}`))
	f.Add([]byte(`{"Image":"busybox:1.37","HostConfig":{"Binds":["/srv/sockguard/data:/data:rw","named-cache:/cache"],"Mounts":[{"Type":"bind","Source":"/srv/sockguard/config","Target":"/config"},{"Type":"volume","Source":"build-cache","Target":"/var/cache"}]}}`))
	f.Add([]byte(`{"HostConfig":`))
	f.Add(bytes.Repeat([]byte("a"), maxContainerCreateBodyBytes+1))
	// SELinux and systempaths seeds — tested against the strict policy below
	// to exercise both the JSON decode path and the denial logic branches.
	f.Add([]byte(`{"HostConfig":{"SecurityOpt":["label=disable"]}}`))
	f.Add([]byte(`{"HostConfig":{"SecurityOpt":["label:disable"]}}`))
	f.Add([]byte(`{"HostConfig":{"SecurityOpt":["label=user:system_u"]}}`))
	f.Add([]byte(`{"HostConfig":{"SecurityOpt":["systempaths=unconfined"]}}`))
	f.Add([]byte(`{"HostConfig":{"MaskedPaths":[]}}`))
	f.Add([]byte(`{"HostConfig":{"ReadonlyPaths":[]}}`))
	f.Add([]byte(`{"HostConfig":{"MaskedPaths":null}}`))
	// Local volume driver seeds — a Type "volume" mount whose DriverConfig
	// asks the local driver for a bind, and the same entry handing it a
	// filesystem type over a /dev node, which is not a bind at all.
	f.Add([]byte(`{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"/"}}}}]}}`))
	f.Add([]byte(`{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"ext4","device":"/dev/sda1"}}}}]}}`))
	f.Add([]byte(`{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"device":"/dev/../dev/sda1"}}}}]}}`))
	f.Add([]byte(`{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"btrfs","o":"rw,device=/dev/sdb"}}}}]}}`))
	f.Add([]byte(`{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"nfs","o":"addr=1.2.3.4","device":":/exports/data"}}}}]}}`))
	// Log driver seeds, run against the strict policy's allowed_log_drivers.
	f.Add([]byte(`{"HostConfig":{"LogConfig":{"Type":"syslog","Config":{"syslog-address":"tcp://evil.example:514"}}}}`))
	f.Add([]byte(`{"HostConfig":{"LogConfig":{"Type":"json-file","Config":{"Driver":"gelf","GELF-ADDRESS":"udp://evil.example:12201"}}}}`))
	f.Add([]byte(`{"HostConfig":{"LogConfig":{"Type":"json-file","Config":{"driver=fluentd":"x","max-size":"10m"}}}}`))
	f.Add([]byte(`{"HostConfig":{"LogConfig":{"Type":"","Config":{"loki-url":"https://evil.example/loki/api/v1/push"}}}}`))

	// permissive policy: exercises JSON decode and existing checks.
	policy := newContainerCreatePolicy(ContainerCreateOptions{
		AllowedBindMounts: []string{"/srv/sockguard"},
	})

	// strict policy: exercises the new denial branches for the SELinux and
	// systempaths seeds above.
	strictPolicy := newContainerCreatePolicy(ContainerCreateOptions{
		AllowedBindMounts:         []string{"/srv/sockguard"},
		AllowAllCapabilities:      true,
		DenySelinuxDisable:        true,
		DenySelinuxLabelOverride:  true,
		DenyUnconfinedSystemPaths: true,
		AllowedLogDrivers:         []string{"json-file", "local"},
	})

	f.Fuzz(func(t *testing.T, body []byte) {
		body = truncateParserFuzzBytes(body, maxContainerCreateBodyBytes+1024)

		for name, p := range map[string]containerCreatePolicy{"permissive": policy, "strict": strictPolicy} {
			reason, err := fuzzVerdictOracle(t, "container create "+name, body, func(b []byte) (string, error) {
				req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewReader(b))
				defer func() {
					if req.Body != nil {
						_, _ = io.Copy(io.Discard, req.Body)
						_ = req.Body.Close()
					}
				}()
				return p.inspect(nil, req, "/containers/create")
			})
			// Neither policy sets AllowPrivileged or AllowHostNetwork, so a
			// body that decodes with either one on must have been refused.
			var decoded struct {
				HostConfig struct {
					Privileged  bool
					NetworkMode string
				}
			}
			if json.Unmarshal(body, &decoded) == nil && !denied(reason, err) {
				if decoded.HostConfig.Privileged {
					t.Fatalf("container create %s: allowed a privileged body: %q", name, body)
				}
				if decoded.HostConfig.NetworkMode == "host" {
					t.Fatalf("container create %s: allowed host network mode: %q", name, body)
				}
			}
		}
	})
}

func FuzzExec(f *testing.F) {
	f.Add([]byte(`{"Cmd":["/usr/local/bin/pre-update","--check"],"User":"app"}`))
	f.Add([]byte(`{"Cmd":["/bin/sh","-c","id"],"User":"app"}`))
	f.Add([]byte(`{"Cmd":"/bin/sh -c id","Privileged":true}`))
	f.Add([]byte(`{"Cmd":[]}`))
	f.Add([]byte(`{"Cmd":null}`))
	f.Add([]byte(`{"Cmd":{"bad":true}}`))
	f.Add([]byte(`{"Cmd":["/bin/sh"],"Env":["LD_PRELOAD=/tmp/x.so"]}`))
	f.Add([]byte(`{"Cmd":["/usr/local/bin/pre-update","--check"],"User":"app","Privileged":true}`))
	f.Add([]byte(`{"Cmd":["/usr/local/bin/pre-update","--check"],"User":"app","Env":["LD_PRELOAD=/tmp/x.so"]}`))
	f.Add([]byte(`{"Cmd":["/usr/local/bin/pre-update","--check"],"User":"app"}`))
	f.Add([]byte(`{"Cmd":["/bin/sh"],"Env":[123]}`))
	f.Add([]byte(`{"Cmd":["/bin/sh"],"Env":"FOO=bar"}`))
	f.Add(bytes.Repeat([]byte("a"), maxExecBodyBytes+1))

	policy := newExecPolicy(ExecOptions{
		AllowedCommands: [][]string{{"/usr/local/bin/pre-update", "--check"}},
		DeniedEnvVars:   []string{"LD_PRELOAD"},
	})

	f.Fuzz(func(t *testing.T, body []byte) {
		body = truncateParserFuzzBytes(body, maxParserFuzzBytes)

		reason, err := fuzzVerdictOracle(t, "exec", body, func(b []byte) (string, error) {
			req := httptest.NewRequest(http.MethodPost, "/containers/abc123/exec", bytes.NewReader(b))
			defer func() {
				if req.Body != nil {
					_, _ = io.Copy(io.Discard, req.Body)
					_ = req.Body.Close()
				}
			}()
			return policy.inspect(nil, req, "/containers/abc123/exec")
		})
		// An allowed non-empty body must be the one allowlisted command, not
		// privileged, and free of the denied env var. Decoding into []string
		// only covers the array form; other Cmd shapes are not asserted on.
		var decoded struct {
			Cmd        []string
			Privileged bool
			Env        []string
		}
		if len(body) > 0 && !denied(reason, err) && json.Unmarshal(body, &decoded) == nil {
			if !slices.Equal(decoded.Cmd, []string{"/usr/local/bin/pre-update", "--check"}) {
				t.Fatalf("exec: allowed command %q outside the allowlist: %q", decoded.Cmd, body)
			}
			if decoded.Privileged {
				t.Fatalf("exec: allowed a privileged exec: %q", body)
			}
			for _, env := range decoded.Env {
				if name, _, _ := strings.Cut(env, "="); name == "LD_PRELOAD" {
					t.Fatalf("exec: allowed denied env var %q: %q", env, body)
				}
			}
		}
	})
}

func FuzzImagePull(f *testing.F) {
	f.Add("fromImage=busybox&tag=latest")
	f.Add("fromImage=ghcr.io%2Facme%2Fapp&tag=latest")
	f.Add("fromSrc=https%3A%2F%2Fexample.com%2Frootfs.tar&repo=acme%2Fimported")
	f.Add("fromImage=index.docker.io%2Flibrary%2Fbusybox%3Alatest")
	f.Add("fromImage=%zz")

	policy := newImagePullPolicy(ImagePullOptions{
		AllowOfficial:     true,
		AllowedRegistries: []string{"ghcr.io"},
	})

	f.Fuzz(func(t *testing.T, rawQuery string) {
		fuzzVerdictOracle(t, "image pull", nil, func([]byte) (string, error) {
			req := httptest.NewRequest(http.MethodPost, "/images/create", nil)
			req.URL = &url.URL{Path: "/images/create", RawQuery: rawQuery}
			return policy.inspect(nil, req, "/images/create")
		})
	})
}

// FuzzImagePush drives the push inspector and destination parser with
// arbitrary paths, queries, registry-auth headers and destination strings. It
// asserts that nothing panics, that the inspector never errors, and that the
// parser only accepts a lowercase host and never a value carrying a byte a
// reference cannot hold, so a destination it cannot read is never allowed.
func FuzzImagePush(f *testing.F) {
	f.Add("/images/ghcr.io/acme/app/push", "tag=latest", "", "ghcr.io/acme/app:v1")
	f.Add("/libpod/images/x/push", "destination=docker://ghcr.io/acme/app", "", "docker://ghcr.io/a")
	f.Add("/libpod/images/x/push", "destination=oci:/tmp/x", "", "oci:/tmp/x")
	f.Add("/libpod/manifests/l/registry/ghcr.io%2Facme%2Fapp", "", "", "[::1]:5000/a")
	f.Add("/libpod/manifests/l/registry/ghcr.io%252Facme%252Fapp", "", "", "Evil/app")
	f.Add("/libpod/manifests/l/push", "destination=%5B::1%5D:5000/a", "", "a@sha256:"+strings.Repeat("a", 64))
	f.Add("/plugins/ghcr.io/acme/p/push", "", "eyJzZXJ2ZXJhZGRyZXNzIjoicXVheS5pbyJ9", "")
	f.Add("/v1.45/images/Evil/app/push", "destination=a&destination=b", "!!", "a:b/c")

	policy := newImagePushPolicy(ImagePushOptions{
		AllowedRegistries: []string{"ghcr.io", "localhost:5000", "[::1]:5000"},
		RegistryAliases:   map[string]string{"mirror.example": "ghcr.io"},
	})

	f.Fuzz(func(t *testing.T, path, rawQuery, auth, destination string) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.URL = &url.URL{Path: path, RawQuery: rawQuery}
		if auth != "" {
			req.Header.Set("X-Registry-Auth", auth)
		}
		if _, err := policy.inspect(nil, req, NormalizePath(req.URL.Path)); err != nil {
			t.Fatalf("inspect returned an error: %v", err)
		}

		for _, libpod := range []bool{false, true} {
			dest := parsePushDestination(destination, libpod)
			if dest.problem == pushDestinationOK {
				if dest.host == "" || dest.host != strings.ToLower(dest.host) {
					t.Fatalf("parsePushDestination(%q) accepted with host %q", destination, dest.host)
				}
				if strings.ContainsAny(destination, " \t\r\n%\\\x00") {
					t.Fatalf("parsePushDestination(%q) accepted a value with a forbidden byte", destination)
				}
			}
			if reason := policy.denyReasonForDestination(destination, libpod); reason == "" && dest.problem != pushDestinationOK {
				t.Fatalf("denyReasonForDestination(%q) allowed a destination that did not parse", destination)
			}
		}
	})
}

func truncateParserFuzzBytes(body []byte, max int) []byte {
	if len(body) > max {
		return body[:max]
	}
	return body
}

func mustBuildContextTarSeed(tb testing.TB, dockerfilePath string, dockerfile string) []byte {
	tb.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, file := range []struct {
		name string
		body string
	}{
		{name: dockerfilePath, body: dockerfile},
		{name: "app.txt", body: "hello"},
	} {
		if err := tw.WriteHeader(&tar.Header{
			Name: file.name,
			Mode: 0o644,
			Size: int64(len(file.body)),
		}); err != nil {
			tb.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write([]byte(file.body)); err != nil {
			tb.Fatalf("write tar body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		tb.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

func mustBuildContextGzipTarSeed(tb testing.TB, dockerfilePath string, dockerfile string) []byte {
	tb.Helper()

	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	for _, file := range []struct {
		name string
		body string
	}{
		{name: dockerfilePath, body: dockerfile},
		{name: "app.txt", body: "hello"},
	} {
		if err := tw.WriteHeader(&tar.Header{
			Name: file.name,
			Mode: 0o644,
			Size: int64(len(file.body)),
		}); err != nil {
			tb.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write([]byte(file.body)); err != nil {
			tb.Fatalf("write tar body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		tb.Fatalf("close tar: %v", err)
	}
	if err := gzw.Close(); err != nil {
		tb.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}
