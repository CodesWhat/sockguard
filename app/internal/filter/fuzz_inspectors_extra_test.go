package filter

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// FuzzImageLoad fuzzes the imageLoadPolicy inspector with a wide range of
// request bodies — plain tar, gzip-wrapped tar, truncated gzip, and oversized
// inputs — and asserts it never panics regardless of input.
func FuzzImageLoad(f *testing.F) {
	// Seed: plain tar with valid manifest.
	f.Add(buildFuzzImageLoadTar(`[{"RepoTags":["registry.example.com/acme/app:latest"]}]`))
	// Seed: gzip-wrapped tar with valid manifest.
	f.Add(buildFuzzGzip(buildFuzzImageLoadTar(`[{"RepoTags":["busybox:latest"]}]`)))
	// Seed: truncated gzip header (first few bytes of a valid gzip).
	truncated := buildFuzzGzip(buildFuzzImageLoadTar(`[{"RepoTags":["busybox:latest"]}]`))
	if len(truncated) > 4 {
		truncated = truncated[:4]
	}
	f.Add(truncated)
	// Seed: tiny oversized-decompression gzip (a valid gzip of 512 zero bytes;
	// the fuzzer discovers real bomb inputs from this starting point).
	f.Add(buildFuzzGzip(bytes.Repeat([]byte{0}, 512)))
	// Seed: invalid/random bytes.
	f.Add([]byte("not a tar archive"))
	f.Add([]byte(`{`))
	f.Add(bytes.Repeat([]byte("a"), 64))

	policy := newImageLoadPolicy(ImageLoadOptions{
		AllowAllRegistries: true,
		AllowUntagged:      true,
	})

	f.Fuzz(func(t *testing.T, body []byte) {
		body = truncateParserFuzzBytes(body, maxImageLoadBodyBytes+1024)

		req := httptest.NewRequest(http.MethodPost, "/images/load", bytes.NewReader(body))
		_, _ = policy.inspect(nil, req, "/images/load")

		if req.Body != nil {
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
		}
	})
}

// FuzzContainerArchive fuzzes the containerArchivePolicy inspector with tar
// archives containing a wide variety of entry paths, including path-traversal
// forms, and asserts it never panics.
func FuzzContainerArchive(f *testing.F) {
	// Seed: safe relative path.
	f.Add("app", buildFuzzContainerArchiveTar("app/file.txt", "hello", 0, "", 0))
	// Seed: path traversal in tar entry name.
	f.Add("app", buildFuzzContainerArchiveTar("../etc/passwd", "root:x:0:0", 0, "", 0))
	// Seed: double-dot traversal form.
	f.Add("app", buildFuzzContainerArchiveTar("app/../../etc/shadow", "secret", 0, "", 0))
	// Seed: absolute path entry.
	f.Add("app", buildFuzzContainerArchiveTar("/etc/passwd", "root:x:0:0", 0, "", 0))
	// Seed: symlink entry with escaping target.
	f.Add("app", buildFuzzContainerArchiveTar("link", "", tar.TypeSymlink, "../../etc/passwd", 0))
	// Seed: hardlink with traversal target.
	f.Add("app", buildFuzzContainerArchiveTar("hlink", "", tar.TypeLink, "../etc/passwd", 0))
	// Seed: setuid bit set.
	f.Add("app", buildFuzzContainerArchiveTar("setuid", "x", 0, "", 0o4755))
	// Seed: plain valid tar.
	f.Add("app", buildFuzzContainerArchiveTar("file.txt", "ok", 0, "", 0))
	// Seed: invalid bytes.
	f.Add("app", []byte("not a tar"))
	f.Add("..", []byte("ignored"))

	policy := newContainerArchivePolicy(ContainerArchiveOptions{
		AllowSetID:         true,
		AllowDeviceNodes:   true,
		AllowEscapingLinks: true,
	})

	f.Fuzz(func(t *testing.T, queryPath string, body []byte) {
		body = truncateParserFuzzBytes(body, maxContainerArchiveBodyBytes+1024)

		req := httptest.NewRequest(http.MethodPut, "/containers/abc/archive", bytes.NewReader(body))
		req.URL = &url.URL{Path: "/containers/abc/archive", RawQuery: "path=" + queryPath}
		_, _ = policy.inspect(nil, req, "/containers/abc/archive")

		if req.Body != nil {
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
		}
	})
}

// FuzzContainerUpdate fuzzes the containerUpdatePolicy inspector with
// arbitrary JSON bodies covering all HostConfig fields and asserts no panics.
func FuzzContainerUpdate(f *testing.F) {
	f.Add([]byte(`{"HostConfig":{"Privileged":true}}`))
	f.Add([]byte(`{"HostConfig":{"Memory":134217728,"CpuShares":512}}`))
	f.Add([]byte(`{"HostConfig":{"RestartPolicy":{"Name":"always","MaximumRetryCount":0}}}`))
	f.Add([]byte(`{"HostConfig":{"CapAdd":["NET_ADMIN"],"CapDrop":["MKNOD"]}}`))
	f.Add([]byte(`{"HostConfig":{"Devices":[{"PathOnHost":"/dev/sda","PathInContainer":"/dev/sda"}]}}`))
	f.Add([]byte(`{"Resources":{"Memory":67108864}}`))
	f.Add([]byte(`{"HostConfig":{"Resources":{"NanoCpus":1000000000}}}`))
	f.Add([]byte(`{`))
	f.Add([]byte(`{}`))
	f.Add(bytes.Repeat([]byte("a"), maxContainerUpdateBodyBytes+1))

	policy := newContainerUpdatePolicy(ContainerUpdateOptions{
		AllowPrivileged:      true,
		AllowAllDevices:      true,
		AllowCapabilities:    true,
		AllowRestartPolicy:   true,
		AllowResourceUpdates: true,
	})

	f.Fuzz(func(t *testing.T, body []byte) {
		body = truncateParserFuzzBytes(body, maxContainerUpdateBodyBytes+1024)

		req := newJSONInspectorFuzzRequest(http.MethodPost, "/containers/abc123/update", "", body)
		_, _ = policy.inspect(nil, req, "/containers/abc123/update")
		drainFuzzRequestBody(req)
	})
}

// FuzzNode fuzzes the nodePolicy inspector with arbitrary node-update JSON
// bodies and asserts it never panics.
func FuzzNode(f *testing.F) {
	f.Add("/nodes/abc123/update", []byte(`{"Role":"manager","Availability":"active"}`))
	f.Add("/nodes/node-1/update", []byte(`{"Name":"worker-1"}`))
	f.Add("/nodes/abc/update", []byte(`{"Labels":{"com.sockguard.owner":"user1"}}`))
	f.Add("/nodes/abc/update", []byte(`{"Role":"worker","Availability":"drain","Name":"node-2","Labels":{"env":"prod"}}`))
	f.Add("/nodes/abc/update", []byte(`{"Role":null,"Labels":null}`))
	f.Add("/nodes/abc/update", []byte(`{`))
	f.Add("/nodes/abc/update", []byte(`{}`))
	f.Add("/nodes/abc/update", bytes.Repeat([]byte("a"), maxNodeBodyBytes+1))
	f.Add("/v1.45/nodes/abc/update", []byte(`{"Role":"manager"}`))

	policy := newNodePolicy(NodeOptions{
		AllowNameChange:         true,
		AllowRoleChange:         true,
		AllowAvailabilityChange: true,
		AllowLabelMutation:      true,
		AllowedLabelKeys:        []string{"env", "com.example.team"},
	})

	f.Fuzz(func(t *testing.T, path string, body []byte) {
		body = truncateParserFuzzBytes(body, maxNodeBodyBytes+1024)

		req := newJSONInspectorFuzzRequest(http.MethodPost, path, "", body)
		_, _ = policy.inspect(nil, req, NormalizePath(path))
		drainFuzzRequestBody(req)
	})
}

// buildFuzzTarEntries constructs a tar archive from a list of simple name/body
// pairs. It is used at fuzz seed time and must not call t.Helper / t.Fatalf.
func buildFuzzTarEntries(entries []struct{ name, body string }) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     int64(len(e.body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			panic("buildFuzzTarEntries: WriteHeader: " + err.Error())
		}
		if e.body != "" {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				panic("buildFuzzTarEntries: Write: " + err.Error())
			}
		}
	}
	if err := tw.Close(); err != nil {
		panic("buildFuzzTarEntries: Close: " + err.Error())
	}
	return buf.Bytes()
}

// buildFuzzGzip wraps raw bytes in a gzip stream. Used at fuzz seed time.
func buildFuzzGzip(raw []byte) []byte {
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	if _, err := gzw.Write(raw); err != nil {
		panic("buildFuzzGzip: Write: " + err.Error())
	}
	if err := gzw.Close(); err != nil {
		panic("buildFuzzGzip: Close: " + err.Error())
	}
	return buf.Bytes()
}

// buildFuzzImageLoadTar produces a minimal docker-save tar with a manifest.
func buildFuzzImageLoadTar(manifest string) []byte {
	return buildFuzzTarEntries([]struct{ name, body string }{
		{name: "manifest.json", body: manifest},
		{name: "sha256/layer.tar", body: "layer"},
	})
}

// buildFuzzContainerArchiveTar creates a tar with the given entry path and body.
func buildFuzzContainerArchiveTar(name, body string, typ byte, link string, mode int64) []byte {
	if typ == 0 {
		typ = tar.TypeReg
	}
	if mode == 0 {
		mode = 0o644
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{
		Name:     name,
		Typeflag: typ,
		Mode:     mode,
		Linkname: link,
	}
	if typ == tar.TypeReg {
		hdr.Size = int64(len(body))
	}
	if err := tw.WriteHeader(hdr); err != nil {
		panic("buildFuzzContainerArchiveTar: WriteHeader: " + err.Error())
	}
	if typ == tar.TypeReg && body != "" {
		if _, err := tw.Write([]byte(body)); err != nil {
			panic("buildFuzzContainerArchiveTar: Write: " + err.Error())
		}
	}
	if err := tw.Close(); err != nil {
		panic("buildFuzzContainerArchiveTar: Close: " + err.Error())
	}
	return buf.Bytes()
}
