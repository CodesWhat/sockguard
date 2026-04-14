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

		req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
		req.URL = &url.URL{Path: "/build", RawQuery: rawQuery}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}

		_, _ = policy.inspect(req, "/build")

		if req.Body != nil {
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
		}
	})
}

func FuzzExec(f *testing.F) {
	f.Add([]byte(`{"Cmd":["/usr/local/bin/pre-update","--check"]}`))
	f.Add([]byte(`{"Cmd":"/bin/sh -c id","Privileged":true}`))
	f.Add([]byte(`{"Cmd":[]}`))
	f.Add([]byte(`{"Cmd":null}`))
	f.Add([]byte(`{"Cmd":{"bad":true}}`))
	f.Add(bytes.Repeat([]byte("a"), maxExecBodyBytes+1))

	policy := newExecPolicy(ExecOptions{
		AllowedCommands: [][]string{{"/usr/local/bin/pre-update", "--check"}},
	})

	f.Fuzz(func(t *testing.T, body []byte) {
		body = truncateParserFuzzBytes(body, maxParserFuzzBytes)

		req := httptest.NewRequest(http.MethodPost, "/containers/abc123/exec", bytes.NewReader(body))
		_, _ = policy.inspect(nil, req, "/containers/abc123/exec")

		if req.Body != nil {
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
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
		req := httptest.NewRequest(http.MethodPost, "/images/create", nil)
		req.URL = &url.URL{Path: "/images/create", RawQuery: rawQuery}
		_, _ = policy.inspect(req, "/images/create")
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
