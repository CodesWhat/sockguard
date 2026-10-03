package cmd

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/apipath"
	"github.com/codeswhat/sockguard/app/internal/config"
)

// buildInstructionsChainDaemon is the build endpoint of each engine, as far as
// choosing which files in the context it builds goes, and it records the files
// of every build it runs.
//
// dockerd serves POST /build. It reads `dockerfile` as one path inside the
// context, defaulting to Dockerfile, and reads dockerfile instead when a path
// named Dockerfile is missing (moby 28.5.1
// builder/remotecontext/detect.go withDockerfileFromContext; BuildKit 0.25.1
// frontend/dockerui does the same for any path whose base is Dockerfile).
//
// Podman serves POST /build and POST /vX/libpod/build from one handler, and has
// no unversioned /libpod/build route. It reads `dockerfile` with
// url.Values.Get, decodes it as a JSON array of paths and takes the value as
// one path when it is not one. Without `dockerfile` it builds Containerfile,
// else Dockerfile, on the libpod route and Dockerfile on the compat one. Read
// from Podman 5.8.6 pkg/api/handlers/compat/images_build.go
// (processBuildContext) and pkg/api/server/register_images.go.
type buildInstructionsChainDaemon struct {
	podman bool

	mu    sync.Mutex
	built [][]string
}

func (d *buildInstructionsChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	versioned := normPath != r.URL.Path
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && normPath == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(d.podman))
	case r.Method == http.MethodPost && normPath == "/build":
		d.build(w, r, false)
	case r.Method == http.MethodPost && normPath == "/libpod/build" && d.podman && versioned:
		d.build(w, r, true)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d *buildInstructionsChainDaemon) build(w http.ResponseWriter, r *http.Request, libpod bool) {
	context, err := buildInstructionsChainUnpack(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	files := d.dockerdFiles(r, context)
	if d.podman {
		files = d.podmanFiles(r, libpod, context)
	}
	built := make([]string, 0, len(files))
	for _, file := range files {
		// Buildah fetches a URL, and reads an absolute path from the daemon
		// host, which here has every file it is asked for.
		if d.podman && (strings.HasPrefix(file, "https://") || strings.HasPrefix(file, "/")) {
			built = append(built, file+": fetched")
			continue
		}
		content, ok := context.read(file)
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		built = append(built, file+": "+content)
	}
	d.mu.Lock()
	d.built = append(d.built, built)
	d.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (d *buildInstructionsChainDaemon) dockerdFiles(r *http.Request, context *buildInstructionsChainTree) []string {
	_ = r.ParseForm()
	name := r.FormValue("dockerfile")
	if name == "" {
		name = "Dockerfile"
	}
	name = path.Clean(name)
	if _, ok := context.read(name); !ok && path.Base(name) == "Dockerfile" {
		name = path.Join(path.Dir(name), "dockerfile")
	}
	return []string{name}
}

func (d *buildInstructionsChainDaemon) podmanFiles(r *http.Request, libpod bool, context *buildInstructionsChainTree) []string {
	if value := r.URL.Query().Get("dockerfile"); value != "" {
		var files []string
		if err := json.Unmarshal([]byte(value), &files); err != nil {
			files = []string{value}
		}
		for i, file := range files {
			if !strings.HasPrefix(file, "https://") {
				files[i] = path.Clean(file)
			}
		}
		return files
	}
	if _, ok := context.read("Containerfile"); libpod && ok {
		return []string{"Containerfile"}
	}
	return []string{"Dockerfile"}
}

func (d *buildInstructionsChainDaemon) builds() [][]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.built)
}

// buildInstructionsChainTree is an unpacked build context: regular files and
// symlinks, each at the path it was written to.
type buildInstructionsChainTree struct {
	files map[string]string
	links map[string]string
}

// resolve follows every symlink in name, the way opening it on the unpacked
// context would.
func (c *buildInstructionsChainTree) resolve(name string) string {
	for range 40 {
		parts := strings.Split(name, "/")
		followed := false
		for i := range parts {
			prefix := strings.Join(parts[:i+1], "/")
			if target, ok := c.links[prefix]; ok {
				rest := strings.Join(parts[i+1:], "/")
				name = strings.TrimPrefix(path.Clean("/"+path.Join(path.Dir(prefix), target, rest)), "/")
				followed = true
				break
			}
		}
		if !followed {
			return name
		}
	}
	return name
}

func (c *buildInstructionsChainTree) read(name string) (string, bool) {
	content, ok := c.files[c.resolve(name)]
	return content, ok
}

// buildInstructionsChainUnpack unpacks a build context the way both engines
// do: each entry lands at its cleaned name, written through any symlink an
// earlier entry left on the way there, and replaces whatever was there.
func buildInstructionsChainUnpack(body io.Reader) (*buildInstructionsChainTree, error) {
	tree := &buildInstructionsChainTree{files: map[string]string{}, links: map[string]string{}}
	reader := tar.NewReader(body)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return tree, nil
		}
		if err != nil {
			return nil, err
		}
		name := strings.TrimPrefix(path.Clean("/"+header.Name), "/")
		if name == "" {
			continue
		}
		name = path.Join(tree.resolve(path.Dir(name)), path.Base(name))
		delete(tree.files, name)
		delete(tree.links, name)
		switch header.Typeflag {
		case tar.TypeReg:
			content, err := io.ReadAll(reader)
			if err != nil {
				return nil, err
			}
			tree.files[name] = string(content)
		case tar.TypeSymlink:
			tree.links[name] = header.Linkname
		case tar.TypeLink:
			if content, ok := tree.read(strings.TrimPrefix(path.Clean("/"+header.Linkname), "/")); ok {
				tree.files[name] = content
			}
		}
	}
}

// buildInstructionsChainFile is a context entry: a regular file, or a symlink
// to link when link is set.
type buildInstructionsChainFile struct {
	name, body string
	link       string
}

func buildInstructionsChainContext(t *testing.T, files ...buildInstructionsChainFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	for _, file := range files {
		header := &tar.Header{Name: file.name, Mode: 0o644, Size: int64(len(file.body))}
		if file.link != "" {
			header = &tar.Header{Name: file.name, Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: file.link}
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := io.WriteString(writer, file.body); err != nil {
			t.Fatalf("write tar body: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

// TestServeChainBuildInspectsTheFilesTheEngineBuilds sends builds through the
// production chain, with RUN instructions refused, to a daemon that picks the
// files to build the way each engine does, and asserts on what it built.
//
// The filter read Dockerfile whenever `dockerfile` was absent, but Podman's
// libpod route builds Containerfile when the context has one, so a context
// carrying a RUN in its Containerfile next to a harmless Dockerfile was
// allowed and built. podman-remote sends `dockerfile` as a JSON array, which
// the filter read as one file name and refused as uninspectable. A URL or an
// absolute path, which Podman fetches or reads from the daemon host, was
// looked up in the tar, so a decoy at the cleaned name passed and an empty
// body skipped the check. And the tar scan only counted regular files, so a
// later symlink at the inspected name, or a file written through a symlinked
// directory, changed what the daemon read after the filter had passed it.
func TestServeChainBuildInspectsTheFilesTheEngineBuilds(t *testing.T) {
	const (
		harmless = "FROM busybox\nCOPY . /app\n"
		runs     = "FROM busybox\nRUN id\n"
	)
	file := func(name, body string) buildInstructionsChainFile {
		return buildInstructionsChainFile{name: name, body: body}
	}
	link := func(name, target string) buildInstructionsChainFile {
		return buildInstructionsChainFile{name: name, link: target}
	}
	containerfileRuns := buildInstructionsChainContext(t, file("Containerfile", runs), file("Dockerfile", harmless))
	tests := []struct {
		name       string
		podman     bool
		target     string
		context    []byte
		wantStatus int
		wantReason string
		wantBuilds [][]string
	}{
		{
			name:       "versioned libpod build with RUN in the Containerfile",
			podman:     true,
			target:     "/v5.0.0/libpod/build",
			context:    containerfileRuns,
			wantStatus: http.StatusForbidden,
			wantReason: `RUN instructions are not allowed in "Containerfile"`,
		},
		{
			// Podman 5.8.6 answers this path with 404, so nothing could be
			// built, but sockguard serves it as the same libpod build.
			name:       "unversioned libpod build with RUN in the Containerfile",
			podman:     true,
			target:     "/libpod/build",
			context:    containerfileRuns,
			wantStatus: http.StatusForbidden,
			wantReason: `RUN instructions are not allowed in "Containerfile"`,
		},
		{
			name:       "versioned libpod build with only a Containerfile",
			podman:     true,
			target:     "/v5.0.0/libpod/build",
			context:    buildInstructionsChainContext(t, file("Containerfile", harmless)),
			wantStatus: http.StatusOK,
			wantBuilds: [][]string{{"Containerfile: " + harmless}},
		},
		{
			name:       "versioned libpod build with only a Dockerfile",
			podman:     true,
			target:     "/v5.0.0/libpod/build",
			context:    buildInstructionsChainContext(t, file("Dockerfile", harmless)),
			wantStatus: http.StatusOK,
			wantBuilds: [][]string{{"Dockerfile: " + harmless}},
		},
		{
			name:       "versioned libpod build with a Containerfile written through a symlinked directory",
			podman:     true,
			target:     "/v5.0.0/libpod/build",
			context:    buildInstructionsChainContext(t, file("Dockerfile", harmless), link("here", "."), file("here/Containerfile", runs)),
			wantStatus: http.StatusForbidden,
			wantReason: `tar entry "here/Containerfile" is written through a symlink`,
		},
		{
			// The compat route never looks for a Containerfile.
			name:       "compat build on Podman with RUN in the Containerfile",
			podman:     true,
			target:     "/v1.41/build",
			context:    containerfileRuns,
			wantStatus: http.StatusOK,
			wantBuilds: [][]string{{"Dockerfile: " + harmless}},
		},
		{
			name:       "compat build on dockerd with RUN in the Containerfile",
			target:     "/v1.45/build",
			context:    containerfileRuns,
			wantStatus: http.StatusOK,
			wantBuilds: [][]string{{"Dockerfile: " + harmless}},
		},
		{
			name:       "compat build on dockerd with a lowercase dockerfile",
			target:     "/v1.45/build",
			context:    buildInstructionsChainContext(t, file("dockerfile", harmless)),
			wantStatus: http.StatusOK,
			wantBuilds: [][]string{{"dockerfile: " + harmless}},
		},
		{
			name:       "compat build on dockerd with RUN in a lowercase dockerfile",
			target:     "/v1.45/build",
			context:    buildInstructionsChainContext(t, file("dockerfile", runs)),
			wantStatus: http.StatusForbidden,
			wantReason: `RUN instructions are not allowed in "dockerfile"`,
		},
		{
			name:       "compat build on dockerd whose Dockerfile is replaced by a symlink",
			target:     "/v1.45/build",
			context:    buildInstructionsChainContext(t, file("Dockerfile", harmless), file("steps", runs), link("Dockerfile", "steps")),
			wantStatus: http.StatusForbidden,
			wantReason: `unable to inspect Dockerfile "Dockerfile"`,
		},
		{
			name:       "compat build on dockerd with a Dockerfile written through a symlinked directory",
			target:     "/v1.45/build",
			context:    buildInstructionsChainContext(t, file("Dockerfile", harmless), link("here", "."), file("here/Dockerfile", runs)),
			wantStatus: http.StatusForbidden,
			wantReason: `tar entry "here/Dockerfile" is written through a symlink`,
		},
		{
			// podman-remote build -f Containerfile.a -f Containerfile.b
			name:       "podman-remote build with two Containerfiles",
			podman:     true,
			target:     "/v5.0.0/libpod/build?dockerfile=%5B%22Containerfile.a%22%2C%22Containerfile.b%22%5D",
			context:    buildInstructionsChainContext(t, file("Containerfile.a", harmless), file("Containerfile.b", "COPY . /srv\n")),
			wantStatus: http.StatusOK,
			wantBuilds: [][]string{{"Containerfile.a: " + harmless, "Containerfile.b: COPY . /srv\n"}},
		},
		{
			name:       "podman-remote build with RUN in its second Containerfile",
			podman:     true,
			target:     "/v5.0.0/libpod/build?dockerfile=%5B%22Containerfile.a%22%2C%22Containerfile.b%22%5D",
			context:    buildInstructionsChainContext(t, file("Containerfile.a", harmless), file("Containerfile.b", "RUN id\n")),
			wantStatus: http.StatusForbidden,
			wantReason: `RUN instructions are not allowed in "Containerfile.b"`,
		},
		{
			// The old inspector let an empty body through without reading
			// `dockerfile` at all.
			name:       "remote Containerfile with no context on Podman",
			podman:     true,
			target:     "/v5.0.0/libpod/build?dockerfile=https%3A%2F%2Fexample.com%2FContainerfile",
			wantStatus: http.StatusForbidden,
			wantReason: `remote Dockerfile "https://example.com/Containerfile" cannot be inspected`,
		},
		{
			name:       "remote Containerfile next to a decoy on Podman",
			podman:     true,
			target:     "/v5.0.0/libpod/build?dockerfile=https%3A%2F%2Fexample.com%2FContainerfile",
			context:    buildInstructionsChainContext(t, file("https:/example.com/Containerfile", harmless)),
			wantStatus: http.StatusForbidden,
			wantReason: `remote Dockerfile "https://example.com/Containerfile" cannot be inspected`,
		},
		{
			name:       "daemon-host Containerfile next to a decoy on Podman",
			podman:     true,
			target:     "/v5.0.0/libpod/build?dockerfile=%2Fsrv%2Fapp%2FContainerfile",
			context:    buildInstructionsChainContext(t, file("srv/app/Containerfile", harmless)),
			wantStatus: http.StatusForbidden,
			wantReason: `Dockerfile "/srv/app/Containerfile" is an absolute path`,
		},
		{
			name:       "JSON array on the compat route on Podman",
			podman:     true,
			target:     "/v1.41/build?dockerfile=%5B%22build%2FContainerfile%22%5D",
			context:    buildInstructionsChainContext(t, file("build/Containerfile", runs), file("Dockerfile", harmless)),
			wantStatus: http.StatusForbidden,
			wantReason: `RUN instructions are not allowed in "build/Containerfile"`,
		},
		{
			name:       "named file in the context on Podman",
			podman:     true,
			target:     "/v5.0.0/libpod/build?dockerfile=build%2FContainerfile",
			context:    buildInstructionsChainContext(t, file("build/Containerfile", harmless), file("Containerfile", runs)),
			wantStatus: http.StatusOK,
			wantBuilds: [][]string{{"build/Containerfile: " + harmless}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &buildInstructionsChainDaemon{podman: tt.podman}
			addr := newEngineChain(t, "build-files", daemon, func(cfg *config.Config) {
				cfg.Response.DenyVerbosity = "verbose"
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/build"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/build"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
			})

			status, body := sendBuildInstructionsChainRequest(t, "http://"+addr+tt.target, tt.context)
			if builds := daemon.builds(); !slices.EqualFunc(builds, tt.wantBuilds, slices.Equal[[]string]) {
				t.Errorf("daemon built %q, want %q", builds, tt.wantBuilds)
			}
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", status, tt.wantStatus, body)
			}
			if tt.wantStatus == http.StatusForbidden && tt.wantReason == "" {
				t.Fatal("a denied case must name the reason it is denied for")
			}
			if tt.wantReason != "" {
				var denial struct {
					Reason string `json:"reason"`
				}
				if err := json.Unmarshal(body, &denial); err != nil || !strings.Contains(denial.Reason, tt.wantReason) {
					t.Errorf("body = %s, want reason containing %q", body, tt.wantReason)
				}
			}
		})
	}
}

func sendBuildInstructionsChainRequest(t *testing.T, target string, context []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(context))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-tar")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}
