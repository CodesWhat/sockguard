package cmd

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/apipath"
	"github.com/codeswhat/sockguard/v2/app/internal/config"
)

// spooledBodyChainUpstream is a daemon that keeps the body of every load and
// build it is sent, and answers every other request from an image store. With
// failInspects set it answers an image inspect with a 500, which is a lookup
// owner isolation cannot finish.
type spooledBodyChainUpstream struct {
	store        *imageNameChainDaemon
	failInspects bool

	mu     sync.Mutex
	bodies [][]byte
}

func (u *spooledBodyChainUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	switch {
	case r.Method == http.MethodPost && (normPath == "/images/load" || normPath == "/build"):
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		u.mu.Lock()
		u.bodies = append(u.bodies, body)
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"stream":"done"}`)
	case u.failInspects && r.Method == http.MethodGet && strings.HasPrefix(normPath, "/images/") && strings.HasSuffix(normPath, "/json"):
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"message":"store is unavailable"}`)
	default:
		u.store.ServeHTTP(w, r)
	}
}

func (u *spooledBodyChainUpstream) received() [][]byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([][]byte(nil), u.bodies...)
}

// waitForEmptySpoolDir waits for dir to hold nothing. The client can read a
// response before the handler that wrote it has returned, so a body the chain
// is about to remove may still be there for a moment.
func waitForEmptySpoolDir(t *testing.T, dir string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read spool directory: %v", err)
		}
		if len(entries) == 0 {
			return
		}
		if time.Now().After(deadline) {
			names := make([]string, 0, len(entries))
			for _, entry := range entries {
				names = append(names, entry.Name())
			}
			t.Fatalf("spool directory still holds %v, want it empty", names)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestServeChainRemovesTheSpooledBody sends requests whose body the filter
// spools through the production handler chain and checks what is left on disk
// afterwards.
//
// The filter spools a load's archive, and a build's context while RUN is
// restricted, to a temp file and forwards the file as the request body. Only a
// Close on that body removed it, and only the reverse proxy called one. Owner
// isolation sits between the two and answers a request it refuses, or whose
// lookup fails, without forwarding it, so each such request left its body on
// disk: up to 512 MiB a time, for a client that only has to name another
// owner's image. An allowed request has to keep working: the daemon gets the
// whole body, and the file goes once it has.
func TestServeChainRemovesTheSpooledBody(t *testing.T) {
	archive := func(t *testing.T, name string) []byte {
		return imageLoadChainArchive(t, nil, name)
	}
	// A raw Dockerfile is a build context both engines accept, and without a
	// RUN it passes the inspection that has the filter spool it.
	dockerfile := func(*testing.T, string) []byte {
		return []byte("FROM scratch\nCOPY . /app\n" + strings.Repeat("# padding\n", 4096))
	}

	// A copy into a container is spooled the same way, and owner isolation
	// has refused one aimed at another owner's container since before it read
	// image names.
	copyIn := func(t *testing.T, _ string) []byte {
		return imageLoadChainArchive(t, nil)
	}

	tests := []struct {
		name         string
		method       string
		target       string
		body         func(*testing.T, string) []byte
		contentType  string
		reference    string
		failInspects bool
		wantStatus   int
	}{
		{name: "copy into another owner's container", method: http.MethodPut, target: "/v1.45/containers/" + imageNameChainVictimContainer + "/archive?path=%2Ftmp", body: copyIn, contentType: "application/x-tar", wantStatus: http.StatusForbidden},
		{name: "load onto another owner's name", target: "/v1.45/images/load", body: archive, contentType: "application/x-tar", reference: "theirs/app:latest", wantStatus: http.StatusForbidden},
		{name: "build onto another owner's name", target: "/v1.45/build?t=theirs%2Fapp%3Alatest", body: dockerfile, contentType: "text/plain", wantStatus: http.StatusForbidden},
		{name: "load whose owner lookup fails", target: "/v1.45/images/load", body: archive, contentType: "application/x-tar", reference: "mine/new:v2", failInspects: true, wantStatus: http.StatusBadGateway},
		{name: "build whose owner lookup fails", target: "/v1.45/build?t=mine%2Fnew%3Av2", body: dockerfile, contentType: "text/plain", failInspects: true, wantStatus: http.StatusBadGateway},
		{name: "allowed load", target: "/v1.45/images/load", body: archive, contentType: "application/x-tar", reference: "mine/new:v2", wantStatus: http.StatusOK},
		{name: "allowed build", target: "/v1.45/build?t=mine%2Fnew%3Av2", body: dockerfile, contentType: "text/plain", wantStatus: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spoolDir := t.TempDir()
			t.Setenv("TMPDIR", spoolDir)

			upstream := &spooledBodyChainUpstream{store: newImageNameChainDaemon(), failInspects: tt.failInspects}
			addr := newImageNameChain(t, upstream, func(cfg *config.Config) {
				cfg.RequestBody.Build.AllowRunInstructions = false
				cfg.Rules = append([]config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPut, Path: "/containers/*/archive"}, Action: "allow"},
				}, cfg.Rules...)
			})
			body := tt.body(t, tt.reference)
			method := tt.method
			if method == "" {
				method = http.MethodPost
			}

			req, err := http.NewRequest(method, "http://"+addr+tt.target, bytes.NewReader(body))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("Content-Type", tt.contentType)
			resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
			if err != nil {
				t.Fatalf("%s %s: %v", method, tt.target, err)
			}
			answer, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, tt.wantStatus, answer)
			}
			received := upstream.received()
			if tt.wantStatus == http.StatusOK {
				if len(received) != 1 || !bytes.Equal(received[0], body) {
					t.Errorf("daemon received %d bodies, want the one %d byte body the client sent", len(received), len(body))
				}
			} else if len(received) != 0 {
				t.Errorf("daemon received %d bodies, want the request stopped", len(received))
			}
			waitForEmptySpoolDir(t, spoolDir)
		})
	}
}
