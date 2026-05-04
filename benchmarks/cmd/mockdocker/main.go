// mockdocker is a minimal Docker-API-shaped HTTP server that listens on a
// unix socket. It exists so the sockguard synthetic benchmark has a stable
// upstream whose behavior doesn't drift between runs. It intentionally does
// NOT implement the full Docker API — just the three endpoints the
// benchmark targets:
//
//	GET  /_ping              → 200 "OK" (tiny body)
//	GET  /containers/json    → 200 JSON array of 5 fake containers (~2KB)
//	POST /exec/{id}/start    → 204 no body (the deny target — sockguard
//	                           should never forward this call to us)
//
// Anything else returns 404. Logs are silenced by default; pass -log to
// enable per-request logging when debugging.
package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unicode"
)

type mockContainer struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	State  string            `json:"State"`
	Status string            `json:"Status"`
	Labels map[string]string `json:"Labels"`
}

var fakeContainers = []mockContainer{
	{ID: "c0000000001", Names: []string{"/traefik"}, Image: "traefik:v3", State: "running", Status: "Up 3 days", Labels: map[string]string{"com.docker.compose.project": "infra"}},
	{ID: "c0000000002", Names: []string{"/grafana"}, Image: "grafana/grafana:10", State: "running", Status: "Up 3 days", Labels: map[string]string{"com.docker.compose.project": "infra"}},
	{ID: "c0000000003", Names: []string{"/prometheus"}, Image: "prom/prometheus:v2", State: "running", Status: "Up 2 days", Labels: map[string]string{"com.docker.compose.project": "infra"}},
	{ID: "c0000000004", Names: []string{"/postgres"}, Image: "postgres:17", State: "running", Status: "Up 5 hours", Labels: map[string]string{"com.docker.compose.project": "db"}},
	{ID: "c0000000005", Names: []string{"/redis"}, Image: "redis:8", State: "running", Status: "Up 5 hours", Labels: map[string]string{"com.docker.compose.project": "db"}},
}

func main() {
	socket := flag.String("socket", "/tmp/sg-bench-mock.sock", "unix socket path")
	// Debug-only: per-request sanitization and log formatting currently add
	// about six allocations per request, so leave this off for measurements.
	verbose := flag.Bool("log", false, "log every request")
	flag.Parse()

	_ = os.Remove(*socket)
	ln, err := net.Listen("unix", *socket)
	if err != nil {
		log.Fatalf("listen %s: %v", *socket, err)
	}
	if err := os.Chmod(*socket, 0o666); err != nil {
		log.Fatalf("chmod %s: %v", *socket, err)
	}

	containersPayload, err := json.Marshal(fakeContainers)
	if err != nil {
		log.Fatalf("marshal containers: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/_ping", func(w http.ResponseWriter, r *http.Request) {
		if *verbose {
			logRequest(r)
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "OK")
	})
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		if *verbose {
			logRequest(r)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(containersPayload)
	})
	mux.HandleFunc("/exec/", func(w http.ResponseWriter, r *http.Request) {
		if *verbose {
			logRequest(r)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	srv := &http.Server{Handler: mux}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	log.Printf("mockdocker listening on %s", *socket)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	_ = srv.Close()
	<-done
	_ = os.Remove(*socket)
}

func logRequest(r *http.Request) {
	log.Printf("method=%q path=%q", sanitizeLogField(r.Method), sanitizeLogField(r.URL.Path))
}

func sanitizeLogField(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
