package filter_test

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
)

func presetDocsSection(t *testing.T, heading, nextHeading string) string {
	t.Helper()

	contents, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "content", "docs", "presets.mdx"))
	if err != nil {
		t.Fatalf("read preset documentation: %v", err)
	}

	document := string(contents)
	start := strings.Index(document, heading)
	if start < 0 {
		t.Fatalf("preset documentation is missing heading %q", heading)
	}
	end := strings.Index(document[start+len(heading):], nextHeading)
	if end < 0 {
		t.Fatalf("preset documentation section %q is missing following heading %q", heading, nextHeading)
	}

	return document[start : start+len(heading)+end]
}

func TestTraefikPresetDocumentationIncludesNodeInspect(t *testing.T) {
	section := presetDocsSection(t, "## Traefik (`traefik.yaml`)", "## Portainer (`portainer.yaml`)")
	if !strings.Contains(section, "`GET /nodes/*`") {
		t.Fatal("Traefik preset documentation must disclose the allowed node-inspect route GET /nodes/*")
	}
}

// exfilDenialCases is the read-exfiltration surface that a "/containers/**"
// or "/images/**" allow glob silently swallows. Every entry here must
// evaluate to deny for a preset that ships without
// insecure_allow_read_exfiltration: true — that flag exists precisely to
// acknowledge these paths, so a preset dropping the flag has to prove it
// no longer reaches them.
//
// The list mirrors the Docker-compat half of sensitiveExfilEndpoints in
// internal/cmd/rules.go (the libpod half has no counterpart in these two
// presets, which never allow a /libpod path at all), plus the
// GET /containers/{id}/attach/ws websocket variant.
var exfilDenialCases = []presetCase{
	{"archive-denied", http.MethodGet, "/containers/abc/archive", "", false},
	{"archive-head-denied", http.MethodHead, "/containers/abc/archive", "", false},
	{"export-denied", http.MethodGet, "/containers/abc/export", "", false},
	{"logs-denied", http.MethodGet, "/containers/abc/logs", "", false},
	{"attach-ws-denied", http.MethodGet, "/containers/abc/attach/ws", "", false},
	{"attach-denied", http.MethodPost, "/containers/abc/attach", "", false},
	{"service-logs-denied", http.MethodGet, "/services/abc/logs", "", false},
	{"task-logs-denied", http.MethodGet, "/tasks/abc/logs", "", false},
	{"images-get-denied", http.MethodGet, "/images/get", "", false},
	{"image-get-denied", http.MethodGet, "/images/abc/get", "", false},
	{"image-push-denied", http.MethodPost, "/images/abc/push", "", false},
	{"plugin-push-denied", http.MethodPost, "/plugins/abc/push", "", false},
	// Version-prefixed forms normalize to the same paths, so the same
	// verdicts must hold after stripVersionPrefix.
	{"v-prefixed-archive-denied", http.MethodGet, "/v1.45/containers/abc/archive", "", false},
	{"v-prefixed-logs-denied", http.MethodGet, "/v1.45/containers/abc/logs", "", false},
	{"v-prefixed-image-get-denied", http.MethodGet, "/v1.45/images/abc/get", "", false},
}

// assertPresetDoesNotAckReadExfiltration pins the whole point of the
// narrowing: the shipped YAML must not carry
// insecure_allow_read_exfiltration: true. Without this assertion the deny
// cases below would still pass if someone re-widened the globs and put the
// flag back, because the flag is a startup-validation gate, not a
// request-time one.
func assertPresetDoesNotAckReadExfiltration(t *testing.T, presetFile string) {
	t.Helper()

	cfg, err := config.Load(filepath.Join("..", "..", "configs", presetFile))
	if err != nil {
		t.Fatalf("load preset %s: %v", presetFile, err)
	}
	if cfg.InsecureAllowReadExfiltration {
		t.Fatalf("%s sets insecure_allow_read_exfiltration: true; the preset is meant to be narrow enough not to need it", presetFile)
	}
}

// TestTraefikPresetConformance proves the shipped traefik.yaml admits every
// endpoint Traefik's Docker provider actually calls while denying the
// read-exfiltration surface the old "/containers/**" glob let through.
//
// The allow set is taken from traefik v3.7.12 pkg/provider/docker:
// pdocker.go calls ServerVersion (GET /version), Events (GET /events) and
// ContainerList (GET /containers/json); shared.go's inspectContainers calls
// ContainerInspect (GET /containers/{id}/json); pswarm.go's listServices
// calls ServiceList (GET /services) and NetworkList (GET /networks), and
// listTasks calls TaskList (GET /tasks). The moby client pings with
// HEAD /_ping and falls back to GET /_ping during version negotiation.
func TestTraefikPresetConformance(t *testing.T) {
	assertPresetDoesNotAckReadExfiltration(t, "traefik.yaml")
	handler := buildDrydockPresetHandler(t, "traefik.yaml")

	cases := []presetCase{
		// Health + metadata (moby client Ping: HEAD, GET fallback).
		{"ping-head", http.MethodHead, "/_ping", "", true},
		{"ping-get", http.MethodGet, "/_ping", "", true},
		{"version", http.MethodGet, "/version", "", true},
		{"info", http.MethodGet, "/info", "", true},
		{"events", http.MethodGet, "/events", "", true},

		// Docker-mode provider.
		{"containers-list", http.MethodGet, "/containers/json", "", true},
		{"container-inspect", http.MethodGet, "/containers/abc/json", "", true},

		// Swarm-mode provider.
		{"networks-list", http.MethodGet, "/networks", "", true},
		{"network-inspect", http.MethodGet, "/networks/abc", "", true},
		{"services-list", http.MethodGet, "/services", "", true},
		{"service-inspect", http.MethodGet, "/services/abc", "", true},
		{"tasks-list", http.MethodGet, "/tasks", "", true},
		{"task-inspect", http.MethodGet, "/tasks/abc", "", true},
		// pswarm.go parseTasks calls NodeInspect for every task carrying a
		// NodeID; moby/moby client v0.4.0 node_inspect.go:27 maps that to
		// GET /nodes/{id}. Without this the task is skipped and the service
		// gets no endpoints.
		{"node-inspect", http.MethodGet, "/nodes/abc", "", true},

		// Version-prefixed forms of the same reads.
		{"v-prefixed-containers-list", http.MethodGet, "/v1.45/containers/json", "", true},
		{"v-prefixed-container-inspect", http.MethodGet, "/v1.45/containers/abc/json", "", true},
		{"v-prefixed-node-inspect", http.MethodGet, "/v1.45/nodes/abc", "", true},

		// Reads Traefik never makes stay denied — the narrowing is a rule
		// list, not a "GET is fine" posture.
		{"container-stats-denied", http.MethodGet, "/containers/abc/stats", "", false},
		{"container-top-denied", http.MethodGet, "/containers/abc/top", "", false},
		{"container-changes-denied", http.MethodGet, "/containers/abc/changes", "", false},
		{"images-list-denied", http.MethodGet, "/images/json", "", false},
		// Traefik calls NodeInspect but never NodeList, so the two-segment
		// /nodes/* rule must not also admit the one-segment list.
		{"nodes-list-denied", http.MethodGet, "/nodes", "", false},

		// The node-ID position is a single "*", which compiles to [^/]* and
		// matches one path segment. moby registers the node routes as
		// GET /nodes/{id}, DELETE /nodes/{id} and POST /nodes/{id}/update
		// (daemon/server/router/swarm/cluster.go), so /nodes/{id}/update is
		// the only node subpath that exists — it must stay denied under
		// every method, proving "*" cannot absorb a trailing segment.
		{"node-update-get-denied", http.MethodGet, "/nodes/abc/update", "", false},
		{"node-update-denied", http.MethodPost, "/nodes/abc/update", "", false},
		{"node-remove-denied", http.MethodDelete, "/nodes/abc", "", false},

		// Writes stay denied.
		{"container-create-denied", http.MethodPost, "/containers/create", "", false},
		{"container-start-denied", http.MethodPost, "/containers/abc/start", "", false},
		{"container-delete-denied", http.MethodDelete, "/containers/abc", "", false},
		{"exec-create-denied", http.MethodPost, "/containers/abc/exec", "", false},
	}
	cases = append(cases, exfilDenialCases...)

	for _, c := range cases {
		fireDrydockCase(t, handler, c)
	}
}

// TestHomepagePresetConformance proves the shipped homepage.yaml admits
// every endpoint the Homepage dashboard actually calls while denying the
// read-exfiltration surface the old "/containers/**" and "/images/**" globs
// let through.
//
// The allow set is taken from gethomepage/homepage main, whose only
// dockerode call sites are src/utils/config/service-helpers.js
// (listContainers, listServices), src/pages/api/docker/status/[...service].js
// (listContainers, container.inspect, getService().inspect, listTasks) and
// src/pages/api/docker/stats/[...service].js (listContainers,
// container.stats, listTasks). dockerode maps those to GET /containers/json,
// GET /containers/{id}/json, GET /containers/{id}/stats, GET /services,
// GET /services/{id} and GET /tasks.
func TestHomepagePresetConformance(t *testing.T) {
	assertPresetDoesNotAckReadExfiltration(t, "homepage.yaml")
	handler := buildDrydockPresetHandler(t, "homepage.yaml")

	cases := []presetCase{
		// Health + metadata.
		{"ping-get", http.MethodGet, "/_ping", "", true},
		{"ping-head", http.MethodHead, "/_ping", "", true},
		{"version", http.MethodGet, "/version", "", true},
		{"info", http.MethodGet, "/info", "", true},
		{"events", http.MethodGet, "/events", "", true},

		// Container reads: list, inspect, stats.
		{"containers-list", http.MethodGet, "/containers/json", "", true},
		{"container-inspect", http.MethodGet, "/containers/abc/json", "", true},
		{"container-stats", http.MethodGet, "/containers/abc/stats", "", true},

		// Image list for the image-info display.
		{"images-list", http.MethodGet, "/images/json", "", true},

		// Swarm reads.
		{"services-list", http.MethodGet, "/services", "", true},
		{"service-inspect", http.MethodGet, "/services/abc", "", true},
		{"tasks-list", http.MethodGet, "/tasks", "", true},
		{"task-inspect", http.MethodGet, "/tasks/abc", "", true},

		// Version-prefixed forms of the same reads.
		{"v-prefixed-containers-list", http.MethodGet, "/v1.45/containers/json", "", true},
		{"v-prefixed-container-stats", http.MethodGet, "/v1.45/containers/abc/stats", "", true},

		// Reads Homepage never makes stay denied.
		{"image-inspect-denied", http.MethodGet, "/images/abc/json", "", false},
		{"image-history-denied", http.MethodGet, "/images/abc/history", "", false},
		{"container-top-denied", http.MethodGet, "/containers/abc/top", "", false},
		{"networks-list-denied", http.MethodGet, "/networks", "", false},
		{"node-inspect-denied", http.MethodGet, "/nodes/abc", "", false},

		// Writes stay denied.
		{"container-create-denied", http.MethodPost, "/containers/create", "", false},
		{"container-start-denied", http.MethodPost, "/containers/abc/start", "", false},
		{"container-delete-denied", http.MethodDelete, "/containers/abc", "", false},
		{"exec-create-denied", http.MethodPost, "/containers/abc/exec", "", false},
	}
	cases = append(cases, exfilDenialCases...)

	for _, c := range cases {
		fireDrydockCase(t, handler, c)
	}
}
