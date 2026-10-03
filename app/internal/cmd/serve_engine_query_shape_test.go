package cmd

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/config"
	"github.com/codeswhat/sockguard/v2/app/internal/upstreamflavor"
)

// podmanSchemaKeys returns the spellings of name present in query, in the
// order a Podman-shaped test daemon visits them.
//
// Podman decodes its query structs with gorilla/schema v1.4.1. Decoder.Decode
// ranges over the url.Values map, and structInfo.get matches each key to a
// field with strings.EqualFold, so every spelling of a parameter writes the
// same field and the one visited last wins. Go randomizes that order per
// request, and a client can resend until it gets the order it wants, so the
// daemons here always visit the exact spelling first and any other spelling
// after it. That is the order that favors the client.
func podmanSchemaKeys(query url.Values, name string) []string {
	var exact, others []string
	for key := range query {
		switch {
		case key == name:
			exact = append(exact, key)
		case strings.EqualFold(key, name):
			others = append(others, key)
		}
	}
	slices.Sort(others)
	return append(exact, others...)
}

// podmanSchemaScalar is the value gorilla/schema leaves in a string field
// tagged name: the last value of each spelling, with an empty one leaving the
// field as it was.
func podmanSchemaScalar(query url.Values, name string) string {
	field := ""
	for _, key := range podmanSchemaKeys(query, name) {
		values := query[key]
		if len(values) == 0 || values[len(values)-1] == "" {
			continue
		}
		field = values[len(values)-1]
	}
	return field
}

// engineChainVersion answers GET /version the way each engine names itself in
// Components, which is all the upstream.flavor probe reads.
func engineChainVersion(podman bool) map[string]any {
	engine := "Engine"
	if podman {
		engine = "Podman Engine"
	}
	return map[string]any{"Components": []map[string]string{{"Name": engine}}}
}

// newEngineChain serves daemon on a unix socket and returns the address of
// the production handler chain in front of it. The engine is resolved the way
// serve resolves it, with the production probe.
func newEngineChain(t *testing.T, label string, daemon http.Handler, configure func(*config.Config)) string {
	t.Helper()

	socketPath := shortSocketPath(t, label)
	startUnixHTTPUpstream(t, socketPath, daemon)

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	configure(&cfg)

	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	logger := newDiscardLogger()
	deps := newServeTestDeps()
	deps.detectUpstreamFlavor = upstreamflavor.Detect
	runtime, err := newServeRuntime(&cfg, logger, deps)
	if err != nil {
		t.Fatalf("newServeRuntime: %v", err)
	}
	if err := resolveUpstreamFlavorForRuntime(t.Context(), deps, runtime, &cfg, logger); err != nil {
		t.Fatalf("resolve upstream flavor: %v", err)
	}
	handler, teardown, _ := buildServeHandlerChainWithRuntime(serveHandlerBuild{
		Cfg:     &cfg,
		Logger:  logger,
		Rules:   rules,
		Deps:    deps,
		Runtime: runtime,
	})
	t.Cleanup(teardown)
	addr, _ := startProxyChainServer(t, handler)
	return addr
}
