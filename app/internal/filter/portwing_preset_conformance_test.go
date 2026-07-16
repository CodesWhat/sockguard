package filter_test

import (
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
)

func TestPortwingExecPresetConformance(t *testing.T) {
	t.Run("base preset keeps exec denied", func(t *testing.T) {
		handler := buildPortwingPresetHandler(t, "portwing.yaml")
		fireDrydockCase(t, handler, presetCase{
			name: "exec-create-denied", method: http.MethodPost,
			path: "/containers/abc/exec", body: `{"Cmd":["sh","-c","id"]}`, allowed: false,
		})
	})

	t.Run("exec preset honors explicit blind-write opt-in", func(t *testing.T) {
		handler := buildPortwingPresetHandler(t, "portwing-with-exec.yaml")
		fireDrydockCase(t, handler, presetCase{
			name: "interactive-exec-allowed", method: http.MethodPost,
			path: "/containers/abc/exec", body: `{"Cmd":["sh","-c","id"]}`, allowed: true,
		})
		fireDrydockCase(t, handler, presetCase{
			name: "privileged-exec-denied", method: http.MethodPost,
			path: "/containers/abc/exec", body: `{"Cmd":["sh"],"Privileged":true}`, allowed: false,
		})
	})
}

func buildPortwingPresetHandler(t *testing.T, presetFile string) http.Handler {
	t.Helper()

	cfg, err := config.Load(filepath.Join("..", "..", "configs", presetFile))
	if err != nil {
		t.Fatalf("load preset %s: %v", presetFile, err)
	}

	policy := cfg.RequestBody.ToFilterOptions()
	policy.DenyResponseVerbosity = filter.DenyResponseVerbosityVerbose
	policy.Exec.AllowBlindWrites = cfg.InsecureAllowBodyBlindWrites

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return filter.MiddlewareWithOptions(
		compileDrydockRules(t, cfg.Rules),
		logger,
		filter.Options{PolicyConfig: policy},
	)(next)
}
