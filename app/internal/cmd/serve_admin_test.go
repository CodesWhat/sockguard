package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/admin"
	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
)

// adminTestRules produces a single allow rule so buildServeHandler succeeds
// even when the test config keeps default-deny behavior. The interceptor
// short-circuits /admin/validate before this list is ever consulted.
func adminTestRules(t *testing.T) []*filter.CompiledRule {
	t.Helper()
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "admin-up")
	compiled, err := validateAndCompileRules(&cfg)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	return compiled
}

func TestBuildAdminValidatorAcceptsDefaultsYAML(t *testing.T) {
	validator := buildAdminValidator(newDiscardLogger())

	yaml := `
listen:
  socket: /tmp/sockguard.sock
upstream:
  socket: /var/run/docker.sock
rules:
  - match: { method: GET, path: "/_ping" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
`
	resp := validator([]byte(yaml))
	if !resp.OK {
		t.Fatalf("OK = false, want true; errors=%v", resp.Errors)
	}
	if resp.Rules != 2 {
		t.Fatalf("rules = %d, want 2", resp.Rules)
	}
	if resp.Profiles != 0 {
		t.Fatalf("profiles = %d, want 0", resp.Profiles)
	}
}

func TestBuildAdminValidatorReportsValidationErrors(t *testing.T) {
	validator := buildAdminValidator(newDiscardLogger())

	// Invalid action — validator must reject without rule compilation.
	yaml := `
upstream:
  socket: /var/run/docker.sock
rules:
  - match: { method: GET, path: "/_ping" }
    action: maybe
`
	resp := validator([]byte(yaml))
	if resp.OK {
		t.Fatalf("OK = true, want false on invalid action")
	}
	if len(resp.Errors) == 0 {
		t.Fatalf("Errors empty; expected at least one entry")
	}
	joined := strings.Join(resp.Errors, " | ")
	if !strings.Contains(joined, "action") {
		t.Fatalf("errors do not mention action: %s", joined)
	}
}

func TestBuildAdminValidatorReportsMalformedYAML(t *testing.T) {
	validator := buildAdminValidator(newDiscardLogger())

	resp := validator([]byte("rules: [bad-yaml-here"))
	if resp.OK {
		t.Fatalf("OK = true on malformed YAML, want false")
	}
	if len(resp.Errors) == 0 || !strings.HasPrefix(resp.Errors[0], "parse: ") {
		t.Fatalf("expected parse error prefix, got %v", resp.Errors)
	}
}

func TestBuildAdminValidatorReportsCompatActive(t *testing.T) {
	// INFO=1 only adds an allow rule for /info, which has no read-exfil or
	// blind-write implications, so the validator runs cleanly while still
	// exercising the compat-detection code path.
	t.Setenv("INFO", "1")
	validator := buildAdminValidator(newDiscardLogger())

	resp := validator([]byte(""))
	if !resp.OK {
		t.Fatalf("OK = false, want true; errors=%v", resp.Errors)
	}
	if !resp.CompatActive {
		t.Fatalf("compat_active = false, want true under INFO=1 env")
	}
}

func TestServeHandlerShortCircuitsAdminValidate(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "admin-svc")
	cfg.Admin.Enabled = true
	cfg.Admin.Path = "/admin/validate"
	cfg.Admin.MaxRequestBytes = 4096

	rules := adminTestRules(t)
	handler := buildServeHandler(&cfg, newDiscardLogger(), nil, rules, newServeTestDeps())

	body := strings.NewReader("rules:\n  - match: { method: GET, path: /_ping }\n    action: allow\n")
	req := httptest.NewRequest(http.MethodPost, "/admin/validate", body)
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d. body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp admin.ValidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if !resp.OK {
		t.Fatalf("ok=false errors=%v", resp.Errors)
	}
}

func TestServeHandlerAdminDisabledFallsThrough(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "admin-off")
	cfg.Admin.Enabled = false

	rules := adminTestRules(t)
	handler := buildServeHandler(&cfg, newDiscardLogger(), nil, rules, newServeTestDeps())

	req := httptest.NewRequest(http.MethodPost, "/admin/validate", bytes.NewReader([]byte("rules: []")))
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// With admin disabled the request passes through to the filter, which
	// has no allow rule for /admin/validate and denies it.
	if rec.Code == http.StatusOK {
		t.Fatalf("expected non-200 when admin disabled, got %d", rec.Code)
	}
}

func TestServeHandlerAdminRejectsGET(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "admin-get")
	cfg.Admin.Enabled = true

	rules := adminTestRules(t)
	handler := buildServeHandler(&cfg, newDiscardLogger(), nil, rules, newServeTestDeps())

	req := httptest.NewRequest(http.MethodGet, "/admin/validate", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestSplitValidationErrorPassesThroughNonValidation(t *testing.T) {
	got := splitValidationError(errAdminTest{msg: "boom"})
	if len(got) != 1 || got[0] != "boom" {
		t.Fatalf("got %#v, want [boom]", got)
	}
}

type errAdminTest struct{ msg string }

func (e errAdminTest) Error() string { return e.msg }
