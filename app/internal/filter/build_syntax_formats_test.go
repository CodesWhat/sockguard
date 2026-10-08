package filter

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMiddlewareBuildSyntaxFormats(t *testing.T) {

	const frontend = "example.invalid/inert-compiler:review"
	cases := []struct{ name, dockerfile string }{
		{"hash", "# syntax=" + frontend + "\nFROM scratch\n"},
		{"BOM", "\ufeff# syntax=" + frontend + "\nFROM scratch\n"},
		{"shebang", "#!/usr/bin/env builder\n# syntax=" + frontend + "\nFROM scratch\n"},
		{"BOM and shebang", "\ufeff#!/usr/bin/env builder\n# syntax=" + frontend + "\n"},
		{"slash", "// syntax=" + frontend + "\n"},
		{"JSON", `{"syntax":"` + frontend + `"}`},
		{"check", "# check=skip=all\n# syntax=" + frontend + "\nFROM scratch\n"},
	}

	for _, tc := range cases {
		for _, allowRun := range []bool{false, true} {
			name := tc.name + "/restricted"
			if allowRun {
				name = tc.name + "/allow RUN"
			}
			t.Run(name, func(t *testing.T) {
				rule, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/build", Action: ActionAllow})
				if err != nil {
					t.Fatal(err)
				}
				forwarded := false
				context := mustBuildContextTar(t, "Dockerfile", tc.dockerfile)
				handler := MiddlewareWithOptions([]*CompiledRule{rule}, testLogger(), Options{
					PolicyConfig: PolicyConfig{
						DenyResponseVerbosity: DenyResponseVerbosityVerbose,
						Build:                 BuildOptions{AllowRunInstructions: allowRun},
					},
				})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					forwarded = true
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(body, context) {
						t.Fatal("forwarded build context changed")
					}
					w.WriteHeader(http.StatusOK)
				}))
				req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(context))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if allowRun {
					if rec.Code != http.StatusOK || !forwarded {
						t.Fatalf("status = %d, forwarded = %v; body: %s", rec.Code, forwarded, rec.Body.String())
					}
					return
				}
				if rec.Code != http.StatusForbidden || forwarded {
					t.Fatalf("status = %d, forwarded = %v; want denied without forwarding", rec.Code, forwarded)
				}
				var denial DenialResponse
				if err := json.NewDecoder(rec.Body).Decode(&denial); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(denial.Reason, "syntax frontend") {
					t.Fatalf("reason = %q, want syntax frontend denial", denial.Reason)
				}
			})
		}
	}
}
