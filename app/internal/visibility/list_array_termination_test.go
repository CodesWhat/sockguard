package visibility

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/logging"
)

// TestPatternListRejectsUnterminatedArrayAndTrailingBytes pins that the
// element loop is not the whole parse. It ends on dec.More(), which is false
// both when the array closed and when the input ran out, so without the
// explicit closing-delimiter and trailing-byte checks a body the filter could
// not account for in full was rewritten into a well-formed 200 the client read
// as the complete list.
//
// Elements are still checked individually, so this was never a confidentiality
// bypass. It made the documented fail-closed claim narrower than stated, which
// is what these cases hold to.
func TestPatternListRejectsUnterminatedArrayAndTrailingBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		body     string
		wantCode int
	}{
		{name: "open bracket only", body: `[`, wantCode: http.StatusBadGateway},
		{name: "unclosed object inside the array", body: `[{`, wantCode: http.StatusBadGateway},
		{name: "element decoded but array never closed", body: `[{"Id":"a"}`, wantCode: http.StatusBadGateway},
		{name: "trailing garbage after the array", body: `[{"Id":"a"}]garbage`, wantCode: http.StatusBadGateway},
		{name: "second value after the array", body: `[{"Id":"a"}] [{"Id":"b"}]`, wantCode: http.StatusBadGateway},
		{name: "trailing comma after the array", body: `[{"Id":"a"}],`, wantCode: http.StatusBadGateway},
		{name: "trailing null after the array", body: `[{"Id":"a"}]null`, wantCode: http.StatusBadGateway},
		{name: "trailing whitespace is still an array", body: "[{\"Id\":\"a\"}]   \n\t", wantCode: http.StatusOK},
		{name: "closed array", body: `[{"Id":"a"}]`, wantCode: http.StatusOK},
		{name: "empty array", body: `[]`, wantCode: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, tt.body)
			})
			// A policy with an image axis only: the container items above
			// carry no Image field, so nothing is filtered out and the test
			// isolates the parse from the pattern matching.
			handler := middlewareWithDeps(testVisibilityLogger(),
				Options{ImagePatterns: []string{"*"}}, visibilityDeps{})(upstream)

			meta := &logging.RequestMeta{}
			req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantCode, rec.Body.String())
			}
			if tt.wantCode != http.StatusBadGateway {
				return
			}
			if meta.ReasonCode != reasonCodeVisibilityPolicyLookupFailed {
				t.Errorf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeVisibilityPolicyLookupFailed)
			}
			if body := rec.Body.String(); body == tt.body {
				t.Errorf("upstream body was relayed instead of refused: %s", body)
			}
		})
	}
}

// TestPatternListWarnModeStillFailsClosedOnUnterminatedArray: the refusal is a
// response-side control, not a policy verdict warn mode stages, exactly like
// the non-array case beside it.
func TestPatternListWarnModeStillFailsClosedOnUnterminatedArray(t *testing.T) {
	t.Parallel()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `[{"Names":["/visible-web"]}]trailing`)
	})
	handler := middlewareWithDeps(testVisibilityLogger(),
		Options{NamePatterns: []string{"visible-*"}}, visibilityDeps{})(upstream)

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), &logging.RequestMeta{RolloutMode: "warn"}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d under warn mode; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}
}
