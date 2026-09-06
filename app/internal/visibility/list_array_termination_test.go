package visibility

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/testhelp"
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
//
// The cases come from testhelp.JSONArrayTerminationCases because
// internal/responsefilter streams the same Docker list bodies through a
// decoder of its own, and two decoders that have to agree eventually will not.
// TestArrayTerminationParityWithVisibility runs this table over that package's
// routes; a case added here is a case that package has to answer too.
func TestPatternListRejectsUnterminatedArrayAndTrailingBytes(t *testing.T) {
	t.Parallel()

	for _, tt := range testhelp.JSONArrayTerminationCases() {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			wantCode := http.StatusBadGateway
			if tt.Accept {
				wantCode = http.StatusOK
			}
			upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, tt.Body)
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

			if rec.Code != wantCode {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, wantCode, rec.Body.String())
			}
			if tt.Accept {
				return
			}
			if meta.ReasonCode != reasonCodeVisibilityPolicyLookupFailed {
				t.Errorf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeVisibilityPolicyLookupFailed)
			}
			if body := rec.Body.String(); body == tt.Body {
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
