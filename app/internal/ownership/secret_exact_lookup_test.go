package ownership

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/upstreamflavor"
)

func TestSecretCreateDistinguishesIDPrefixFromExactForeignSecret(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		existingName string
		wantStatus   int
	}{
		{"ID prefix only", "other-secret", http.StatusAccepted},
		{"exact name", "cafez", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			inspects := 0
			transport := buildImageTransport(func(r *http.Request) (*http.Response, error) {
				inspects++
				if r.Method != http.MethodGet || r.URL.Path != "/secrets/cafez" {
					t.Errorf("unexpected inspect: %s %s", r.Method, r.URL.Path)
				}
				body := `{"ID":"cafez11111111111111111111","Spec":{"Name":"` + tc.existingName + `","Labels":{"` + DefaultLabelKey + `":"team-b"}}}`
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			forwarded := false
			handler := MiddlewareWithRoundTripper(transport, testLogger(), Options{Owner: "team-a", LabelKey: DefaultLabelKey, UpstreamFlavor: upstreamflavor.Podman})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded = true
				var labels map[string]string
				if err := json.Unmarshal([]byte(r.URL.Query().Get("labels")), &labels); err != nil || labels[DefaultLabelKey] != "team-a" {
					t.Errorf("forwarded labels = %v, error = %v", labels, err)
				}
				w.WriteHeader(http.StatusAccepted)
			}))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/libpod/secrets/create?name=cafez&replace=true", strings.NewReader("payload")))
			if rec.Code != tc.wantStatus || forwarded != (tc.wantStatus == http.StatusAccepted) || inspects != 1 {
				t.Fatalf("status=%d forwarded=%v inspects=%d; want status=%d; body=%s", rec.Code, forwarded, inspects, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestExactSecretLookupContext(t *testing.T) {
	if exactSecretLookup(context.Background()) {
		t.Error("a plain context asks for an exact lookup")
	}
	if !exactSecretLookup(withExactSecretLookup(context.Background())) {
		t.Error("withExactSecretLookup did not mark the context")
	}
}

func TestSecretLookupAmbiguousPrefix(t *testing.T) {
	if !secretLookupAmbiguousPrefix(strings.NewReader(`{"message":"more than one result secret with prefix b0: ambiguous"}`)) {
		t.Error("the ambiguous-prefix error was not recognized")
	}
	if secretLookupAmbiguousPrefix(strings.NewReader(`{"message":"database is locked"}`)) {
		t.Error("an unrelated lookup failure was read as an ambiguous prefix")
	}
}

func TestDecodeExactSecret(t *testing.T) {
	const body = `{"ID":"b0b0b0b0b0b0b0b0b0b0b0b02","Spec":{"Name":"theirs","Labels":{"com.sockguard.owner":"team-b"}}}`
	tests := []struct {
		name       string
		body       string
		identifier string
		found      bool
		wantErr    bool
	}{
		{"exact name", body, "theirs", true, false},
		{"exact ID", body, "b0b0b0b0b0b0b0b0b0b0b0b02", true, false},
		{"ID prefix only", body, "b0b0", false, false},
		{"malformed body", `{`, "theirs", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels, found, err := decodeExactSecret(strings.NewReader(tt.body), tt.identifier)
			if (err != nil) != tt.wantErr || found != tt.found {
				t.Fatalf("decodeExactSecret() = (%v, %v, %v), want found=%v err=%v", labels, found, err, tt.found, tt.wantErr)
			}
			if found && labels["com.sockguard.owner"] != "team-b" {
				t.Errorf("labels = %v, want the secret's labels", labels)
			}
		})
	}
}
