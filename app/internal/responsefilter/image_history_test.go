package responsefilter

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
)

const imageHistoryUpstream = `[` +
	`{"Id":"sha256:a","Created":1,"CreatedBy":"/bin/sh -c #(nop)  ENV API_KEY=abc123","Size":0},` +
	`{"Id":"sha256:b","Created":2,"CreatedBy":"ENV TOKEN_X=1 # buildkit","Size":0},` +
	`{"Id":"sha256:c","Created":3,"CreatedBy":"ARG DB_PASS=hunter2 # buildkit","Size":0},` +
	`{"Id":"sha256:d","Created":4,"CreatedBy":"RUN apt-get update # buildkit","Size":123},` +
	`{"Id":"sha256:e","Created":5,"CreatedBy":"/bin/sh -c #(nop)  ENVIRONMENT=x","Size":0}]`

func TestImageHistoryRedactsEnvInstructions(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/v1.53/images/myapp:latest/history", "/v1.53/images/ghcr.io/org/app:1/history", "/v5.0.0/libpod/images/myapp:latest/history"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			resp := newResponseForTest(t, http.MethodGet, path, imageHistoryUpstream)
			if err := New(Options{RedactContainerEnv: true}).ModifyResponse(resp); err != nil {
				t.Fatalf("ModifyResponse() error = %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			var got []map[string]any
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatalf("decode: %v: %s", err, body)
			}
			want := []string{"ENV <redacted>", "ENV <redacted>", "ARG <redacted>", "RUN apt-get update # buildkit", "/bin/sh -c #(nop)  ENVIRONMENT=x"}
			if len(got) != len(want) {
				t.Fatalf("len = %d, want %d", len(got), len(want))
			}
			for i, w := range want {
				if got[i]["CreatedBy"] != w {
					t.Fatalf("entry %d CreatedBy = %v, want %q", i, got[i]["CreatedBy"], w)
				}
			}
			if got[3]["Size"] != float64(123) || got[0]["Id"] != "sha256:a" {
				t.Fatalf("other fields changed: %#v", got)
			}
		})
	}
}

func TestImageHistoryUntouchedWhenRedactionOff(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/v1.53/images/myapp/history", "/v5.0.0/libpod/images/myapp/history"} {
		resp := newResponseForTest(t, http.MethodGet, path, imageHistoryUpstream)
		if err := New(Options{RedactMountPaths: true}).ModifyResponse(resp); err != nil {
			t.Fatalf("ModifyResponse() error = %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != imageHistoryUpstream {
			t.Fatalf("%s: body changed: %s", path, body)
		}
	}
}

func TestImageHistoryMalformedBodyFailsClosed(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/v1.53/images/myapp/history", "/v5.0.0/libpod/images/myapp/history"} {
		resp := newResponseForTest(t, http.MethodGet, path, `[{"CreatedBy":`)
		err := New(Options{RedactContainerEnv: true}).ModifyResponse(resp)
		if !errors.Is(err, ErrResponseRejected) {
			t.Fatalf("%s: error = %v, want ErrResponseRejected", path, err)
		}
	}
}
