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
	`{"Id":"sha256:e","Created":5,"CreatedBy":"/bin/sh -c #(nop)  ENVIRONMENT=x","Size":0},` +
	`{"Id":"sha256:f","Created":6,"CreatedBy":"|2 API_KEY=abc123 DB_PASS=hunter2 /bin/sh -c make build","Size":0},` +
	`{"Id":"sha256:g","Created":7,"CreatedBy":"RUN |1 TOKEN_X=s3cret /bin/sh -c make # buildkit","Size":0}]`

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
			want := []string{"ENV <redacted>", "ENV <redacted>", "ARG <redacted>", "RUN apt-get update # buildkit", "/bin/sh -c #(nop)  ENVIRONMENT=x",
				"<redacted>", "<redacted>"}
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

func TestRedactHistoryCreatedByBuildArgShapes(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"ENV":                               "ENV",
		"ARG":                               "ARG",
		"|":                                 "|",
		"|1":                                "<redacted>",
		"|12":                               "<redacted>",
		"|9 API_KEY=secret /bin/sh -c echo": "<redacted>",
		"|1 K=v a b /bin/sh -c echo":        "<redacted>",
		"|1 K=v /usr/bin/zsh -c echo":       "<redacted>",
		"|0 /bin/sh -c echo":                "<redacted>",
		"| not a prefix":                    "| not a prefix",
		"RUN echo |1 K=v":                   "RUN echo |1 K=v",
		"COPY . /app # buildkit":            "COPY . /app # buildkit",
	} {
		if got := redactHistoryCreatedBy(in); got != want {
			t.Errorf("redactHistoryCreatedBy(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLibpodImageHistoryRedactsCamelCaseKey(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"createdBy", "CreatedBy", "created_by"} {
		body := `[{"id":"a","` + key + `":"ENV SECRET=1"},{"id":"b","` + key + `":"|1 K=v /bin/sh -c x"}]`
		resp := newResponseForTest(t, http.MethodGet, "/v5.0.0/libpod/images/app/history", body)
		if err := New(Options{RedactContainerEnv: true}).ModifyResponse(resp); err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		var got []map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		if got[0][key] != "ENV <redacted>" || got[1][key] != "<redacted>" {
			t.Fatalf("key %s: body = %s", key, raw)
		}
	}
}

func TestImageHistoryHidesAmbiguousArgumentAndCommandBoundaries(t *testing.T) {
	t.Parallel()
	for _, createdBy := range []string{
		"|1 SECRET=before /bin/sh -c secret-tail /bin/sh -c real-command",
		"RUN |1 SECRET=before /bin/sh -c secret-tail /bin/sh -c real-command # buildkit",
		"|2 FIRST=a value with spaces SECOND=tail /bin/sh -c true",
		"|1 SECRET=single' double\" quotes /bin/sh -c private tail",
		"|1 SECRET=first\nsecond /bin/sh -c command",
	} {
		for _, path := range []string{"/images/app/history", "/libpod/images/app/history"} {
			t.Run(path+"/"+createdBy, func(t *testing.T) {
				t.Parallel()
				original := []map[string]any{{"CreatedBy": createdBy, "Id": "image", "Size": 7}}
				raw, err := json.Marshal(original)
				if err != nil {
					t.Fatal(err)
				}
				resp := newResponseForTest(t, http.MethodGet, path, string(raw))
				if err := New(Options{RedactContainerEnv: true}).ModifyResponse(resp); err != nil {
					t.Fatal(err)
				}
				var entries []map[string]any
				if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if entries[0]["CreatedBy"] != "<redacted>" || entries[0]["Id"] != "image" || entries[0]["Size"] != float64(7) {
					t.Fatalf("history entry = %#v", entries[0])
				}
			})
		}
	}
}
