package ownership

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/filter"
	"github.com/codeswhat/sockguard/v2/app/internal/logging"
)

// ambiguousBodyKeyOutcome is one request through owner isolation under a
// rollout mode, and what came out the other side.
type ambiguousBodyKeyOutcome struct {
	status    int
	message   string
	forwarded []string
	meta      *logging.RequestMeta
}

func sendThroughOwnerIsolation(t *testing.T, mode, target, body string) ambiguousBodyKeyOutcome {
	t.Helper()
	var out ambiguousBodyKeyOutcome
	handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a", LabelKey: DefaultLabelKey}, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read forwarded body: %v", err)
		}
		out.forwarded = append(out.forwarded, string(got))
		w.WriteHeader(http.StatusCreated)
	}))

	out.meta = &logging.RequestMeta{RolloutMode: mode}
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req = req.WithContext(logging.WithMeta(req.Context(), out.meta))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	out.status = rec.Code
	var denial struct {
		Message string `json:"message"`
	}
	if rec.Code != http.StatusCreated {
		if err := json.Unmarshal(rec.Body.Bytes(), &denial); err != nil {
			t.Fatalf("decode denial %q: %v", rec.Body.String(), err)
		}
	}
	out.message = denial.Message
	return out
}

// TestAmbiguousBodyKeyFollowsRolloutMode covers a body with a key holding a
// character the engines' JSON decoders match differently, once it reaches
// owner isolation. The inspectors refuse it as request_body_ambiguous, and on
// a profile in warn or audit they record that and forward it.
//
// Owner isolation then refused it outright, whatever the mode: a create with
// a Turkish label key that was answered 201 under warn before the refusal
// existed came back 400. It now does what the inspectors do. Enforce refuses
// under their reason code, and warn and audit record the would-be denial and
// forward the body stamped like any other.
func TestAmbiguousBodyKeyFollowsRolloutMode(t *testing.T) {
	t.Parallel()
	ambiguous := func(key, codePoint string) string {
		return "request body denied: ambiguous JSON object key " + key + ": " + codePoint + " matches a field name in some JSON decoders and not in others"
	}
	tests := []struct {
		name       string
		target     string
		body       string
		wantReason string
		// wantForwarded is the body warn and audit send on: the client's,
		// with the owner label, re-marshaled with its keys sorted.
		wantForwarded string
	}{
		{
			name:          "container create with a dotted capital I in a label key",
			target:        "/v1.45/containers/create",
			body:          "{\"Labels\":{\"\u0130stanbul\":\"1\"},\"Cmd\":[\"true\"]}",
			wantReason:    ambiguous(`"\u0130stanbul"`, "U+0130"),
			wantForwarded: "{\"Cmd\":[\"true\"],\"Labels\":{\"com.sockguard.owner\":\"team-a\",\"\u0130stanbul\":\"1\"}}",
		},
		{
			name:          "volume create with a dotted capital I in a label key",
			target:        "/v1.45/volumes/create",
			body:          "{\"Name\":\"v\",\"Labels\":{\"\u0130\":\"1\"}}",
			wantReason:    ambiguous(`"\u0130"`, "U+0130"),
			wantForwarded: "{\"Labels\":{\"com.sockguard.owner\":\"team-a\",\"\u0130\":\"1\"},\"Name\":\"v\"}",
		},
		{
			name:          "native container create with a long s in an env name",
			target:        "/v5.0.0/libpod/containers/create",
			body:          "{\"name\":\"c\",\"env\":{\"\u017f\":\"1\"}}",
			wantReason:    ambiguous(`"\u017f"`, "U+017F"),
			wantForwarded: "{\"env\":{\"\u017f\":\"1\"},\"labels\":{\"com.sockguard.owner\":\"team-a\"},\"name\":\"c\"}",
		},
		{
			name:          "native pod create with a dotted capital I in a field name",
			target:        "/v5.0.0/libpod/pods/create",
			body:          "{\"name\":\"p\",\"p\u0130dns\":{\"nsmode\":\"host\"}}",
			wantReason:    ambiguous(`"p\u0130dns"`, "U+0130"),
			wantForwarded: "{\"labels\":{\"com.sockguard.owner\":\"team-a\"},\"name\":\"p\",\"p\u0130dns\":{\"nsmode\":\"host\"}}",
		},
		{
			name:          "container create with a Kelvin sign in a HostConfig key",
			target:        "/v1.45/containers/create",
			body:          "{\"Cmd\":[\"true\"],\"HostConfig\":{\"Networ\u212aMode\":\"bridge\"}}",
			wantReason:    ambiguous(`"Networ\u212aMode"`, "U+212A"),
			wantForwarded: "{\"Cmd\":[\"true\"],\"HostConfig\":{\"Networ\u212aMode\":\"bridge\"},\"Labels\":{\"com.sockguard.owner\":\"team-a\"}}",
		},
		{
			// encoding/json reads this key as Labels and Podman 6's decoder
			// doesn't. The stamp can't sit under it, or Podman 6 would
			// create the container with no owner label, so the labels are
			// forwarded under the exact key, which every decoder binds.
			name:          "container create that spells Labels with a long s",
			target:        "/v1.45/containers/create",
			body:          "{\"Cmd\":[\"true\"],\"Label\u017f\":{\"a\":\"1\",\"com.sockguard.owner\":\"team-b\"}}",
			wantReason:    ambiguous(`"Label\u017f"`, "U+017F"),
			wantForwarded: `{"Cmd":["true"],"Labels":{"a":"1","com.sockguard.owner":"team-a"}}`,
		},
		{
			name:          "native container create that spells labels with a long s",
			target:        "/v5.0.0/libpod/containers/create",
			body:          "{\"name\":\"c\",\"label\u017f\":{\"a\":\"1\"}}",
			wantReason:    ambiguous(`"label\u017f"`, "U+017F"),
			wantForwarded: `{"labels":{"a":"1","com.sockguard.owner":"team-a"},"name":"c"}`,
		},
	}
	for _, tt := range tests {
		for _, mode := range []string{"", "enforce", "warn", "audit"} {
			t.Run(tt.name+"/mode="+mode, func(t *testing.T) {
				t.Parallel()
				out := sendThroughOwnerIsolation(t, mode, tt.target, tt.body)

				if mode == "warn" || mode == "audit" {
					if out.status != http.StatusCreated {
						t.Fatalf("status = %d, want %d; message: %s", out.status, http.StatusCreated, out.message)
					}
					if len(out.forwarded) != 1 || out.forwarded[0] != tt.wantForwarded {
						t.Fatalf("forwarded %q, want %q", out.forwarded, tt.wantForwarded)
					}
					if out.meta.Decision != logging.DecisionWouldDeny || out.meta.ReasonCode != filter.ReasonCodeRequestBodyAmbiguous || out.meta.Reason != tt.wantReason {
						t.Fatalf("decision/reason code/reason = %q/%q/%q, want %q/%q/%q", out.meta.Decision, out.meta.ReasonCode, out.meta.Reason, logging.DecisionWouldDeny, filter.ReasonCodeRequestBodyAmbiguous, tt.wantReason)
					}
					return
				}

				if out.status != http.StatusBadRequest || len(out.forwarded) != 0 {
					t.Fatalf("status = %d, forwarded %q, want a 400 and nothing forwarded", out.status, out.forwarded)
				}
				if out.message != tt.wantReason {
					t.Fatalf("message = %q, want %q", out.message, tt.wantReason)
				}
				if out.meta.Decision != logging.DecisionDeny || out.meta.ReasonCode != filter.ReasonCodeRequestBodyAmbiguous || out.meta.Reason != tt.wantReason {
					t.Fatalf("decision/reason code/reason = %q/%q/%q, want %q/%q/%q", out.meta.Decision, out.meta.ReasonCode, out.meta.Reason, logging.DecisionDeny, filter.ReasonCodeRequestBodyAmbiguous, tt.wantReason)
				}
			})
		}
	}
}

// TestRepeatedBodyKeyIsRefusedInEveryRolloutMode pins the refusals the mode
// doesn't soften. The body owner isolation forwards is re-marshaled from a
// map, which sorts the keys, and when an engine reads two of them as one
// field the order decides which it honors. So a body with such a pair can't
// be forwarded as the client sent it, in any mode.
//
// A pair that differs in letter case has always been refused for that. A key
// beside the same key spelled with U+0130 is the same pair to Podman 6, whose
// decoder lowers both: `privileged` sorts ahead of its dotted spelling, so
// the re-marshal would hand Podman 6 the dotted one's value whichever order
// the client wrote them in.
func TestRepeatedBodyKeyIsRefusedInEveryRolloutMode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		target      string
		body        string
		wantMessage string
	}{
		{
			name:        "a key in two letter cases",
			target:      "/v1.45/containers/create",
			body:        `{"Image":"alpine","HostConfig":{"NetworkMode":"bridge"},"hostconfig":{"NetworkMode":"container:victim"}}`,
			wantMessage: "ambiguous request body: duplicate case-variant JSON keys",
		},
		{
			name:        "a key beside its dotted capital I spelling",
			target:      "/v5.0.0/libpod/containers/create",
			body:        "{\"image\":\"alpine\",\"pr\u0130v\u0130leged\":true,\"privileged\":false}",
			wantMessage: `ambiguous request body: JSON object keys "privileged" and "pr\u0130v\u0130leged" lowercase to the same name, which some JSON decoders read as one key given twice`,
		},
		{
			name:        "the same pair under HostConfig",
			target:      "/v1.45/containers/create",
			body:        "{\"Image\":\"alpine\",\"HostConfig\":{\"PidMode\":\"private\",\"P\u0130dMode\":\"host\"}}",
			wantMessage: `ambiguous request body: JSON object keys "PidMode" and "P\u0130dMode" lowercase to the same name, which some JSON decoders read as one key given twice`,
		},
	}
	for _, tt := range tests {
		for _, mode := range []string{"", "enforce", "warn", "audit"} {
			t.Run(tt.name+"/mode="+mode, func(t *testing.T) {
				t.Parallel()
				out := sendThroughOwnerIsolation(t, mode, tt.target, tt.body)
				if out.status != http.StatusBadRequest || len(out.forwarded) != 0 {
					t.Fatalf("status = %d, forwarded %q, want a 400 and nothing forwarded", out.status, out.forwarded)
				}
				if !strings.HasPrefix(out.message, tt.wantMessage) {
					t.Fatalf("message = %q, want it to start %q", out.message, tt.wantMessage)
				}
				if out.meta.Decision != logging.DecisionDeny || out.meta.ReasonCode != reasonCodeOwnerRequestInvalid {
					t.Fatalf("decision/reason code = %q/%q, want %q/%q", out.meta.Decision, out.meta.ReasonCode, logging.DecisionDeny, reasonCodeOwnerRequestInvalid)
				}
			})
		}
	}
}

// TestDataMapEntriesThatLowerAlikeAreNotARepeat keeps the pair above from
// reaching into a map the client fills in. No decoder folds or lowers a map's
// keys, so two labels that lower alike are two labels, and the body follows
// the rollout mode for the character one of them holds.
func TestDataMapEntriesThatLowerAlikeAreNotARepeat(t *testing.T) {
	t.Parallel()
	const body = "{\"Cmd\":[\"true\"],\"Labels\":{\"il\":\"1\",\"\u0130l\":\"2\"}}"
	out := sendThroughOwnerIsolation(t, "warn", "/v1.45/containers/create", body)
	if out.status != http.StatusCreated {
		t.Fatalf("status = %d, want %d; message: %s", out.status, http.StatusCreated, out.message)
	}
	if want := "{\"Cmd\":[\"true\"],\"Labels\":{\"com.sockguard.owner\":\"team-a\",\"il\":\"1\",\"\u0130l\":\"2\"}}"; len(out.forwarded) != 1 || out.forwarded[0] != want {
		t.Fatalf("forwarded %q, want %q", out.forwarded, want)
	}
	if out.meta.ReasonCode != filter.ReasonCodeRequestBodyAmbiguous {
		t.Fatalf("reason code = %q, want %q", out.meta.ReasonCode, filter.ReasonCodeRequestBodyAmbiguous)
	}
}

// TestDotlessILabelKeyIsStampedAndForwarded: U+0131 binds to no field in
// either decoder and isn't refused, in any mode.
func TestDotlessILabelKeyIsStampedAndForwarded(t *testing.T) {
	t.Parallel()
	const body = "{\"Name\":\"n\",\"Labels\":{\"a\u0131\":\"1\"}}"
	for _, target := range []string{"/v1.45/containers/create", "/v1.45/volumes/create"} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			out := sendThroughOwnerIsolation(t, "enforce", target, body)
			if out.status != http.StatusCreated {
				t.Fatalf("status = %d, want %d; message: %s", out.status, http.StatusCreated, out.message)
			}
			if want := "{\"Labels\":{\"a\u0131\":\"1\",\"com.sockguard.owner\":\"team-a\"},\"Name\":\"n\"}"; len(out.forwarded) != 1 || out.forwarded[0] != want {
				t.Fatalf("forwarded %q, want %q", out.forwarded, want)
			}
			if out.meta.Decision != "" {
				t.Fatalf("decision = %q, want none recorded", out.meta.Decision)
			}
		})
	}
}
