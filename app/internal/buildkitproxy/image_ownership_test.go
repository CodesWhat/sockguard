package buildkitproxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/control"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/gateway"
	"google.golang.org/protobuf/proto"
)

func TestBridgeBuildImageOwnership(t *testing.T) {
	for _, tc := range []struct {
		name, frontend, config, names string
		denied                        bool
	}{
		{"dockerfile stamp", "dockerfile.v0", "", "mine/app:v1,mine/app:v2", false},
		{"foreign destination", "dockerfile.v0", "", "mine/app:v1,foreign/app:v1", true},
		{"dynamic name", "dockerfile.v0", "", "*", true},
		{"raw image needs config", "", "", "mine/app:v1", true},
		{"raw image config", "", `{"architecture":"arm64","os":"linux","config":{"Cmd":["/app"],"Labels":{"owner":"forged","keep":"value"}}}`, "mine/app:v1", false},
		{"raw moby", "", `{"architecture":"arm64","os":"linux","config":{}}`, "mine/app:v1", true},
		{"syntax argument", "dockerfile.v0", "", "mine/app:v1", true},
		{"malformed config", "dockerfile.v0", `[]`, "mine/app:v1", true},
		{"ambiguous config", "dockerfile.v0", `{"config":{},"Config":{}}`, "mine/app:v1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := allowAllPolicy
			policy.Control.Solve.AllowedExporters = []string{"image", "moby"}
			policy.Control.Solve.AllowRunInstructions = true
			var checked []string
			policy.ImageOwnership = ImageOwnershipPolicy{Owner: "team-a", LabelKey: "owner", Authorize: func(ctx context.Context, name string) error {
				checked = append(checked, name)
				if name == "foreign/app:v1" {
					return errors.New("foreign owner")
				}
				return nil
			}}
			var called atomic.Bool
			daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called.Store(true)
				_, payload, err := readGRPCFrame(r.Body, DefaultLimits().MaxMessageBytes)
				if err != nil {
					t.Error(err)
					return
				}
				var got control.SolveRequest
				if err := proto.Unmarshal(payload, &got); err != nil {
					t.Error(err)
					return
				}
				if tc.frontend != "" && got.FrontendAttrs["label:owner"] != "team-a" {
					t.Error("owner label was not stamped")
				}
				if tc.frontend != "" {
					if value, present := got.FrontendAttrs["cmdline"]; !present || value != "" {
						t.Error("Dockerfile syntax delegation wasn't disabled")
					}
				}
				if tc.config != "" {
					var config struct {
						Config struct {
							Labels map[string]string
							Cmd    []string
						}
					}
					if err := json.Unmarshal([]byte(got.Exporters[0].Attrs["containerimage.config"]), &config); err != nil {
						t.Error(err)
					}
					if config.Config.Labels["owner"] != "team-a" || config.Config.Labels["keep"] != "value" || !reflect.DeepEqual(config.Config.Cmd, []string{"/app"}) {
						t.Errorf("config lost stamp/content: %+v", config)
					}
				}
				writeGRPCStatus(w, 0, "")
			})
			tb := newTestBridge(t, EndpointGRPC, policy, DefaultLimits(), daemon)
			attrs := map[string]string{"name": tc.names}
			if tc.config != "" {
				attrs["containerimage.config"] = tc.config
			}
			req := &control.SolveRequest{Ref: "build", Session: testBuildkitSessionID, Frontend: tc.frontend, FrontendAttrs: map[string]string{"label:owner": "forged"}, Exporters: []*control.Exporter{{Type: "image", Attrs: attrs}}}
			if tc.name == "raw moby" {
				req.Exporters[0].Type = "moby"
			}
			if tc.name == "syntax argument" {
				req.FrontendAttrs["build-arg:BUILDKIT_SYNTAX"] = "untrusted/compiler"
			}
			resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", req))
			if err != nil {
				t.Fatal(err)
			}
			code, _ := grpcStatusOf(t, resp)
			if tc.denied {
				if code == 0 || called.Load() {
					t.Fatal("unowned export reached daemon")
				}
				return
			}
			if code != 0 || !called.Load() {
				t.Fatalf("status=%d, called=%v", code, called.Load())
			}
			want := []string{"mine/app:v1"}
			if tc.names == "mine/app:v1,mine/app:v2" {
				want = append(want, "mine/app:v2")
			}
			if !reflect.DeepEqual(checked, want) {
				t.Fatalf("checked %v, want %v", checked, want)
			}
		})
	}
}

func TestOwnedSolveExpansionRespectsMessageCap(t *testing.T) {
	policy := allowAllPolicy
	policy.Control.Solve.AllowedExporters = []string{"image"}
	policy.ImageOwnership = ImageOwnershipPolicy{Owner: strings.Repeat("a", 1024), LabelKey: "owner", Authorize: func(context.Context, string) error { return nil }}
	limits := DefaultLimits()
	limits.MaxMessageBytes = 512
	var called atomic.Bool
	tb := newTestBridge(t, EndpointGRPC, policy, limits, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called.Store(true) }))
	req := &control.SolveRequest{Ref: "build", Session: testBuildkitSessionID, Frontend: "dockerfile.v0", Exporters: []*control.Exporter{{Type: "image", Attrs: map[string]string{"name": "mine/app:v1"}}}}
	resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", req))
	if err != nil {
		t.Fatal(err)
	}
	code, _ := grpcStatusOf(t, resp)
	if code != grpcCodeResourceExhausted || called.Load() {
		t.Fatalf("expanded request status=%d, daemon=%v", code, called.Load())
	}
}

func TestBuildQueriesWaitForImageOwnershipAdmission(t *testing.T) {
	for _, method := range []string{"Status", "Ping"} {
		t.Run(method, func(t *testing.T) {
			lookupStarted, release := make(chan struct{}), make(chan struct{})
			rootRelease := make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
				select {
				case <-rootRelease:
				default:
					close(rootRelease)
				}
			}()
			policy := allowAllPolicy
			policy.Control.Solve.AllowedExporters = []string{"image"}
			policy.Control.Solve.AllowFrontendGateway = method == "Ping"
			policy.ImageOwnership = ImageOwnershipPolicy{Owner: "team-a", LabelKey: "owner", Authorize: func(ctx context.Context, _ string) error {
				close(lookupStarted)
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}}
			tb := newTestBridge(t, EndpointGRPC, policy, DefaultLimits(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/Solve") {
					<-rootRelease
				}
				writeGRPCStatus(w, 0, "")
				if strings.HasSuffix(r.URL.Path, "/Ping") {
					_, _ = w.Write(grpcFrame(mustMarshal(t, &gateway.PongResponse{})))
				}
			}))
			solveDone := make(chan int, 1)
			go func() {
				frontend := "dockerfile.v0"
				if method == "Ping" {
					frontend = ""
				}
				req := &control.SolveRequest{Ref: "build", Session: testBuildkitSessionID, Frontend: frontend, Exporters: []*control.Exporter{{Type: "image", Attrs: map[string]string{"name": "mine/app:v1"}}}}
				resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", req))
				if err != nil {
					solveDone <- -1
					return
				}
				code, _ := grpcStatusOf(t, resp)
				solveDone <- code
			}()
			select {
			case <-lookupStarted:
			case <-time.After(3 * time.Second):
				t.Fatal("ownership lookup didn't start")
			}
			queryDone := make(chan int, 1)
			go func() {
				request := newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Status", &control.StatusRequest{Ref: "build"})
				if method == "Ping" {
					request = newFramedGRPCRequest(t, "/"+gatewayService+"/Ping", &gateway.PingRequest{})
					request.Header.Set(gatewayBuildHeader, "build")
				}
				resp, err := tb.driver.RoundTrip(request)
				if err != nil {
					queryDone <- -1
					return
				}
				code, _ := grpcStatusOf(t, resp)
				queryDone <- code
			}()
			select {
			case code := <-queryDone:
				t.Fatalf("query returned %d before Solve admission", code)
			case <-time.After(50 * time.Millisecond):
			}
			close(release)
			select {
			case code := <-queryDone:
				if code != 0 {
					t.Fatalf("query status=%d", code)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("admitted query did not complete")
			}
			close(rootRelease)
			select {
			case code := <-solveDone:
				if code != 0 {
					t.Fatalf("solve status=%d", code)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("admitted solve did not complete")
			}
		})
	}
}

func TestOwnedExporterTypesAndImageConfigShapes(t *testing.T) {
	policy := allowAllPolicy
	policy.ImageOwnership = ImageOwnershipPolicy{Owner: "team-a", LabelKey: "owner", Authorize: func(context.Context, string) error { return nil }}
	for _, tc := range []struct {
		kind, config string
		denied       bool
	}{
		{"local", "", false}, {"tar", "", false}, {"unknown", "", true},
		{"oci", `{"config":null}`, false}, {"docker", `{"config":{"labels":null}}`, false},
		{"image", `{"Config":{"Labels":{"keep":"v"}}}`, false},
		{"image", `{"config":[]}`, true}, {"image", `null`, true},
	} {
		t.Run(tc.kind+tc.config, func(t *testing.T) {
			req := &control.SolveRequest{Exporters: []*control.Exporter{{Type: tc.kind, Attrs: map[string]string{"containerimage.config": tc.config}}}}
			if d := applySolveImageOwnership(t.Context(), req, policy); (d != nil) != tc.denied {
				t.Fatalf("denial=%v", d)
			}
		})
	}
}
