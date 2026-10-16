package buildkitproxy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/gateway"
	"google.golang.org/protobuf/proto"
)

func TestGatewayReturnStampsEveryImageConfig(t *testing.T) {
	owner := ImageOwnershipPolicy{Owner: "team-a", LabelKey: "owner", RequireConfig: true, Authorize: func(context.Context, string) error { return nil }}
	for _, tc := range []struct {
		name     string
		metadata map[string][]byte
		denied   bool
	}{
		{"base", map[string][]byte{imageConfigKey: []byte(`{"config":{"Labels":{"owner":"forged"}}}`)}, false},
		{"platform", map[string][]byte{"containerimage.platforms": []byte(`{"platforms":[{"id":"linux/arm64"}]}`), imageConfigKey + "/linux/arm64": []byte(`{"config":{"Labels":{"owner":"forged"}}}`)}, false},
		{"missing", nil, true},
		{"partial platforms", map[string][]byte{"containerimage.platforms": []byte(`{"platforms":[{"id":"linux/arm64"},{"id":"linux/amd64"}]}`), imageConfigKey + "/linux/arm64": []byte(`{"config":{}}`)}, true},
		{"missing platform index", map[string][]byte{imageConfigKey + "/linux/arm64": []byte(`{"config":{}}`)}, true},
		{"null", map[string][]byte{imageConfigKey: []byte(`null`)}, true},
		{"bad labels", map[string][]byte{imageConfigKey: []byte(`{"config":{"Labels":[]}}`)}, true},
		{"case variants", map[string][]byte{imageConfigKey: []byte(`{"config":{"Labels":{},"labels":{}}}`)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := allowAllPolicy
			policy.ImageOwnership = owner
			req := &gateway.ReturnRequest{Result: &gateway.Result{Result: &gateway.Result_Ref{Ref: &gateway.Ref{Id: "result"}}, Metadata: tc.metadata}}
			if tc.name == "platform" || tc.name == "partial platforms" || tc.name == "missing platform index" {
				req.Result.Result = &gateway.Result_Refs{Refs: &gateway.RefMap{Refs: map[string]*gateway.Ref{"linux/arm64": {Id: "result"}}}}
			}
			payload := mustMarshal(t, req)
			frame, d := rewriteGatewayImageOwnership(payload, policy, DefaultLimits().MaxMessageBytes)
			if tc.denied {
				if d == nil {
					t.Fatal("unowned result admitted")
				}
				return
			}
			if d != nil {
				t.Fatal(d)
			}
			var got gateway.ReturnRequest
			if err := proto.Unmarshal(frame[grpcMessageHeaderLen:], &got); err != nil {
				t.Fatal(err)
			}
			for key, raw := range got.Result.Metadata {
				if key == "containerimage.platforms" {
					continue
				}
				var config struct {
					Config struct{ Labels map[string]string }
				}
				if err := json.Unmarshal(raw, &config); err != nil {
					t.Fatal(err)
				}
				if config.Config.Labels["owner"] != "team-a" {
					t.Fatal("owner not stamped")
				}
			}
		})
	}
}

func TestOwnedGatewayReturnRejectsMalformedAndOversizedResults(t *testing.T) {
	policy := allowAllPolicy
	policy.ImageOwnership = ImageOwnershipPolicy{Owner: "team-a", LabelKey: "owner", RequireConfig: true}
	if _, d := rewriteGatewayImageOwnership([]byte{0x08}, policy, 4096); d == nil {
		t.Fatal("malformed Return admitted")
	}
	req := &gateway.ReturnRequest{Result: &gateway.Result{Result: &gateway.Result_Ref{Ref: &gateway.Ref{Id: "result"}}, Metadata: map[string][]byte{imageConfigKey: []byte(`{"config":{}}`)}}}
	if _, d := rewriteGatewayImageOwnership(mustMarshal(t, req), policy, 32); d == nil || d.code != grpcCodeResourceExhausted {
		t.Fatalf("oversized result denial=%v", d)
	}
}
