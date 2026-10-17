package buildkitproxy

import (
	"encoding/binary"
	"math"

	"github.com/codeswhat/sockguard/v3/app/internal/buildkitproto/gateway"
	"google.golang.org/protobuf/proto"
)

func rewriteGatewayDockerfile(payload []byte, policy Policy, maxBytes int64) ([]byte, *mediationDenial) {
	var req gateway.SolveRequest
	if proto.Unmarshal(payload, &req) != nil {
		return nil, gatewayPolicyDenial("malformed Dockerfile frontend request")
	}
	if req.Frontend != "dockerfile.v0" {
		return nil, nil
	}
	if req.FrontendOpt == nil {
		req.FrontendOpt = make(map[string]string)
	}
	// Presence disables both syntax directives and syntax build-argument
	// delegation inside the daemon's built-in Dockerfile frontend.
	req.FrontendOpt["cmdline"] = ""
	if owner := policy.ImageOwnership; owner.Owner != "" {
		req.FrontendOpt["label:"+owner.LabelKey] = owner.Owner
	}
	encoded, err := proto.Marshal(&req)
	if err != nil {
		return nil, gatewayPolicyDenial("invalid Dockerfile frontend request")
	}
	length := int64(len(encoded))
	if length > math.MaxUint32 || length > int64(math.MaxInt-grpcMessageHeaderLen) || (maxBytes > 0 && length+grpcMessageHeaderLen > maxBytes) {
		return nil, deny(grpcCodeResourceExhausted, "buildkit_message_too_large", "Dockerfile frontend request exceeds size cap")
	}
	frame := make([]byte, grpcMessageHeaderLen)
	binary.BigEndian.PutUint32(frame[1:], uint32(length))
	return append(frame, encoded...), nil
}
