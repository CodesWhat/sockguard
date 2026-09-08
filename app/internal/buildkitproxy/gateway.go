package buildkitproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"time"
)

const gatewayService = "moby.buildkit.v1.frontend.LLBBridge"
const gatewayBuildHeader = "buildkit-controlapi-buildid"

func isGatewayMediatedMethod(endpoint Endpoint, service, method string) bool {
	if endpoint != EndpointGRPC || service != gatewayService {
		return false
	}
	switch method {
	case "Ping", "Solve", "ResolveImageConfig", "ResolveSourceMeta", "ReadFile", "ReadDir", "StatFile", "Evaluate", "Return", "Inputs", "Warn":
		return true
	default:
		return false
	}
}

func (b *bridge) forwardGatewayMediated(w http.ResponseWriter, r *http.Request, method string) {
	ids := r.Header.Values(gatewayBuildHeader)
	if len(ids) != 1 || ids[0] == "" || len(ids[0]) > maxBuildkitRefBytes {
		b.denyGateway(w, method, deny(grpcCodeInvalidArgument, "buildkit_invalid_ref", "one frontend build ref is required"))
		return
	}
	g := b.registry.gatewayBuild(b.session.Key, ids[0])
	if g == nil {
		b.denyGateway(w, method, deny(grpcCodePermissionDenied, "buildkit_ref_not_owned", "frontend build is not active for this client/profile"))
		return
	}
	frame, payload, err := readUnaryGRPCMessage(r.Body, b.limits.MaxMessageBytes)
	if err != nil {
		code := grpcCodeInvalidArgument
		if errors.Is(err, errMessageTooLarge) {
			code = grpcCodeResourceExhausted
		}
		b.denyGateway(w, method, deny(code, "buildkit_protocol_error", "invalid frontend request framing"))
		return
	}
	if d := evaluateGatewayRequest(method, payload, g.policy); d != nil {
		b.denyGateway(w, method, d)
		return
	}
	if method == "Solve" && !b.registry.admitGatewaySolve(g) {
		b.denyGateway(w, method, deny(grpcCodeResourceExhausted, "buildkit_ref_limit_exceeded", "frontend solve limit reached or build closed"))
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stop := context.AfterFunc(g.ctx, func() {
		// A successful Return can finish Control.Solve before its own reply
		// is flushed. Let that already-admitted reply finish within its cap.
		if method != "Return" || !errors.Is(context.Cause(g.ctx), errGatewayComplete) {
			cancel()
		}
	})
	defer stop()
	if method == "Return" {
		var stopReturn context.CancelFunc
		ctx, stopReturn = context.WithTimeout(ctx, 30*time.Second)
		defer stopReturn()
	}
	out := r.Clone(ctx)
	out.Header.Set(gatewayBuildHeader, daemonBuildRef(b.session.Key, ids[0]))
	if method == "Ping" {
		out.Body = io.NopCloser(bytes.NewReader(frame))
		b.forwardFilteredUnary(w, out, gatewayService, method, func(src io.Reader, maxLen int64) ([]byte, *mediationDenial) {
			return filterGatewayPong(src, maxLen, g.policy)
		})
		return
	}
	b.audit(gatewayService, method, Mediate, "")
	b.forwardWithBody(w, out, gatewayService, method, io.NopCloser(bytes.NewReader(frame)))
}

func (b *bridge) denyGateway(w http.ResponseWriter, method string, d *mediationDenial) {
	writeGRPCStatus(w, d.code, d.message)
	b.audit(gatewayService, method, Deny, d.reasonCode)
	if d.code != grpcCodeResourceExhausted {
		b.recordDeniedAndMaybeClose()
	}
}
