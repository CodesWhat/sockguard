package buildkitproxy

import (
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/control"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/gateway"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/pb"
)

func evaluateGatewayRequest(method string, payload []byte, policy Policy) *mediationDenial {
	var message proto.Message
	switch method {
	case "Ping":
		message = &gateway.PingRequest{}
	case "Solve":
		message = &gateway.SolveRequest{}
	case "ResolveImageConfig":
		message = &gateway.ResolveImageConfigRequest{}
	case "ResolveSourceMeta":
		message = &gateway.ResolveSourceMetaRequest{}
	case "ReadFile":
		message = &gateway.ReadFileRequest{}
	case "ReadDir":
		message = &gateway.ReadDirRequest{}
	case "StatFile":
		message = &gateway.StatFileRequest{}
	case "Evaluate":
		message = &gateway.EvaluateRequest{}
	case "Return":
		message = &gateway.ReturnRequest{}
	case "Inputs":
		message = &gateway.InputsRequest{}
	case "Warn":
		message = &gateway.WarnRequest{}
	default:
		return deny(grpcCodePermissionDenied, "buildkit_method_denied", "frontend method is not supported")
	}
	if err := proto.Unmarshal(payload, message); err != nil {
		return deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "malformed frontend request")
	}
	if hasUnknownFields(message) {
		return deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported frontend schema")
	}
	solve := policy.Control.Solve
	switch req := message.(type) {
	case *gateway.SolveRequest:
		if req.Frontend != "" || len(req.FrontendOpt) != 0 || len(req.FrontendInputs) != 0 || len(req.SourcePolicies) != 0 || req.Final || len(req.ExporterAttr) != 0 {
			return gatewayPolicyDenial("frontend solve contains an unmediated delegation or output")
		}
		cache := &control.CacheOptions{}
		for _, entry := range req.CacheImports {
			cache.Imports = append(cache.Imports, &control.CacheOptionsEntry{Type: entry.GetType(), Attrs: entry.GetAttrs()})
		}
		if d := checkSolveCache(&control.SolveRequest{Cache: cache}, solve); d != nil {
			return d
		}
		return checkGatewayDefinition(req.Definition, solve)
	case *gateway.ResolveImageConfigRequest:
		if req.Ref == "" || req.ResolverType != 0 || req.SessionID != "" || req.StoreID != "" || len(req.SourcePolicies) != 0 {
			return gatewayPolicyDenial("image resolution cannot override session, store, or source policy")
		}
	case *gateway.ResolveSourceMetaRequest:
		if len(req.SourcePolicies) != 0 || req.GetImage().GetAttestationChain() || len(req.GetImage().GetResolveAttestations()) != 0 {
			return gatewayPolicyDenial("source policy and attestation resolution are not mediated")
		}
		return checkGatewaySource(req.Source, solve)
	case *gateway.ReadFileRequest:
		if !gatewayResultRef(req.Ref) || !gatewayFilePath(req.FilePath) || req.MountIndex != 0 || req.GetRange().GetOffset() < 0 || req.GetRange().GetLength() < 0 {
			return gatewayPolicyDenial("invalid frontend file request")
		}
	case *gateway.ReadDirRequest:
		if !gatewayResultRef(req.Ref) || !gatewayFilePath(req.DirPath) || req.MountIndex != 0 {
			return gatewayPolicyDenial("invalid frontend directory request")
		}
	case *gateway.StatFileRequest:
		if !gatewayResultRef(req.Ref) || !gatewayFilePath(req.Path) || req.MountIndex != 0 {
			return gatewayPolicyDenial("invalid frontend stat request")
		}
	case *gateway.EvaluateRequest:
		if !gatewayResultRef(req.Ref) {
			return gatewayPolicyDenial("invalid frontend result ref")
		}
	case *gateway.ReturnRequest:
		if (req.Result == nil) == (req.Error == nil) {
			return gatewayPolicyDenial("frontend must return either a result or an error")
		}
		if req.Error != nil {
			if req.Error.Code < 1 || req.Error.Code > 16 {
				return gatewayPolicyDenial("invalid frontend error status")
			}
			return nil
		}
		return checkGatewayResult(req.Result, solve)
	}
	return nil
}

func checkGatewayDefinition(def *pb.Definition, policy SolvePolicy) *mediationDenial {
	if !policy.AllowRunInstructions && !definitionExecAllowed(def, policy) {
		return gatewayPolicyDenial("frontend operation is not approved")
	}
	if d := checkSolveSourceSessions(def); d != nil {
		return d
	}
	for _, raw := range def.GetDef() {
		var op pb.Op
		if err := proto.Unmarshal(raw, &op); err != nil {
			return gatewayPolicyDenial("malformed frontend operation")
		}
		if op.GetBuild() != nil {
			return gatewayPolicyDenial("nested daemon-resolved builds are not mediated by the frontend gateway")
		}
		if source := op.GetSource(); source != nil {
			if d := checkGatewaySource(source, policy); d != nil {
				return d
			}
		}
	}
	return nil
}

func checkGatewaySource(source *pb.SourceOp, policy SolvePolicy) *mediationDenial {
	if source == nil || source.Attrs["local.session"] != "" || source.Attrs["oci.session"] != "" {
		return gatewayPolicyDenial("frontend source must inherit the build session")
	}
	switch {
	case strings.HasPrefix(source.Identifier, "docker-image://"), strings.HasPrefix(source.Identifier, "local://"):
		return nil
	case strings.HasPrefix(source.Identifier, "http://"), strings.HasPrefix(source.Identifier, "https://"), strings.HasPrefix(source.Identifier, "git://"):
		if policy.AllowRemoteContext {
			return nil
		}
	}
	return gatewayPolicyDenial("frontend source is not permitted by the build context policy")
}

func checkGatewayResult(result *gateway.Result, policy SolvePolicy) *mediationDenial {
	if len(result.Attestations) != 0 {
		return gatewayPolicyDenial("frontend attestations are not mediated")
	}
	var refs []*gateway.Ref
	switch value := result.Result.(type) {
	case *gateway.Result_Ref:
		refs = append(refs, value.Ref)
	case *gateway.Result_Refs:
		if len(value.Refs.GetRefs()) > maxGatewaySolvesPerBuild {
			return gatewayPolicyDenial("too many frontend result refs")
		}
		for _, ref := range value.Refs.GetRefs() {
			refs = append(refs, ref)
		}
	case *gateway.Result_RefDeprecated:
		refs = append(refs, &gateway.Ref{Id: value.RefDeprecated})
	case *gateway.Result_RefsDeprecated:
		if len(value.RefsDeprecated.GetRefs()) > maxGatewaySolvesPerBuild {
			return gatewayPolicyDenial("too many frontend result refs")
		}
		for _, ref := range value.RefsDeprecated.GetRefs() {
			refs = append(refs, &gateway.Ref{Id: ref})
		}
	}
	for _, ref := range refs {
		// Empty refs represent scratch. Nonempty refs are resolved by the
		// daemon inside this build's forwarder, never its global ref store.
		if ref == nil || (ref.Id != "" && !gatewayResultRef(ref.Id)) {
			return gatewayPolicyDenial("invalid frontend result ref")
		}
		if d := checkGatewayDefinition(ref.Def, policy); d != nil {
			return d
		}
	}
	return nil
}

func gatewayResultRef(ref string) bool { _, ok := canonicalBuildkitSessionID(ref); return ok }
func gatewayFilePath(path string) bool {
	return len(path) <= DefaultLimits().MaxFileSyncPathLength && !strings.ContainsRune(path, 0)
}
func gatewayPolicyDenial(message string) *mediationDenial {
	return deny(grpcCodePermissionDenied, "buildkit_policy_denied", message)
}
