package buildkitproxy

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/caps"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/gateway"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/worker"
)

// Pinned to the v0.32.0 gateway and LLB capability inventories. An advertised
// field still requires request-level policy approval. Container/process RPCs,
// nested builds, explicit source sessions, and unsupported sources are absent.
var gatewayFrontendCaps = map[string]bool{
	"solve.base": true, "resolveimage": true, "resolveimage.resolvemode": true,
	"readfile": true, "readdir": true, "statfile": true, "return": true, "returnmap": true,
	"proto.refarray": true, "reference.output": true, "frontend.inputs": true,
	"gateway.solve.metadata": true, "frontend.caps": true, "gateway.solve.evaluate": true,
	"gateway.evaluate": true, "gateway.warnings": true, "source.metaresolver": true,
}

var gatewayLLBCaps = map[string]bool{
	"source.image": true, "source.image.resolvemode": true, "source.image.layerlimit": true, "source.image.checksum": true,
	"source.local": true, "source.local.unique": true, "source.local.includepatterns": true, "source.local.followpaths": true, "source.local.excludepatterns": true,
	"source.local.sharedkeyhint": true, "source.local.differ": true, "source.local.metadatatransfer": true,
	"source.git": true, "source.git.keepgitdir": true, "source.git.fullurl": true, "source.git.httpauth": true, "source.git.knownsshhosts": true,
	"source.git.mountsshsock": true, "source.git.subdir": true, "source.git.checksum": true, "source.git.skipsubmodules": true,
	"source.http": true, "source.http.auth": true, "source.http.checksum": true, "source.http.perm": true, "soruce.http.uidgid": true, "source.http.header": true,
	"exec.meta.base": true, "exec.meta.network": true, "exec.meta.proxyenv": true, "exec.meta.security": true, "exec.meta.setsdefaultpath": true,
	"exec.meta.ulimit": true, "exec.meta.removemountstubs.recursive": true,
	"exec.mount.bind": true, "exec.mount.bind.readwrite-nooutput": true, "exec.mount.cache": true, "exec.mount.cache.sharing": true,
	"exec.mount.selector": true, "exec.mount.tmpfs": true, "exec.mount.tmpfs.size": true, "exec.mount.secret": true, "exec.mount.ssh": true,
	"exec.mount.cache.content": true, "exec.secretenv": true, "exec.validexitcode": true,
	"file.base": true, "file.rm.wildcard": true, "file.copy.includeexcludepatterns": true, "file.copy.alwaysreplaceexistingdestpaths": true,
	"file.copy.modestring": true, "file.symlink.create": true,
	"constraints": true, "platform": true, "meta.ignorecache": true, "meta.description": true, "meta.exportcache": true,
	"mergeop": true, "diffop": true,
}

func filterGatewayPong(src io.Reader, maxLen int64, policy Policy) ([]byte, *mediationDenial) {
	_, payload, err := readGRPCFrame(src, maxLen)
	if errors.Is(err, io.EOF) {
		return nil, nil
	}
	if errors.Is(err, errMessageTooLarge) {
		return nil, deny(grpcCodeResourceExhausted, "buildkit_message_too_large", "frontend response exceeds size cap")
	}
	if err != nil {
		return nil, denyControlResponseUnparsable()
	}
	if _, _, err := readGRPCFrame(src, maxLen); !errors.Is(err, io.EOF) {
		return nil, denyControlResponseUnparsable()
	}
	var pong gateway.PongResponse
	if err := (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(payload, &pong); err != nil {
		return nil, denyControlResponseUnparsable()
	}
	out := &gateway.PongResponse{}
	for _, cap := range pong.FrontendAPICaps {
		allowed := gatewayFrontendCaps[cap.ID] || (cap.ID == "importcaches" && len(policy.Control.Solve.AllowedCacheImportTypes) > 0)
		if allowed && cap.Enabled {
			out.FrontendAPICaps = append(out.FrontendAPICaps, &caps.APICap{ID: cap.ID, Enabled: true})
		}
	}
	for _, cap := range pong.LLBCaps {
		if !gatewayLLBCaps[cap.ID] || !cap.Enabled {
			continue
		}
		if (strings.HasPrefix(cap.ID, "source.git") || strings.HasPrefix(cap.ID, "source.http") || cap.ID == "soruce.http.uidgid") && !policy.Control.Solve.AllowRemoteContext {
			continue
		}
		out.LLBCaps = append(out.LLBCaps, &caps.APICap{ID: cap.ID, Enabled: true})
	}
	for _, record := range pong.Workers {
		out.Workers = append(out.Workers, &worker.WorkerRecord{ID: record.ID, Platforms: record.Platforms, BuildkitVersion: record.BuildkitVersion})
	}
	filtered, err := proto.Marshal(out)
	if err != nil {
		return nil, denyControlResponseUnparsable()
	}
	length := int64(len(filtered))
	if length > math.MaxUint32 || length > int64(math.MaxInt-grpcMessageHeaderLen) || (maxLen > 0 && length+grpcMessageHeaderLen > maxLen) {
		return nil, deny(grpcCodeResourceExhausted, "buildkit_message_too_large", "frontend response exceeds size cap")
	}
	frame := make([]byte, grpcMessageHeaderLen+len(filtered))
	binary.BigEndian.PutUint32(frame[1:grpcMessageHeaderLen], uint32(length))
	copy(frame[grpcMessageHeaderLen:], filtered)
	return frame, nil
}
