package buildkitproxy

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"math"
	"strings"

	"github.com/codeswhat/sockguard/v3/app/internal/buildkitproto/control"
	"github.com/codeswhat/sockguard/v3/app/internal/buildkitproto/gateway"
	"google.golang.org/protobuf/proto"
)

const imageConfigKey = "containerimage.config"

func rewriteGatewayImageOwnership(payload []byte, policy Policy, maxBytes int64) ([]byte, *mediationDenial) {
	var req gateway.ReturnRequest
	if proto.Unmarshal(payload, &req) != nil {
		return nil, imageOwnershipDenial()
	}
	owner := policy.ImageOwnership
	if owner.Owner != "" && req.Result != nil {
		for key, raw := range req.Result.Metadata {
			if key != imageConfigKey && !strings.HasPrefix(key, imageConfigKey+"/") {
				continue
			}
			stamped, ok := stampImageConfig(raw, owner)
			if !ok {
				return nil, imageOwnershipDenial()
			}
			req.Result.Metadata[key] = stamped
		}
		if owner.RequireConfig {
			switch req.Result.Result.(type) {
			case *gateway.Result_Refs, *gateway.Result_RefsDeprecated:
				if !completeImageConfigs(req.Result.Metadata) {
					return nil, imageOwnershipDenial()
				}
			default:
				if len(req.Result.Metadata[imageConfigKey]) == 0 {
					return nil, imageOwnershipDenial()
				}
			}
		}
	}
	encoded, err := proto.Marshal(&req)
	if err != nil {
		return nil, imageOwnershipDenial()
	}
	length := int64(len(encoded))
	if length > math.MaxUint32 || (maxBytes > 0 && length+grpcMessageHeaderLen > maxBytes) {
		return nil, deny(grpcCodeResourceExhausted, "buildkit_message_too_large", "owned image result exceeds size cap")
	}
	frame := make([]byte, grpcMessageHeaderLen)
	binary.BigEndian.PutUint32(frame[1:], uint32(length))
	return append(frame, encoded...), nil
}

func completeImageConfigs(metadata map[string][]byte) bool {
	var index struct {
		Platforms []struct {
			ID string `json:"id"`
		} `json:"platforms"`
	}
	if json.Unmarshal(metadata["containerimage.platforms"], &index) != nil || len(index.Platforms) == 0 {
		return false
	}
	for _, platform := range index.Platforms {
		if platform.ID == "" || len(metadata[imageConfigKey+"/"+platform.ID]) == 0 {
			return false
		}
	}
	return true
}

func imageExporter(kind string) bool {
	return kind == "image" || kind == "moby" || kind == "docker" || kind == "oci"
}

func hasImageExporter(req *control.SolveRequest) bool {
	for _, exporter := range req.GetExporters() {
		if imageExporter(exporter.GetType()) {
			return true
		}
	}
	return false
}

func imageOwnershipDenial() *mediationDenial {
	return deny(grpcCodePermissionDenied, "buildkit_image_owner_denied", "image export cannot satisfy owner isolation")
}

func applySolveImageOwnership(ctx context.Context, req *control.SolveRequest, policy Policy) *mediationDenial {
	owner := policy.ImageOwnership
	if owner.Owner == "" {
		return nil
	}
	if owner.LabelKey == "" {
		return imageOwnershipDenial()
	}
	names := 0
	for _, exporter := range req.GetExporters() {
		if exporter == nil {
			continue
		}
		if !imageExporter(exporter.Type) {
			if exporter.Type != "local" && exporter.Type != "tar" {
				return imageOwnershipDenial()
			}
			continue
		}
		for _, name := range strings.Split(exporter.Attrs["name"], ",") {
			if name == "" {
				continue
			}
			names++
			if names > 256 || name == "*" || owner.Authorize == nil || owner.Authorize(ctx, name) != nil {
				return imageOwnershipDenial()
			}
		}
		for key, config := range exporter.Attrs {
			if key != imageConfigKey && !strings.HasPrefix(key, imageConfigKey+"/") {
				continue
			}
			stamped, ok := stampImageConfig([]byte(config), owner)
			if !ok {
				return imageOwnershipDenial()
			}
			exporter.Attrs[key] = string(stamped)
		}
		gatewayRoot := policy.Control.Solve.AllowFrontendGateway && req.Frontend == "" && req.Definition == nil
		// Older Docker image stores don't apply image-config exporter attrs.
		// Only the built-in compiler or mediated Return metadata can stamp them.
		if exporter.Type == "moby" && req.Frontend != "dockerfile.v0" && !gatewayRoot {
			return imageOwnershipDenial()
		}
		if req.Frontend != "dockerfile.v0" && !gatewayRoot && exporter.Attrs[imageConfigKey] == "" {
			return imageOwnershipDenial()
		}
	}
	if hasImageExporter(req) && req.Frontend == "dockerfile.v0" {
		if req.FrontendAttrs == nil {
			req.FrontendAttrs = make(map[string]string)
		}
		req.FrontendAttrs["label:"+owner.LabelKey] = owner.Owner
		if _, present := req.FrontendAttrs["build-arg:BUILDKIT_SYNTAX"]; present {
			return imageOwnershipDenial()
		}
		// Presence of cmdline disables Dockerfile syntax delegation in
		// BuildKit's built-in frontend. External compilers must use the
		// mediated gateway, where Return image configs are stamped.
		req.FrontendAttrs["cmdline"] = ""
	}
	if req.ExporterDeprecated != "" && len(req.Exporters) > 0 {
		req.ExporterAttrsDeprecated = req.Exporters[0].GetAttrs()
	}
	return nil
}

// canonicalImageField refuses case-ambiguous struct fields, then normalizes
// their spelling. Image config is a JSON struct; label keys remain data keys.
func canonicalImageField(object map[string]json.RawMessage, field string) (json.RawMessage, bool) {
	var raw json.RawMessage
	found := false
	for key, value := range object {
		if !strings.EqualFold(key, field) {
			continue
		}
		if found {
			return nil, false
		}
		found, raw = true, value
		delete(object, key)
	}
	return raw, true
}

func stampImageConfig(raw []byte, owner ImageOwnershipPolicy) ([]byte, bool) {
	var image map[string]json.RawMessage
	if json.Unmarshal(raw, &image) != nil || image == nil {
		return nil, false
	}
	configRaw, ok := canonicalImageField(image, "config")
	if !ok {
		return nil, false
	}
	config := make(map[string]json.RawMessage)
	if len(configRaw) != 0 && (json.Unmarshal(configRaw, &config) != nil) {
		return nil, false
	}
	if config == nil {
		config = make(map[string]json.RawMessage)
	}
	labelsRaw, ok := canonicalImageField(config, "Labels")
	if !ok {
		return nil, false
	}
	labels := make(map[string]string)
	if len(labelsRaw) != 0 && json.Unmarshal(labelsRaw, &labels) != nil {
		return nil, false
	}
	if labels == nil {
		labels = make(map[string]string)
	}
	labels[owner.LabelKey] = owner.Owner
	config["Labels"], _ = json.Marshal(labels)
	image["config"], _ = json.Marshal(config)
	stamped, err := json.Marshal(image)
	return stamped, err == nil
}
