package ownership

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
)

type imageVolumeIDKey struct{}

func withImageVolumeID(ctx context.Context) context.Context {
	return context.WithValue(ctx, imageVolumeIDKey{}, true)
}

func imageVolumeID(ctx context.Context) bool {
	exact, _ := ctx.Value(imageVolumeIDKey{}).(bool)
	return exact
}

// A Podman manifest list has a full storage ID, but resolves to a mutable
// platform instance. Delayed volume lookup is safe only when the inspected
// image's own config ID equals the full ID recorded in the create body.
func decodeImageVolumeID(body io.Reader, identifier string) (map[string]string, bool, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxOwnershipBodyBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > maxOwnershipBodyBytes {
		return nil, false, fmt.Errorf("image volume inspect response exceeds %d bytes", maxOwnershipBodyBytes)
	}
	var payload struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, false, err
	}
	if !isFullImageID(identifier) || !isFullImageID(payload.ID) || strings.TrimPrefix(payload.ID, "sha256:") != strings.TrimPrefix(identifier, "sha256:") {
		return nil, false, nil
	}
	labels, err := dockerresource.DecodeLabels(bytes.NewReader(data), dockerresource.KindImage)
	if err != nil {
		return nil, false, err
	}
	return labels, true, nil
}
