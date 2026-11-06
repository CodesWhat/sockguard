package ownership

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
)

type networkDeleteNameKey struct{}

func withNetworkDeleteName(ctx context.Context) context.Context {
	return context.WithValue(ctx, networkDeleteNameKey{}, true)
}

func networkDeleteName(ctx context.Context) bool {
	exact, _ := ctx.Value(networkDeleteNameKey{}).(bool)
	return exact
}

// Podman stores network names on containers but compares the delete argument
// literally when checking whether a network is in use. Deletion by ID can
// leave those references behind. Require the canonical name so the daemon's
// in-use check runs before it removes a network.
func decodeNetworkDeleteName(body io.Reader, identifier string) (map[string]string, bool, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxOwnershipBodyBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > maxOwnershipBodyBytes {
		return nil, false, fmt.Errorf("network inspect response exceeds %d bytes", maxOwnershipBodyBytes)
	}
	var payload struct {
		Name   string            `json:"Name"`
		Labels map[string]string `json:"Labels"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, false, err
	}
	if payload.Name != identifier {
		return nil, false, nil
	}
	return payload.Labels, true, nil
}
