package ownership

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
)

type exactSecretLookupKey struct{}

// withExactSecretLookup marks a secret inspect as one that has to answer for
// the secret Podman's Store would match, which is an exact name or an exact
// ID. The inspect itself is SecretsManager.Lookup, which falls back to a
// unique ID prefix when neither matches, and that fallback made a create's
// answer depend on whether its name began another owner's secret ID.
func withExactSecretLookup(ctx context.Context) context.Context {
	return context.WithValue(ctx, exactSecretLookupKey{}, true)
}

func exactSecretLookup(ctx context.Context) bool {
	exact, _ := ctx.Value(exactSecretLookupKey{}).(bool)
	return exact
}

// secretLookupMaxBody bounds the inspect and error bodies read for an exact
// lookup.
const secretLookupMaxBody = 1 << 20

// secretLookupAmbiguousMarker is the text go.podman.io/common's Lookup puts in
// the error for an ID prefix that more than one secret shares (secretsdb.go,
// "more than one result secret with prefix %s"). Lookup tries an exact name
// and an exact ID first, so the error means neither matched.
var secretLookupAmbiguousMarker = []byte("more than one result secret with prefix")

func secretLookupAmbiguousPrefix(body io.Reader) bool {
	data, err := io.ReadAll(io.LimitReader(body, secretLookupMaxBody))
	return err == nil && bytes.Contains(data, secretLookupAmbiguousMarker)
}

// decodeExactSecret reads a secret inspect and reports it found only when its
// ID or Spec.Name is the identifier the request named.
func decodeExactSecret(body io.Reader, identifier string) (map[string]string, bool, error) {
	var payload struct {
		ID   string `json:"ID"`
		Spec struct {
			Name   string            `json:"Name"`
			Labels map[string]string `json:"Labels"`
		} `json:"Spec"`
	}
	if err := json.NewDecoder(io.LimitReader(body, secretLookupMaxBody)).Decode(&payload); err != nil {
		return nil, false, err
	}
	if payload.ID != identifier && payload.Spec.Name != identifier {
		return nil, false, nil
	}
	return payload.Spec.Labels, true, nil
}
