package ownership

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
)

type imageBatchOwnershipReferences struct {
	identifiers  []string
	denialReason string
}

// maxImageBatchReferences bounds the internal inspect fan-out caused by one
// client action. The limit applies before deduplication so a duplicate-only
// query cannot bypass the request-work bound.
const maxImageBatchReferences = 256

type imageBatchQueryValue struct {
	key   string
	value string
}

type imageBatchBoolPossibilities struct {
	mayBeTrue  bool
	mayBeFalse bool
}

func isImageBatchOwnershipPath(method, normPath string) bool {
	return method == http.MethodGet && (normPath == "/images/get" || normPath == libpodPrefix+"images/export") ||
		method == http.MethodDelete && normPath == libpodPrefix+"images/remove"
}

func parseImageBatchOwnershipReferences(r *http.Request, normPath string) (*imageBatchOwnershipReferences, error) {
	query, err := parseImageBatchQuery(r.URL.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("invalid image batch query: %w", err)
	}

	key := "names"
	foldKeys := false
	denialReason := ""
	switch normPath {
	case libpodPrefix + "images/export":
		key = "references"
		foldKeys = true
	case libpodPrefix + "images/remove":
		key = "images"
		foldKeys = true
		if _, err := parseImageBatchBoolPossibilities(query, "all"); err != nil {
			return nil, fmt.Errorf("invalid image batch query: %w", err)
		}
		force, err := parseImageBatchBoolPossibilities(query, "force")
		if err != nil {
			return nil, fmt.Errorf("invalid image batch query: %w", err)
		}
		noPrune, err := parseImageBatchBoolPossibilities(query, "noprune")
		if err != nil {
			return nil, fmt.Errorf("invalid image batch query: %w", err)
		}
		lookupManifest, err := parseImageBatchBoolPossibilities(query, "lookupManifest")
		if err != nil {
			return nil, fmt.Errorf("invalid image batch query: %w", err)
		}

		switch {
		case force.mayBeTrue:
			denialReason = "owner policy denied force image batch removal because it can remove containers"
		case noPrune.mayBeFalse:
			denialReason = "owner policy requires noprune=true for image batch removal"
		case lookupManifest.mayBeTrue:
			denialReason = "owner policy denied manifest-list image batch removal"
		}
	}

	identifiers := make([]string, 0)
	for _, field := range query {
		if field.key == key || foldKeys && strings.EqualFold(field.key, key) {
			identifiers = append(identifiers, field.value)
		}
	}
	if len(identifiers) > maxImageBatchReferences {
		return nil, fmt.Errorf("invalid image batch query: selected images exceeds %d image reference limit", maxImageBatchReferences)
	}
	uniqueIdentifiers := make([]string, 0, len(identifiers))
	seen := make(map[string]struct{}, len(identifiers))
	for _, identifier := range identifiers {
		if identifier == "" {
			return nil, fmt.Errorf("invalid image batch query: %s contains an empty image reference", key)
		}
		if _, duplicate := seen[identifier]; duplicate {
			continue
		}
		seen[identifier] = struct{}{}
		uniqueIdentifiers = append(uniqueIdentifiers, identifier)
	}
	identifiers = uniqueIdentifiers

	if normPath == libpodPrefix+"images/remove" && len(identifiers) == 0 {
		return &imageBatchOwnershipReferences{denialReason: "owner policy denied unscoped image batch removal"}, nil
	}
	if denialReason != "" {
		return &imageBatchOwnershipReferences{denialReason: denialReason}, nil
	}
	if normPath == "/images/get" && len(identifiers) > 0 {
		return &imageBatchOwnershipReferences{denialReason: "owner policy cannot safely authorize Docker-compatible multi-platform image export"}, nil
	}

	return &imageBatchOwnershipReferences{identifiers: identifiers}, nil
}

// parseImageBatchBoolPossibilities mirrors the native Podman decoder's
// security-relevant scalar behavior. Gorilla/schema matches field names with
// strings.EqualFold, but r.URL.Query groups values by their exact decoded key
// spelling before the decoder iterates that map. Repetitions of one exact
// spelling use their last value; differently-cased spellings each remain a
// possible final setter because map iteration order is unspecified. An empty
// final value is a no-op with the decoder's default ZeroEmpty(false).
func parseImageBatchBoolPossibilities(query []imageBatchQueryValue, key string) (imageBatchBoolPossibilities, error) {
	lastBySpelling := make(map[string]string)
	spellings := make([]string, 0)
	for _, field := range query {
		if !strings.EqualFold(field.key, key) {
			continue
		}
		if _, seen := lastBySpelling[field.key]; !seen {
			spellings = append(spellings, field.key)
		}
		lastBySpelling[field.key] = field.value
	}

	possibilities := imageBatchBoolPossibilities{}
	hasSetter := false
	for _, spelling := range spellings {
		value := lastBySpelling[spelling]
		if value == "" {
			continue
		}
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return imageBatchBoolPossibilities{}, fmt.Errorf("%s: %w", key, err)
		}
		hasSetter = true
		if parsed {
			possibilities.mayBeTrue = true
		} else {
			possibilities.mayBeFalse = true
		}
	}
	if !hasSetter {
		possibilities.mayBeFalse = true
	}
	return possibilities, nil
}

// parseImageBatchQuery follows net/url.ParseQuery's decoding and validation
// rules while retaining the client's field order. That order keeps repeated
// ownership lookups deterministic after libpod's case-insensitive query-key
// matching combines differently-cased spellings into one conservative set.
func parseImageBatchQuery(rawQuery string) ([]imageBatchQueryValue, error) {
	values := make([]imageBatchQueryValue, 0)
	for rawQuery != "" {
		field := rawQuery
		if before, after, found := strings.Cut(rawQuery, "&"); found {
			field = before
			rawQuery = after
		} else {
			rawQuery = ""
		}
		if strings.Contains(field, ";") {
			return nil, fmt.Errorf("invalid semicolon separator in query")
		}
		if field == "" {
			continue
		}

		rawKey, rawValue, _ := strings.Cut(field, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			return nil, err
		}
		value, err := url.QueryUnescape(rawValue)
		if err != nil {
			return nil, err
		}
		values = append(values, imageBatchQueryValue{key: key, value: value})
	}
	return values, nil
}

func checkImageBatchOwnershipReferences(
	ctx context.Context,
	inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error),
	batch *imageBatchOwnershipReferences,
	opts Options,
) (ownershipVerdict, string, error) {
	if batch == nil {
		return verdictPassThrough, "", nil
	}
	if batch.denialReason != "" {
		return verdictDeny, batch.denialReason, nil
	}

	strictest := verdictPassThrough
	for _, identifier := range batch.identifiers {
		verdict, reason, err := checkOwnedResource(ctx, inspectResource, dockerresource.KindImage, identifier, opts, false)
		if err != nil || verdict == verdictDeny {
			return verdict, reason, err
		}
		strictest = verdictAllow
	}
	return strictest, "", nil
}
