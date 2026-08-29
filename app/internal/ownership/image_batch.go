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
	switch normPath {
	case libpodPrefix + "images/export":
		key = "references"
		foldKeys = true
	case libpodPrefix + "images/remove":
		key = "images"
		foldKeys = true
		var lastAllValue string
		hasAllValue := false
		for _, field := range query {
			if field.key == "all" {
				lastAllValue = field.value
				hasAllValue = true
			}
		}
		if hasAllValue {
			if _, err := strconv.ParseBool(lastAllValue); err != nil {
				return nil, fmt.Errorf("invalid image batch query: all: %w", err)
			}
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
	if normPath == "/images/get" {
		for _, identifier := range identifiers {
			if !compatImageExportNamesOneImage(identifier) {
				return &imageBatchOwnershipReferences{denialReason: "owner policy cannot safely enumerate an image repository export"}, nil
			}
		}
	}

	return &imageBatchOwnershipReferences{identifiers: identifiers}, nil
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

func compatImageExportNamesOneImage(identifier string) bool {
	if len(identifier) == 64 {
		allHex := true
		for _, char := range identifier {
			if (char < '0' || char > '9') && (char < 'a' || char > 'f') && (char < 'A' || char > 'F') {
				allHex = false
				break
			}
		}
		if allHex {
			return true
		}
	}

	if at := strings.IndexByte(identifier, '@'); at > 0 && at == strings.LastIndexByte(identifier, '@') {
		digest := identifier[at+1:]
		separator := strings.IndexByte(digest, ':')
		return separator > 0 && separator < len(digest)-1
	}

	lastColon := strings.LastIndexByte(identifier, ':')
	return lastColon > strings.LastIndexByte(identifier, '/') && lastColon < len(identifier)-1
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
