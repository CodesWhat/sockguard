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

func isImageBatchOwnershipPath(method, normPath string) bool {
	return method == http.MethodGet && (normPath == "/images/get" || normPath == libpodPrefix+"images/export") ||
		method == http.MethodDelete && normPath == libpodPrefix+"images/remove"
}

func parseImageBatchOwnershipReferences(r *http.Request, normPath string) (*imageBatchOwnershipReferences, error) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("invalid image batch query: %w", err)
	}

	key := "names"
	switch normPath {
	case libpodPrefix + "images/export":
		key = "references"
	case libpodPrefix + "images/remove":
		key = "images"
		allValues := query["all"]
		if len(allValues) > 0 {
			_, err := strconv.ParseBool(allValues[len(allValues)-1])
			if err != nil {
				return nil, fmt.Errorf("invalid image batch query: all: %w", err)
			}
		}
	}

	identifiers := query[key]
	for _, identifier := range identifiers {
		if identifier == "" {
			return nil, fmt.Errorf("invalid image batch query: %s contains an empty image reference", key)
		}
	}

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
