package ownership

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/app/internal/imageselector"
)

type imageBatchOwnershipReferences struct {
	identifiers  []string
	denialReason string
}

type imageBatchBoolPossibilities struct {
	mayBeTrue  bool
	mayBeFalse bool
}

// isImageBatchOwnershipPath reports whether the request is one of the three
// image endpoints that name their subjects in the query string.
//
// HEAD is matched alongside GET on the two export routes, the way
// imageIdentifier and libpodImageIdentifier already reserve "get" and "export"
// for both methods. Moby and Podman register the exporters GET-only, so a HEAD
// gets a 405 from the daemon rather than an archive, but that is the upstream
// routing table rather than a property of the request. Gating on GET alone
// would forward the HEAD unchecked and leave the refusal resting on a detail
// this proxy does not control. Batch removal stays DELETE-only because that is
// the only method its route accepts and no read spelling of it exists.
func isImageBatchOwnershipPath(method, normPath string) bool {
	if method == http.MethodGet || method == http.MethodHead {
		return normPath == "/images/get" || normPath == libpodPrefix+"images/export"
	}
	return method == http.MethodDelete && normPath == libpodPrefix+"images/remove"
}

func parseImageBatchOwnershipReferences(r *http.Request, normPath string) (*imageBatchOwnershipReferences, error) {
	// Keep arrival order and exact key spelling so case-folded image selectors
	// are deterministic while case-variant scalar setters stay conservative.
	query, err := imageselector.Parse(r.URL.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("invalid image batch query: %w", err)
	}

	key := "names"
	// Podman's native and Docker-compatible handlers both use Gorilla/schema,
	// which matches query keys case-insensitively. Dockerd requires exact
	// lowercase "names", so folding here is only more conservative there: every
	// named compatibility export is refused under ownership either way.
	denialReason := ""
	switch normPath {
	case libpodPrefix + "images/export":
		key = "references"
	case libpodPrefix + "images/remove":
		key = "images"
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

	identifiers, err := query.References(key)
	if err != nil {
		return nil, fmt.Errorf("invalid image batch query: %w", err)
	}

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
func parseImageBatchBoolPossibilities(query imageselector.Query, key string) (imageBatchBoolPossibilities, error) {
	lastBySpelling := make(map[string]string)
	spellings := make([]string, 0)
	for _, field := range query {
		if !strings.EqualFold(field.Key, key) {
			continue
		}
		if _, seen := lastBySpelling[field.Key]; !seen {
			spellings = append(spellings, field.Key)
		}
		lastBySpelling[field.Key] = field.Value
	}

	possibilities := imageBatchBoolPossibilities{}
	hasSetter := false
	for _, spelling := range spellings {
		value := lastBySpelling[spelling]
		if value == "" {
			continue
		}
		parsed := value == "on"
		if !parsed {
			var err error
			parsed, err = strconv.ParseBool(value)
			if err != nil {
				return imageBatchBoolPossibilities{}, fmt.Errorf("%s: %w", key, err)
			}
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
		if err != nil || verdict.denied() {
			return verdict, reason, err
		}
		strictest = verdictAllow
	}
	return strictest, "", nil
}
