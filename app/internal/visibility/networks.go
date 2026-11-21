package visibility

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/v3/app/internal/httpjson"
	"github.com/codeswhat/sockguard/v3/app/internal/logging"
)

// networks.go applies response.visible_networks to the networks themselves.
//
// The axis was first a container filter: a container is visible only while it
// is attached to a listed network. A listed network is the other half of that
// boundary. GET /networks and GET /networks/{id} would otherwise enumerate every
// network on the host, and each one carries a Containers map that names every
// attached container, visible or not, with its endpoint addresses. So both
// routes are narrowed on the response, by exact network name, and the
// Containers map is cut down to the containers this policy lets the caller see.
//
// Only the Docker-compat spellings are covered. Podman's native
// /libpod/networks/json and /libpod/networks/{id}/json keep the label
// selectors alone.

const networkListPath = "/networks"

// isNetworkInspectPath reports whether normPath is GET /networks/{id}. A
// network name may itself carry slashes, so everything after the prefix counts.
func isNetworkInspectPath(normPath string) bool {
	rest, ok := strings.CutPrefix(normPath, networkListPath+"/")
	return ok && rest != ""
}

// networkAxisAppliesToNetworks reports whether the policy narrows the network
// routes. Only visible_networks does; the name and image patterns are about
// containers and images.
func (p *compiledPolicy) networkAxisAppliesToNetworks(normPath string) bool {
	return len(p.networks) > 0 && (normPath == networkListPath || isNetworkInspectPath(normPath))
}

// networkNameVisible reports whether a network is listed by exact,
// case-sensitive name.
func (p *compiledPolicy) networkNameVisible(name string) bool {
	return slices.Contains(p.networks, name)
}

// containerVisibleOnNetwork reports whether the policy lets the caller see one
// container named in a network's Containers map. A container that cannot be
// found is hidden rather than shown: the map is a disclosure, so what the
// policy cannot vouch for stays out. A failed lookup fails the whole response.
func containerVisibleOnNetwork(ctx context.Context, deps visibilityDeps, policy *compiledPolicy, id string, memo map[string]bool) (bool, error) {
	if visible, ok := memo[id]; ok {
		return visible, nil
	}
	visible, found, err := lookupResourceVisibilityWithPolicy(ctx, deps, dockerresource.KindContainer, id, policy)
	if err != nil {
		return false, err
	}
	visible = visible && found
	memo[id] = visible
	return visible, nil
}

// narrowNetworkContainers replaces item's Containers map with the entries for
// visible containers. A missing or null map is left alone.
func narrowNetworkContainers(ctx context.Context, deps visibilityDeps, policy *compiledPolicy, item map[string]json.RawMessage, memo map[string]bool) error {
	raw, ok := item["Containers"]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	var containers map[string]json.RawMessage
	if err := json.Unmarshal(raw, &containers); err != nil {
		return fmt.Errorf("decode network Containers: %w", err)
	}
	kept := make(map[string]json.RawMessage, len(containers))
	for id, entry := range containers {
		visible, err := containerVisibleOnNetwork(ctx, deps, policy, id, memo)
		if err != nil {
			return err
		}
		if visible {
			kept[id] = entry
		}
	}
	narrowed, err := json.Marshal(kept)
	if err != nil {
		return err
	}
	item["Containers"] = narrowed
	return nil
}

// networkItemName reads the network's name off a decoded list item or inspect
// body. A body without a string Name is one this filter cannot place, so it is
// an error and the response fails closed.
func networkItemName(item map[string]json.RawMessage) (string, error) {
	raw, ok := item["Name"]
	if !ok {
		return "", errors.New("network has no Name")
	}
	var name string
	if err := json.Unmarshal(raw, &name); err != nil {
		return "", fmt.Errorf("decode network Name: %w", err)
	}
	return name, nil
}

// flushNetworkList filters GET /networks. Items for networks the policy does
// not list are dropped, and the Containers map of each kept one is narrowed.
// Like flushFiltered it refuses a body that is not exactly one JSON array.
func (p *patternFilterWriter) flushNetworkList(ctx context.Context, deps visibilityDeps, policy *compiledPolicy) error {
	if committed, err := p.commitIfUnfilterable(); committed {
		return err
	}
	body, err := p.decodedBody()
	if err != nil {
		return err
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("decode %s list response: %w", networkListPath, err)
	}
	if tok != json.Delim('[') {
		return fmt.Errorf("decode %s list response: expected a JSON array, got %T", networkListPath, tok)
	}

	memo := make(map[string]bool)
	kept := make([]json.RawMessage, 0)
	for dec.More() {
		var item map[string]json.RawMessage
		if err := dec.Decode(&item); err != nil {
			return fmt.Errorf("decode network list item: %w", err)
		}
		name, err := networkItemName(item)
		if err != nil {
			return err
		}
		if !policy.networkNameVisible(name) {
			continue
		}
		if err := narrowNetworkContainers(ctx, deps, policy, item, memo); err != nil {
			return err
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			return err
		}
		kept = append(kept, encoded)
	}
	closing, err := dec.Token()
	if err != nil {
		return fmt.Errorf("decode %s list response: array never closed: %w", networkListPath, err)
	}
	if closing != json.Delim(']') {
		return fmt.Errorf("decode %s list response: expected the array to close, got %v", networkListPath, closing)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode %s list response: trailing bytes after the JSON array", networkListPath)
	}

	out, err := json.Marshal(kept)
	if err != nil {
		return err
	}
	return p.commitFilteredBody(out)
}

// flushNetworkInspect filters GET /networks/{id}. A network the policy does not
// list answers 404 exactly like any other hidden resource (or, under a warn or
// audit rollout, is recorded as would_deny and forwarded unchanged), and a
// listed network's Containers map is narrowed to visible containers.
func (p *patternFilterWriter) flushNetworkInspect(ctx context.Context, deps visibilityDeps, policy *compiledPolicy, w http.ResponseWriter, r *http.Request) error {
	if committed, err := p.commitIfUnfilterable(); committed {
		return err
	}
	body, err := p.decodedBody()
	if err != nil {
		return err
	}
	var item map[string]json.RawMessage
	if err := json.Unmarshal(body, &item); err != nil {
		return fmt.Errorf("decode network inspect response: %w", err)
	}
	name, err := networkItemName(item)
	if err != nil {
		return err
	}
	if !policy.networkNameVisible(name) {
		const reason = "visibility policy hid resource"
		if logging.MetaForRequest(w, r).AllowsPassThrough() {
			logging.SetWouldDenyWithCode(w, r, reasonCodeVisibilityPolicyHidResource, reason, nil)
			return p.commitFilteredBody(body)
		}
		logging.SetDeniedWithCode(w, r, reasonCodeVisibilityPolicyHidResource, reason, nil)
		clearUpstreamRepresentationHeaders(p.underlying.Header())
		p.headerWritten = true
		return httpjson.Write(p.underlying, http.StatusNotFound, httpjson.ErrorResponse{Message: "resource not found"})
	}
	if err := narrowNetworkContainers(ctx, deps, policy, item, make(map[string]bool)); err != nil {
		return err
	}
	out, err := json.Marshal(item)
	if err != nil {
		return err
	}
	return p.commitFilteredBody(out)
}
