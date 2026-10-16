package filter

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"

	"github.com/codeswhat/sockguard/v2/app/internal/queryparam"
)

var podmanRunControlNames = []string{
	"nsoptions", "addcaps", "devices", "securityopt", "seccomp", "apparmor",
	"labelopts", "idmappingoptions", "groupadd", "cgroupparent", "ulimits",
	"shmsize", "dnsservers", "dnssearch", "dnsoptions", "from", "extrahosts", "isolation",
}

// KnownPodmanBuildControl validates the exact, versioned query-key grants.
func KnownPodmanBuildControl(name string) bool { return slices.Contains(podmanRunControlNames, name) }

type podmanBuildNamespace struct {
	Name string
	Host bool
	Path string
}

func privateBuildNetwork(raw string) bool {
	var namespaces []podmanBuildNamespace
	if json.Unmarshal([]byte(raw), &namespaces) != nil {
		return false
	}
	found := false
	for _, ns := range namespaces {
		if ns.Name == "network" {
			if ns.Host || ns.Path != "" {
				return false
			}
			found = true
		}
	}
	return found
}

func privateNetworkOnly(raw string) bool {
	var namespaces []podmanBuildNamespace
	if json.Unmarshal([]byte(raw), &namespaces) != nil || len(namespaces) == 0 {
		return false
	}
	for _, ns := range namespaces {
		if ns.Name != "network" || ns.Host || ns.Path != "" {
			return false
		}
	}
	return true
}

func (p buildPolicy) inspectPodmanRunControls(query url.Values, podman bool) string {
	if podman && !p.allowHostNetwork {
		raw, _, ok := queryparam.Scalar(query, "nsoptions")
		isolation, _, isolationOK := queryparam.Scalar(query, "isolation")
		if !ok || !isolationOK || !privateBuildNetwork(raw) || (isolation != "" && isolation != "oci" && isolation != "rootless") {
			return "build denied: host network mode is not allowed: RUN-enabled Podman builds require an explicit private network namespace"
		}
	}
	for _, key := range podmanRunControlNames {
		values, ok := queryparam.List(query, key)
		if !ok || len(values) > 1 {
			return ambiguousQueryReason("build", key)
		}
		if len(values) == 0 {
			continue
		}
		if key == "nsoptions" && privateNetworkOnly(values[0]) {
			continue
		}
		if _, allowed := p.allowedPodmanControls[key]; !allowed {
			return fmt.Sprintf("build denied: RUN control %q requires an allowed_podman_controls grant", key)
		}
	}
	return ""
}
