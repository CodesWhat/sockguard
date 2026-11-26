package cmd

import (
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/ui"
)

// Profile selection strategies reported by `sockguard match`. They mirror the
// names clientacl logs for the strategies an offline run can reproduce.
const (
	matchSelectionNone           = "none"
	matchSelectionExplicit       = "explicit_profile"
	matchSelectionSourceIP       = "source_ip"
	matchSelectionDefaultProfile = "default_profile"
)

// matchSelection says which rule set decided the request and how that set was
// chosen. Profile is empty when the root rules ran.
type matchSelection struct {
	Strategy string `json:"strategy"`
	Profile  string `json:"profile,omitempty"`
	SourceIP string `json:"source_ip,omitempty"`
}

// matchOwnership is the ownership scope read from the configuration for the
// rule set that ran. It is configuration only: no resource labels were read.
type matchOwnership struct {
	Source                          string `json:"source"`
	Owner                           string `json:"owner,omitempty"`
	AllOwners                       bool   `json:"all_owners,omitempty"`
	AllowUnownedImages              bool   `json:"allow_unowned_images"`
	AllowCrossOwnerNamespaceSharing bool   `json:"allow_cross_owner_namespace_sharing"`
}

// matchVisibility is one scope's configured read-side visibility lists.
type matchVisibility struct {
	VisibleResourceLabels []string `json:"visible_resource_labels,omitempty"`
	NamePatterns          []string `json:"name_patterns,omitempty"`
	ImagePatterns         []string `json:"image_patterns,omitempty"`
	VisibleNetworks       []string `json:"visible_networks,omitempty"`
}

func (v matchVisibility) empty() bool {
	return len(v.VisibleResourceLabels) == 0 && len(v.NamePatterns) == 0 &&
		len(v.ImagePatterns) == 0 && len(v.VisibleNetworks) == 0
}

// matchResponsePolicy is the configured response policy: the effective
// redaction switches for the selected scope plus the root and profile
// visibility lists. The visibility layer combines the two lists at request
// time, and this report does not merge them.
type matchResponsePolicy struct {
	Redaction  matchRedaction   `json:"redaction"`
	Root       *matchVisibility `json:"root_visibility,omitempty"`
	Profile    *matchVisibility `json:"profile_visibility,omitempty"`
	Visibility string           `json:"visibility_note,omitempty"`
}

type matchRedaction struct {
	ContainerEnv    bool `json:"container_env"`
	MountPaths      bool `json:"mount_paths"`
	NetworkTopology bool `json:"network_topology"`
	SensitiveData   bool `json:"sensitive_data"`
	HostTopology    bool `json:"host_topology"`
}

// selectMatchProfile resolves which client profile the offline request runs
// under. An explicit profile name wins; otherwise a source IP is walked
// through clients.source_ip_profiles in config order and then
// clients.default_profile, the order the running proxy uses after client
// certificate and unix peer selection (which an offline run cannot reproduce).
// With neither flag the root rules run, as `match` always did.
func selectMatchProfile(cfg *config.Config, explicit, sourceIP string) (*config.ClientProfileConfig, matchSelection, error) {
	explicit = strings.TrimSpace(explicit)
	sourceIP = strings.TrimSpace(sourceIP)
	if explicit != "" && sourceIP != "" {
		return nil, matchSelection{}, fmt.Errorf("--profile and --source-ip are mutually exclusive: --profile names the profile directly, --source-ip selects one the way the proxy would")
	}

	if explicit != "" {
		profile := findMatchProfile(cfg, explicit)
		if profile == nil {
			return nil, matchSelection{}, fmt.Errorf("profile %q is not defined under clients.profiles", explicit)
		}
		return profile, matchSelection{Strategy: matchSelectionExplicit, Profile: profile.Name}, nil
	}

	if sourceIP == "" {
		return nil, matchSelection{Strategy: matchSelectionNone}, nil
	}

	addr, err := netip.ParseAddr(sourceIP)
	if err != nil {
		return nil, matchSelection{}, fmt.Errorf("source IP %q is not a valid IP address: %w", sourceIP, err)
	}
	addr = addr.Unmap()

	for _, assignment := range cfg.Clients.SourceIPProfiles {
		for _, cidr := range assignment.CIDRs {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
			if err != nil {
				return nil, matchSelection{}, fmt.Errorf("clients.source_ip_profiles cidr %q: %w", cidr, err)
			}
			if prefix.Contains(addr) {
				return selectedMatchProfile(cfg, assignment.Profile, matchSelectionSourceIP, addr)
			}
		}
	}
	if cfg.Clients.DefaultProfile != "" {
		return selectedMatchProfile(cfg, cfg.Clients.DefaultProfile, matchSelectionDefaultProfile, addr)
	}
	return nil, matchSelection{Strategy: matchSelectionNone, SourceIP: addr.String()}, nil
}

func selectedMatchProfile(cfg *config.Config, name, strategy string, addr netip.Addr) (*config.ClientProfileConfig, matchSelection, error) {
	profile := findMatchProfile(cfg, name)
	if profile == nil {
		return nil, matchSelection{}, fmt.Errorf("profile %q selected by %s is not defined under clients.profiles", name, strategy)
	}
	return profile, matchSelection{Strategy: strategy, Profile: profile.Name, SourceIP: addr.String()}, nil
}

func findMatchProfile(cfg *config.Config, name string) *config.ClientProfileConfig {
	for i := range cfg.Clients.Profiles {
		if cfg.Clients.Profiles[i].Name == name {
			return &cfg.Clients.Profiles[i]
		}
	}
	return nil
}

func explainMatchOwnership(cfg *config.Config, profile *config.ClientProfileConfig) *matchOwnership {
	eff := cfg.EffectiveOwnership(profile)
	source := "root"
	if profile != nil {
		source = "profile " + profile.Name
	}
	return &matchOwnership{
		Source:                          source,
		Owner:                           eff.Owner,
		AllOwners:                       eff.AllOwners,
		AllowUnownedImages:              eff.AllowUnownedImages,
		AllowCrossOwnerNamespaceSharing: eff.AllowCrossOwnerNamespaceSharing,
	}
}

func explainMatchResponse(cfg *config.Config, profile *config.ClientProfileConfig) *matchResponsePolicy {
	redaction := cfg.Response.RedactionSettings()
	root := matchVisibility{
		VisibleResourceLabels: cfg.Response.VisibleResourceLabels,
		NamePatterns:          cfg.Response.NamePatterns,
		ImagePatterns:         cfg.Response.ImagePatterns,
		VisibleNetworks:       cfg.Response.VisibleNetworks,
	}
	out := &matchResponsePolicy{}
	if !root.empty() {
		out.Root = &root
	}
	if profile != nil {
		redaction = profile.Response.ApplyRedaction(redaction)
		scoped := matchVisibility{
			VisibleResourceLabels: profile.Response.VisibleResourceLabels,
			NamePatterns:          profile.Response.NamePatterns,
			ImagePatterns:         profile.Response.ImagePatterns,
			VisibleNetworks:       profile.Response.VisibleNetworks,
		}
		if !scoped.empty() {
			out.Profile = &scoped
		}
	}
	if out.Root != nil || out.Profile != nil {
		out.Visibility = "configured lists only; the running proxy combines root and profile lists per request and no live resource was read"
	}
	out.Redaction = matchRedaction{
		ContainerEnv:    redaction.ContainerEnv,
		MountPaths:      redaction.MountPaths,
		NetworkTopology: redaction.NetworkTopology,
		SensitiveData:   redaction.SensitiveData,
		HostTopology:    redaction.HostTopology,
	}
	return out
}

// matchNotInspected lists what an offline `match` run never looks at, so the
// output cannot be read as a claim about live state. The profile-selection
// entry is added only when the config assigns profiles by something other than
// source IP and the run chose a profile by IP.
func matchNotInspected(cfg *config.Config, selection matchSelection) []string {
	notes := []string{
		"request body (body inspectors such as container create, exec and build run only on a real request)",
		"live resources (ownership labels, visibility lists and response redaction are reported from configuration, not applied to any resource)",
	}
	if selection.Strategy == matchSelectionSourceIP || selection.Strategy == matchSelectionDefaultProfile || selection.Strategy == matchSelectionNone && selection.SourceIP != "" {
		if len(cfg.Clients.ClientCertificateProfiles) > 0 || len(cfg.Clients.UnixPeerProfiles) > 0 {
			notes = append(notes, "client certificate and unix peer profile assignments (a connection that matches one selects its profile before source IP)")
		}
	}
	return notes
}

func writeMatchExplanation(w io.Writer, p *ui.Printer, label func(string) string, result matchResult) {
	if result.Selection != nil && result.Selection.Strategy != matchSelectionNone {
		line := result.Selection.Strategy
		if result.Selection.SourceIP != "" {
			line += " (" + result.Selection.SourceIP + ")"
		}
		fmt.Fprintf(w, "%s %s\n", label("Profile:"), result.Selection.Profile)
		fmt.Fprintf(w, "%s %s\n", label("Selected by:"), line)
	} else if result.Selection != nil && result.Selection.SourceIP != "" {
		fmt.Fprintf(w, "%s %s\n", label("Profile:"), "none matched "+result.Selection.SourceIP+", root rules ran")
	}
	if result.RolloutMode != "" && result.RolloutMode != string(config.RolloutEnforce) {
		note := result.RolloutMode
		if result.PassThrough {
			note += " (a deny passes through to Docker)"
		}
		fmt.Fprintf(w, "%s %s\n", label("Rollout mode:"), note)
	}
	if o := result.Ownership; o != nil {
		fmt.Fprintf(w, "%s %s\n", label("Ownership:"), describeMatchOwnership(o))
	}
	if r := result.Response; r != nil {
		fmt.Fprintf(w, "%s %s\n", label("Response:"), describeMatchRedaction(r.Redaction))
		if r.Root != nil {
			fmt.Fprintf(w, "%s %s\n", label("Root visible:"), describeMatchVisibility(*r.Root))
		}
		if r.Profile != nil {
			fmt.Fprintf(w, "%s %s\n", label("Profile visible:"), describeMatchVisibility(*r.Profile))
		}
		if r.Visibility != "" {
			fmt.Fprintf(w, "%s %s\n", label(""), p.Dim(r.Visibility))
		}
	}
	for _, note := range result.NotInspected {
		fmt.Fprintf(w, "%s %s\n", label("Not inspected:"), note)
	}
}

func describeMatchOwnership(o *matchOwnership) string {
	switch {
	case o.Owner == "":
		return "off (" + o.Source + " sets no owner)"
	case o.AllOwners:
		return fmt.Sprintf("owner %q, scope all owners (%s)", o.Owner, o.Source)
	default:
		return fmt.Sprintf("owner %q (%s), unowned images %s, cross-owner namespace sharing %s",
			o.Owner, o.Source, onOff(o.AllowUnownedImages, "allowed", "denied"), onOff(o.AllowCrossOwnerNamespaceSharing, "allowed", "denied"))
	}
}

func describeMatchRedaction(r matchRedaction) string {
	var on []string
	for _, item := range []struct {
		name string
		set  bool
	}{
		{"container env", r.ContainerEnv},
		{"mount paths", r.MountPaths},
		{"network topology", r.NetworkTopology},
		{"sensitive data", r.SensitiveData},
		{"host topology", r.HostTopology},
	} {
		if item.set {
			on = append(on, item.name)
		}
	}
	if len(on) == 0 {
		return "no redaction configured"
	}
	return "redacts " + strings.Join(on, ", ")
}

func describeMatchVisibility(v matchVisibility) string {
	var parts []string
	if len(v.VisibleResourceLabels) > 0 {
		parts = append(parts, "labels "+strings.Join(v.VisibleResourceLabels, ","))
	}
	if len(v.NamePatterns) > 0 {
		parts = append(parts, "names "+strings.Join(v.NamePatterns, ","))
	}
	if len(v.ImagePatterns) > 0 {
		parts = append(parts, "images "+strings.Join(v.ImagePatterns, ","))
	}
	if len(v.VisibleNetworks) > 0 {
		parts = append(parts, "networks "+strings.Join(v.VisibleNetworks, ","))
	}
	return strings.Join(parts, "; ")
}

func onOff(v bool, on, off string) string {
	if v {
		return on
	}
	return off
}
