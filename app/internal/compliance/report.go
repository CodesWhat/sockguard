package compliance

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/version"
)

// Generate evaluates every control against cfg. configBytes is the config file
// content the hash is taken over. Output depends only on its inputs: no
// clocks, hostnames, paths or map iteration.
func Generate(cfg *config.Config, configBytes []byte) Report {
	sum := sha256.Sum256(configBytes)
	r := Report{
		Benchmark:        Benchmark,
		SockguardVersion: version.Version,
		ConfigSHA256:     hex.EncodeToString(sum[:]),
		Disclaimer:       Disclaimer,
		Notes:            reportNotes(cfg),
		Controls:         make([]ControlResult, 0, len(controls)),
	}
	for _, c := range controls {
		var res ControlResult
		if c.Evaluate != nil {
			res = c.Evaluate(cfg)
		} else {
			res = ControlResult{Status: StatusOutsideScope, Evidence: []Evidence{}, Notes: []string{c.Reason}}
		}
		res.ID, res.Title, res.Category = c.ID, c.Title, c.Category
		if res.Evidence == nil {
			res.Evidence = []Evidence{}
		}
		if res.Notes == nil {
			res.Notes = []string{}
		}
		r.Controls = append(r.Controls, res)
		r.Summary.Total++
		switch res.Status {
		case StatusConfigured:
			r.Summary.Configured++
		case StatusNotConfigured:
			r.Summary.NotConfigured++
		case StatusPartial:
			r.Summary.Partial++
		case StatusAlwaysOn:
			r.Summary.AlwaysOn++
		case StatusNeedsEvidence:
			r.Summary.NeedsEvidence++
		case StatusOutsideScope:
			r.Summary.OutsideScope++
		}
	}
	return r
}

func reportNotes(cfg *config.Config) []string {
	notes := []string{}
	if cfg.PolicyBundle.Enabled {
		notes = append(notes, "policy_bundle.enabled is true. This report validates the config only; it does not check signed-policy startup requirements (the out-of-band trust config and the bundle signature), so serve can still refuse this config.")
	}
	if cfg.InsecureAllowBodyBlindWrites {
		notes = append(notes, "insecure_allow_body_blind_writes is true. It lets exec run without a command allowlist and relaxes Podman build controls, image load and container update fields that bodies can't be checked for. None of the mapped Section 5 knobs are relaxed: container create, privileged exec and root exec checks still apply.")
	}
	return notes
}
