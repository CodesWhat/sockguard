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
		case StatusOutsideScope:
			r.Summary.OutsideScope++
		}
	}
	return r
}
