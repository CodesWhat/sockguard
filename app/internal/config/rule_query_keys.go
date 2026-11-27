package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// restoreCaseSensitiveKeys parses the YAML once and restores every map whose
// keys are data rather than schema: match.query and match.body keys and
// allowed_device_requests[].options keys.
func restoreCaseSensitiveKeys(cfg *Config, data []byte) {
	if len(data) == 0 {
		return
	}
	codec, err := viper.NewCodecRegistry().Decoder("yaml")
	if err != nil {
		return
	}
	raw := make(map[string]any)
	if err := codec.Decode(data, raw); err != nil {
		return
	}
	restoreRuleMatchKeys(cfg, raw)
	restoreDeviceRequestOptionKeys(cfg, raw)
}

// restoreRuleMatchKeys puts the original letter case back on match.query and
// match.body keys.
//
// Viper lowercases every map key it reads, which is harmless for the schema's
// own field names and wrong for a query or body key: those are case-sensitive
// on the wire, so a rule written for "Signal" that silently became "signal"
// would never match the request it was written for. On a deny rule that is a
// bypass, not a nuisance. The raw YAML still has the real spelling, so the
// keys (and their pattern lists) are re-read from it, by position, for the top
// level rules and each client profile's rules.
//
// Anything the raw document does not describe in the expected shape is left as
// Viper decoded it; validation then sees the same value it always would.
func restoreRuleMatchKeys(cfg *Config, raw map[string]any) {
	restoreRuleListMatchKeys(cfg.Rules, rawKey(raw, "rules"))
	clients, _ := rawKey(raw, "clients").(map[string]any)
	profiles, _ := rawKey(clients, "profiles").([]any)
	for i := range cfg.Clients.Profiles {
		if i >= len(profiles) {
			break
		}
		profile, _ := profiles[i].(map[string]any)
		restoreRuleListMatchKeys(cfg.Clients.Profiles[i].Rules, rawKey(profile, "rules"))
	}
}

func restoreRuleListMatchKeys(rules []RuleConfig, rawRules any) {
	list, ok := rawRules.([]any)
	if !ok || len(list) != len(rules) {
		return
	}
	for i := range rules {
		if len(rules[i].Match.Query) == 0 && len(rules[i].Match.Body) == 0 {
			continue
		}
		rule, _ := list[i].(map[string]any)
		match, _ := rawKey(rule, "match").(map[string]any)
		if len(rules[i].Match.Query) > 0 {
			query, _ := rawKey(match, "query").(map[string]any)
			if restored, ok := rawMatchValueConstraints(query); ok {
				rules[i].Match.Query = restored
			}
		}
		if len(rules[i].Match.Body) > 0 {
			body, _ := rawKey(match, "body").(map[string]any)
			if restored, ok := rawMatchValueConstraints(body); ok {
				rules[i].Match.Body = restored
			}
		}
	}
}

// rawKey looks up a schema key the way Viper does, ignoring letter case. The
// keys inside a query map are not looked up this way: those keep their case.
// When several spellings are present the lexically smallest one wins, so the
// result does not depend on map iteration order.
func rawKey(m map[string]any, name string) any {
	var (
		best  string
		value any
		found bool
	)
	for key, v := range m {
		if !strings.EqualFold(key, name) {
			continue
		}
		if !found || key < best {
			best, value, found = key, v, true
		}
	}
	return value
}

// rawMatchValueConstraints converts a raw YAML match.query or match.body map
// to the typed form with Viper's weak decoding rules for scalars (a bare
// value is a one-element list, numbers and booleans become their text). ok is
// false when any entry has a shape that decoding would not have accepted
// either. A null value, or a null entry in a list, yields a nil pattern list
// so validation rejects it instead of reading it as an empty-string pattern; a
// quoted "" stays valid.
func rawMatchValueConstraints(constraints map[string]any) (map[string][]string, bool) {
	if len(constraints) == 0 {
		return nil, false
	}
	out := make(map[string][]string, len(constraints))
	for key, value := range constraints {
		switch v := value.(type) {
		case []any:
			patterns := make([]string, 0, len(v))
			hasNull := false
			for _, item := range v {
				if item == nil {
					hasNull = true
					continue
				}
				text, ok := rawScalarText(item)
				if !ok {
					return nil, false
				}
				patterns = append(patterns, text)
			}
			if hasNull {
				patterns = nil
			}
			out[key] = patterns
		case nil:
			out[key] = nil
		default:
			text, ok := rawScalarText(v)
			if !ok {
				return nil, false
			}
			out[key] = []string{text}
		}
	}
	return out, true
}

func rawScalarText(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case bool, int, int64, uint64, float64:
		return fmt.Sprint(v), true
	default:
		return "", false
	}
}
