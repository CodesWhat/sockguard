package config

import "strings"

// restoreDeviceRequestOptionKeys puts the original letter case back on
// allowed_device_requests[].options keys.
//
// Viper lowercases every map key it reads, but these keys are matched byte for
// byte against a request's DeviceRequest Options, so an option written as
// Visible must stay Visible: the lowercased grant would deny the key the
// operator wrote and admit one they never did. The raw YAML still has the real
// spelling, so each entry's options are re-read from it by position, for the
// top level container_create list and for every client profile's.
//
// Anything the raw document does not describe in the expected shape is left as
// Viper decoded it.
func restoreDeviceRequestOptionKeys(cfg *Config, raw map[string]any) {
	body, _ := rawKey(raw, "request_body").(map[string]any)
	restoreDeviceRequestListOptionKeys(cfg.RequestBody.ContainerCreate.AllowedDeviceRequests, rawContainerCreateDeviceRequests(body))

	clients, _ := rawKey(raw, "clients").(map[string]any)
	profiles, _ := rawKey(clients, "profiles").([]any)
	for i := range cfg.Clients.Profiles {
		if i >= len(profiles) {
			break
		}
		profile, _ := profiles[i].(map[string]any)
		profileBody, _ := rawKey(profile, "request_body").(map[string]any)
		restoreDeviceRequestListOptionKeys(cfg.Clients.Profiles[i].RequestBody.ContainerCreate.AllowedDeviceRequests, rawContainerCreateDeviceRequests(profileBody))
	}
}

func rawContainerCreateDeviceRequests(requestBody map[string]any) any {
	containerCreate, _ := rawKey(requestBody, "container_create").(map[string]any)
	return rawKey(containerCreate, "allowed_device_requests")
}

func restoreDeviceRequestListOptionKeys(entries []AllowedDeviceRequest, rawEntries any) {
	list, ok := rawEntries.([]any)
	if !ok || len(list) != len(entries) {
		return
	}
	for i := range entries {
		if len(entries[i].Options) == 0 {
			continue
		}
		entry, _ := list[i].(map[string]any)
		options, _ := rawKey(entry, "options").(map[string]any)
		if restored, ok := rawDeviceOptions(options, entries[i].Options); ok {
			entries[i].Options = restored
		}
	}
}

// rawDeviceOptions rebuilds an options map with the raw key spellings. ok is
// false when a value is not a scalar, or when the lowercased raw keys are not
// exactly the keys Viper decoded, so a shape this does not understand is left
// as decoded. Keys that differ only by case both survive, since they are
// distinct options on the wire.
func rawDeviceOptions(options map[string]any, decoded map[string]string) (map[string]string, bool) {
	if len(options) == 0 {
		return nil, false
	}
	out := make(map[string]string, len(options))
	lowered := make(map[string]struct{}, len(options))
	for key, value := range options {
		text, ok := rawScalarText(value)
		if !ok {
			return nil, false
		}
		out[key] = text
		lowered[strings.ToLower(key)] = struct{}{}
	}
	if len(lowered) != len(decoded) {
		return nil, false
	}
	for key := range decoded {
		if _, ok := lowered[key]; !ok {
			return nil, false
		}
	}
	return out, true
}
