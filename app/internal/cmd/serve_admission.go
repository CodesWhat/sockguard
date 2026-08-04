package cmd

import (
	"net/http"

	"github.com/codeswhat/sockguard/internal/clientacl"
	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/inbound"
	"github.com/codeswhat/sockguard/internal/logging"
)

// withListenerAdmission enforces each effective listener's allowed_profiles
// scope (#149). It must run after clientacl's middleware has resolved the
// request's profile (clientacl.RequestProfile) — see the layer ordering
// comment in buildServeHandlerLayersWithRuntime — and reads the connection's
// listener identity from context (inbound.FromContext), never from a
// request header, so a client cannot forge which listener it arrived on.
//
// A listener whose AllowedProfiles is exactly the wildcard ("*", the legacy
// synthesized default and the explicit opt-in) admits every profile,
// including the unprofiled default-policy path, matching pre-#149 global
// behavior byte-for-byte — the gate is skipped entirely rather than
// evaluated against a permit-everything set. A concrete AllowedProfiles list
// only ever narrows: a resolved profile outside that list is denied with
// reason_code listener_profile_not_allowed. This function never retries
// against a weaker identity selector — the profile clientacl already
// resolved (certificate > unix peer > source IP > default) is final.
//
// Missing or unrecognized connection identity — the ConnContext hook did not
// run, or named a listener this config no longer knows about — is a
// programming/wiring error, not a client-controllable condition, so it fails
// closed with 500 rather than either silently admitting or silently
// denying.
func withListenerAdmission(cfg *config.Config) func(http.Handler) http.Handler {
	if len(cfg.Listeners) == 0 {
		// Legacy config (no explicit listeners: list): EffectiveListeners
		// synthesizes exactly one wildcard listener, which admits every
		// profile including the unprofiled default-policy path — there is
		// nothing to gate. Skipping the layer entirely (rather than
		// evaluating it against an always-true condition) also means this
		// layer imposes no new requirement on request context for the
		// pre-#149 behavior: only an operator who has actually opted into
		// listeners: needs inbound identity to be present on every request.
		return func(next http.Handler) http.Handler { return next }
	}

	byName := make(map[string]config.ListenerConfig, len(cfg.Listeners))
	for _, l := range cfg.Listeners {
		byName[l.Name] = l
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, ok := inbound.FromContext(r.Context())
			if !ok || identity.Role != inbound.RoleMain {
				denyListenerAdmission(w, r, http.StatusInternalServerError,
					"listener_identity_missing", "listener identity missing or invalid")
				return
			}

			entry, ok := byName[identity.Name]
			if !ok {
				denyListenerAdmission(w, r, http.StatusInternalServerError,
					"listener_config_missing", "listener configuration not found")
				return
			}

			if entry.Wildcard() {
				next.ServeHTTP(w, r)
				return
			}

			profile, ok := clientacl.RequestProfile(r)
			if !ok || !allowedProfileContains(entry.AllowedProfiles, profile) {
				denyListenerAdmission(w, r, http.StatusForbidden,
					"listener_profile_not_allowed", "client profile not allowed on this listener")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func allowedProfileContains(allowed []string, profile string) bool {
	for _, p := range allowed {
		if p == profile {
			return true
		}
	}
	return false
}

func denyListenerAdmission(w http.ResponseWriter, r *http.Request, status int, reasonCode, reason string) {
	logging.SetDeniedWithCode(w, r, reasonCode, reason, filter.NormalizePath)
	_ = httpjson.Write(w, status, httpjson.ErrorResponse{Message: reason})
}
