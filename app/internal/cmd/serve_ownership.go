package cmd

import (
	"log/slog"
	"net/http"

	"github.com/codeswhat/sockguard/v3/app/internal/clientacl"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/logging"
	"github.com/codeswhat/sockguard/v3/app/internal/ownership"
	"github.com/codeswhat/sockguard/v3/app/internal/upstreamflavor"
)

// ownerScopeKey identifies one distinct effective ownership. Profiles that
// resolve to the same key share one ownership.Options and one middleware.
type ownerScopeKey struct {
	owner              string
	allowUnownedImages bool
	allowCrossOwnerNS  bool
	allOwners          bool
}

func ownerScopeKeyOf(eff config.EffectiveOwnership) ownerScopeKey {
	return ownerScopeKey{
		owner:              eff.Owner,
		allowUnownedImages: eff.AllowUnownedImages,
		allowCrossOwnerNS:  eff.AllowCrossOwnerNamespaceSharing,
		allOwners:          eff.AllOwners,
	}
}

// ownerScopes is the per-request ownership selector built at chain-build time.
// root serves requests with no profile (and profiles that inherit the root
// ownership unchanged); byProfile holds only profiles whose effective
// ownership differs from root.
type ownerScopes struct {
	root      ownerScopeKey
	byProfile map[string]ownerScopeKey
}

func newOwnerScopes(cfg *config.Config) ownerScopes {
	scopes := ownerScopes{root: ownerScopeKeyOf(cfg.EffectiveOwnership(nil)), byProfile: map[string]ownerScopeKey{}}
	for i := range cfg.Clients.Profiles {
		profile := &cfg.Clients.Profiles[i]
		if key := ownerScopeKeyOf(cfg.EffectiveOwnership(profile)); key != scopes.root {
			scopes.byProfile[profile.Name] = key
		}
	}
	return scopes
}

// distinct returns every distinct key, root first.
func (s ownerScopes) distinct() []ownerScopeKey {
	keys := []ownerScopeKey{s.root}
	seen := map[ownerScopeKey]struct{}{s.root: {}}
	for _, key := range s.byProfile {
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys
}

func (s ownerScopes) keyFor(profile string, hasProfile bool) ownerScopeKey {
	if hasProfile {
		if key, ok := s.byProfile[profile]; ok {
			return key
		}
	}
	return s.root
}

func (k ownerScopeKey) options(cfg *config.Config, capabilities upstreamflavor.Capabilities) ownership.Options {
	return ownership.Options{
		Owner:                           k.owner,
		LabelKey:                        cfg.Ownership.LabelKey,
		AllowUnownedImages:              k.allowUnownedImages,
		AllowCrossOwnerNamespaceSharing: k.allowCrossOwnerNS,
		AllOwners:                       k.allOwners,
		UpstreamFlavor:                  capabilities.Flavor,
		UpstreamProbedDocker:            capabilities.ProbedDocker,
		PodmanConjunctiveVolumeFilters:  capabilities.PodmanConjunctiveVolumeFilters,
	}
}

// logOwnerScopes names, at startup, every profile that runs under its own
// owner or lifts owner scoping, so the privileged ones are visible in logs.
func logOwnerScopes(cfg *config.Config, scopes ownerScopes, logger *slog.Logger) {
	for _, profile := range cfg.Clients.Profiles {
		key, ok := scopes.byProfile[profile.Name]
		if !ok {
			continue
		}
		if key.allOwners {
			logger.Warn("client profile lifts owner scoping (ownership.scope: all)", "profile", profile.Name, "owner", key.owner)
			continue
		}
		logger.Info("client profile has its own owner", "profile", profile.Name, "owner", key.owner)
	}
	if cfg.Ownership.InsecureAllowWeakOwnerSelection {
		logger.Warn("ownership.insecure_allow_weak_owner_selection is set: profile owners may be selected by source IP or default_profile")
	}
}

// withOwnership applies owner scoping per request. One ownership middleware is
// built for each distinct effective ownership; the request's resolved client
// profile (clientacl.RequestProfile) picks which one runs, and a request with
// no profile uses the root ownership. With no profile overriding the root this
// is exactly the single root middleware.
func withOwnership(cfg *config.Config, res http.RoundTripper, logger *slog.Logger, capabilities upstreamflavor.Capabilities, locks *ownership.KeyedLocks) func(http.Handler) http.Handler {
	scopes := newOwnerScopes(cfg)
	if locks == nil {
		locks = ownership.NewKeyedLocks(0, 0)
	}
	if len(scopes.byProfile) == 0 {
		opts := scopes.root.options(cfg, capabilities)
		opts.Locks = locks
		return ownership.MiddlewareWithRoundTripper(res, logger, opts)
	}
	logOwnerScopes(cfg, scopes, logger)
	middlewares := make(map[ownerScopeKey]func(http.Handler) http.Handler, len(scopes.byProfile)+1)
	// Every generation shares the process lock set, including single-owner
	// generations that overlap a reload changing the effective owners.
	for _, key := range scopes.distinct() {
		opts := key.options(cfg, capabilities)
		opts.Locks = locks
		middlewares[key] = ownership.MiddlewareWithRoundTripper(res, logger, opts)
	}
	return func(next http.Handler) http.Handler {
		handlers := make(map[ownerScopeKey]http.Handler, len(middlewares))
		for key, mw := range middlewares {
			handlers[key] = mw(next)
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name, ok := clientacl.RequestProfile(r)
			handlers[scopes.keyFor(name, ok)].ServeHTTP(w, r)
		})
	}
}

// auditOwnershipFor builds the per-profile effective ownership the audit
// event reports, for profiles whose ownership differs from root.
func auditOwnershipFor(cfg *config.Config) map[string]logging.AuditOwnership {
	scopes := newOwnerScopes(cfg)
	if len(scopes.byProfile) == 0 {
		return nil
	}
	out := make(map[string]logging.AuditOwnership, len(scopes.byProfile))
	for name, key := range scopes.byProfile {
		scope := "owner"
		if key.allOwners {
			scope = "all"
		}
		out[name] = logging.AuditOwnership{Owner: key.owner, Scope: scope}
	}
	return out
}
