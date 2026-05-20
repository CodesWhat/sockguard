package cmd

import (
	"log/slog"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/ratelimit"
)

// warnAssignedProfilesWithoutLimits flags profiles that operators bound to a
// caller identity (mTLS, source IP, unix peer, default) but did not give any
// rate or concurrency configuration. Once any profile has limits configured,
// an unlimited assigned profile is almost always a config oversight, not an
// intentional carve-out — surface it at startup so operators notice before
// the proxy ships traffic.
func warnAssignedProfilesWithoutLimits(cfg *config.Config, limitedProfiles map[string]ratelimit.ProfileOptions, logger *slog.Logger) {
	assigned := make(map[string]struct{})
	if cfg.Clients.DefaultProfile != "" {
		assigned[cfg.Clients.DefaultProfile] = struct{}{}
	}
	for _, a := range cfg.Clients.SourceIPProfiles {
		if a.Profile != "" {
			assigned[a.Profile] = struct{}{}
		}
	}
	for _, a := range cfg.Clients.ClientCertificateProfiles {
		if a.Profile != "" {
			assigned[a.Profile] = struct{}{}
		}
	}
	for _, a := range cfg.Clients.UnixPeerProfiles {
		if a.Profile != "" {
			assigned[a.Profile] = struct{}{}
		}
	}
	for name := range assigned {
		if _, ok := limitedProfiles[name]; ok {
			continue
		}
		logger.Warn(
			"client profile is assigned to callers but has no rate or concurrency limits configured",
			slog.String("profile", name),
			slog.String("recommendation",
				"add clients.profiles[...].limits.rate, .concurrency, or .priority — or remove the assignment if unlimited access is intended"),
		)
	}
}

// configLimitsToRateLimitOptions converts a per-profile LimitsConfig to the
// ratelimit package's ProfileOptions. Returns zero-valued options (both nil)
// when no limits are configured.
func configLimitsToRateLimitOptions(profileName string, cfg config.LimitsConfig, logger *slog.Logger) ratelimit.ProfileOptions {
	var opts ratelimit.ProfileOptions
	if cfg.Priority != "" {
		var ok bool
		opts.Priority, ok = ratelimit.ParsePriority(cfg.Priority)
		if !ok {
			logger.Warn("unrecognized priority value in client profile; falling back to normal",
				slog.String("profile", profileName),
				slog.String("priority", cfg.Priority),
			)
		}
	}
	if cfg.Rate != nil {
		burst := cfg.Rate.Burst
		if burst == 0 {
			burst = cfg.Rate.TokensPerSecond
		}
		var costs []ratelimit.EndpointCost
		if len(cfg.Rate.EndpointCosts) > 0 {
			costs = make([]ratelimit.EndpointCost, 0, len(cfg.Rate.EndpointCosts))
			for _, ec := range cfg.Rate.EndpointCosts {
				costs = append(costs, ratelimit.EndpointCost{
					PathGlob: ec.Path,
					Methods:  ec.Methods,
					Cost:     ec.Cost,
				})
			}
		}
		opts.Rate = &ratelimit.RateOptions{
			TokensPerSecond: cfg.Rate.TokensPerSecond,
			Burst:           burst,
			EndpointCosts:   costs,
		}
	}
	if cfg.Concurrency != nil {
		opts.Concurrency = &ratelimit.ConcurrencyOptions{
			MaxInflight: cfg.Concurrency.MaxInflight,
		}
	}
	return opts
}
