package cmd

import (
	"log/slog"
	"net/http"

	"github.com/codeswhat/sockguard/v3/app/internal/admin"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/reload"
)

func withPolicyDiffEndpoint(cfg *config.Config, logger *slog.Logger, versioner *admin.PolicyVersioner) func(http.Handler) http.Handler {
	var source func() *admin.PolicySnapshot
	if versioner != nil {
		source = versioner.Snapshot
	}
	return admin.NewPolicyDiffInterceptor(admin.PolicyDiffOptions{
		Path: cfg.Admin.PolicyDiffPath, MaxRequestBytes: cfg.Admin.MaxRequestBytes,
		Source: source, Compare: compareAdminPolicy, Logger: logger,
	})
}

func compareAdminPolicy(body []byte, snapshot *admin.PolicySnapshot) admin.PolicyDiffResponse {
	candidate, err := config.LoadBytes(body)
	if err != nil {
		return admin.PolicyDiffResponse{Error: "candidate configuration could not be parsed"}
	}
	config.ApplyCompat(candidate, discardLogger)
	if _, err := validateAndCompileRulesStructural(candidate); err != nil {
		return admin.PolicyDiffResponse{Error: "candidate configuration failed validation"}
	}
	unknown, err := config.UnknownKeysBytes(body)
	if err != nil {
		return admin.PolicyDiffResponse{Error: "candidate configuration could not be parsed"}
	}
	changes := config.PolicyChanges(snapshot.Config, candidate)
	return admin.PolicyDiffResponse{
		OK: true, BaseVersion: snapshot.Version, Changed: len(changes) > 0,
		Changes: changes, UnknownKeys: len(unknown), Validation: "structural",
		RestartRequired: len(reload.ImmutableDiff(snapshot.Config, candidate)) > 0,
	}
}
