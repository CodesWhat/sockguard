package clientacl

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
)

const DefaultLabelPrefix = "com.sockguard.allow."

// Options configures client admission and per-client container-label ACLs.
type Options struct {
	AllowedCIDRs    []string
	ContainerLabels ContainerLabelOptions
}

// ContainerLabelOptions configures opt-in ACLs loaded from the caller
// container's labels after resolving the client by source IP.
type ContainerLabelOptions struct {
	Enabled     bool
	LabelPrefix string
}

type aclDeps struct {
	resolveClient func(context.Context, netip.Addr) (resolvedClient, bool, error)
}

type resolvedClient struct {
	ID     string
	Name   string
	Labels map[string]string
}

type compiledOptions struct {
	allowedCIDRs []netip.Prefix
	labelPrefix  string
	labelsOn     bool
}

type listedContainer struct {
	ID              string            `json:"Id"`
	Names           []string          `json:"Names"`
	Labels          map[string]string `json:"Labels"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress         string `json:"IPAddress"`
			GlobalIPv6Address string `json:"GlobalIPv6Address"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

type upstreamResolver struct {
	client *http.Client
}

// Middleware applies client CIDR admission checks and optional per-client
// label ACLs resolved from the caller container's source IP.
func Middleware(upstreamSocket string, logger *slog.Logger, opts Options) func(http.Handler) http.Handler {
	return middlewareWithDeps(logger, opts, newACLDeps(upstreamSocket))
}

func middlewareWithDeps(logger *slog.Logger, opts Options, deps aclDeps) func(http.Handler) http.Handler {
	compiled, err := compileOptions(opts)
	if err != nil {
		logger.Error("invalid client ACL config", "error", err)
		return func(http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				setDeniedMeta(w, r, "client ACL misconfigured")
				_ = httpjson.Write(w, http.StatusInternalServerError, httpjson.ErrorResponse{Message: "client ACL misconfigured"})
			})
		}
	}

	if len(compiled.allowedCIDRs) == 0 && !compiled.labelsOn {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP, ipOK := remoteIP(r.RemoteAddr)
			if len(compiled.allowedCIDRs) > 0 {
				if !ipOK || !ipAllowed(clientIP, compiled.allowedCIDRs) {
					setDeniedMeta(w, r, "client IP not allowed")
					_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: "client IP not allowed"})
					return
				}
			}

			if !compiled.labelsOn || !ipOK {
				next.ServeHTTP(w, r)
				return
			}

			client, found, err := deps.resolveClient(r.Context(), clientIP)
			if err != nil {
				logger.ErrorContext(r.Context(), "client label ACL lookup failed", "error", err, "client_ip", clientIP.String())
				setDeniedMeta(w, r, "client label ACL lookup failed")
				_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: "client label ACL lookup failed"})
				return
			}
			if !found {
				next.ServeHTTP(w, r)
				return
			}

			rules, hasACLLabels, err := compileContainerLabelRules(client.Labels, compiled.labelPrefix)
			if err != nil {
				logger.ErrorContext(
					r.Context(),
					"client label ACL evaluation failed",
					"error", err,
					"client_ip", clientIP.String(),
					"client_container", clientName(client),
				)
				setDeniedMeta(w, r, "client label ACL evaluation failed")
				_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: "client label ACL evaluation failed"})
				return
			}
			if !hasACLLabels {
				next.ServeHTTP(w, r)
				return
			}

			action, _, _ := filter.Evaluate(rules, r)
			if action == filter.ActionAllow {
				next.ServeHTTP(w, r)
				return
			}

			setDeniedMeta(w, r, "client label policy denied request")
			_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: "client label policy denied request"})
		})
	}
}

func newACLDeps(upstreamSocket string) aclDeps {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", upstreamSocket)
		},
	}
	resolver := upstreamResolver{
		client: &http.Client{Transport: transport},
	}
	return aclDeps{
		resolveClient: resolver.resolveClient,
	}
}

func compileOptions(opts Options) (compiledOptions, error) {
	compiled := compiledOptions{
		labelPrefix: opts.ContainerLabels.LabelPrefix,
		labelsOn:    opts.ContainerLabels.Enabled,
	}
	if compiled.labelsOn && compiled.labelPrefix == "" {
		compiled.labelPrefix = DefaultLabelPrefix
	}

	compiled.allowedCIDRs = make([]netip.Prefix, 0, len(opts.AllowedCIDRs))
	for _, raw := range opts.AllowedCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return compiled, fmt.Errorf("parse allowed CIDR %q: %w", raw, err)
		}
		compiled.allowedCIDRs = append(compiled.allowedCIDRs, prefix.Masked())
	}

	return compiled, nil
}

func remoteIP(remoteAddr string) (netip.Addr, bool) {
	if remoteAddr == "" {
		return netip.Addr{}, false
	}

	host := remoteAddr
	if splitHost, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = splitHost
	}

	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func ipAllowed(addr netip.Addr, allowed []netip.Prefix) bool {
	for _, prefix := range allowed {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func compileContainerLabelRules(labels map[string]string, labelPrefix string) ([]*filter.CompiledRule, bool, error) {
	return compileContainerLabelRulesWith(labels, labelPrefix, filter.CompileRule)
}

func compileContainerLabelRulesWith(
	labels map[string]string,
	labelPrefix string,
	compileRule func(filter.Rule) (*filter.CompiledRule, error),
) ([]*filter.CompiledRule, bool, error) {
	if len(labels) == 0 {
		return nil, false, nil
	}

	rules := make([]*filter.CompiledRule, 0)
	hasACLLabels := false
	index := 0
	for key, value := range labels {
		if !strings.HasPrefix(key, labelPrefix) {
			continue
		}
		hasACLLabels = true

		method, ok := labelMethod(key, labelPrefix)
		if !ok {
			return nil, true, fmt.Errorf("unsupported client ACL label %q", key)
		}

		patterns := splitLabelPatterns(value)
		if len(patterns) == 0 {
			return nil, true, fmt.Errorf("empty client ACL label %q", key)
		}

		for _, pattern := range patterns {
			rule, err := compileRule(filter.Rule{
				Methods: []string{method},
				Pattern: pattern,
				Action:  filter.ActionAllow,
				Index:   index,
			})
			if err != nil {
				return nil, true, fmt.Errorf("compile client ACL label %q: %w", key, err)
			}
			rules = append(rules, rule)
			index++
		}
	}

	return rules, hasACLLabels, nil
}

func labelMethod(key, labelPrefix string) (string, bool) {
	switch strings.ToUpper(strings.TrimPrefix(key, labelPrefix)) {
	case http.MethodGet:
		return http.MethodGet, true
	case http.MethodHead:
		return http.MethodHead, true
	case http.MethodPost:
		return http.MethodPost, true
	case http.MethodPut:
		return http.MethodPut, true
	case http.MethodDelete:
		return http.MethodDelete, true
	case http.MethodPatch:
		return http.MethodPatch, true
	case http.MethodOptions:
		return http.MethodOptions, true
	case http.MethodConnect:
		return http.MethodConnect, true
	case http.MethodTrace:
		return http.MethodTrace, true
	default:
		return "", false
	}
}

func splitLabelPatterns(value string) []string {
	parts := strings.Split(value, ",")
	patterns := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		patterns = append(patterns, trimmed)
	}
	return patterns
}

func (r upstreamResolver) resolveClient(ctx context.Context, addr netip.Addr) (resolvedClient, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/json", nil)
	if err != nil {
		return resolvedClient{}, false, err
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return resolvedClient{}, false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return resolvedClient{}, false, fmt.Errorf("docker container lookup status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var containers []listedContainer
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return resolvedClient{}, false, err
	}

	for _, container := range containers {
		if containerHasIP(container, addr) {
			return resolvedClient{
				ID:     container.ID,
				Name:   firstContainerName(container.Names),
				Labels: container.Labels,
			}, true, nil
		}
	}

	return resolvedClient{}, false, nil
}

func containerHasIP(container listedContainer, addr netip.Addr) bool {
	for _, network := range container.NetworkSettings.Networks {
		if ipMatches(network.IPAddress, addr) || ipMatches(network.GlobalIPv6Address, addr) {
			return true
		}
	}
	return false
}

func ipMatches(raw string, want netip.Addr) bool {
	if raw == "" {
		return false
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return false
	}
	return addr.Unmap() == want
}

func firstContainerName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return strings.TrimPrefix(names[0], "/")
}

func clientName(client resolvedClient) string {
	if client.Name != "" {
		return client.Name
	}
	return client.ID
}

func setDeniedMeta(w http.ResponseWriter, r *http.Request, reason string) {
	if meta := logging.MetaForRequest(w, r); meta != nil {
		meta.Decision = "deny"
		meta.Reason = reason
		if meta.NormPath == "" {
			meta.NormPath = filter.NormalizePath(r.URL.Path)
		}
	}
}
