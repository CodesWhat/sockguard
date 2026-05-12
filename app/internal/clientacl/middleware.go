package clientacl

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/codeswhat/sockguard/internal/dockerclient"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/pkipin"
)

const DefaultLabelPrefix = "com.sockguard.allow."

const (
	reasonCodeClientACLMisconfigured     = "client_acl_misconfigured"
	reasonCodeClientIPNotAllowed         = "client_ip_not_allowed"
	reasonCodeClientIdentityLookupFailed = "client_identity_lookup_failed"
	reasonCodeClientLabelACLLookupFailed = "client_label_acl_lookup_failed"
	reasonCodeClientLabelACLEvalFailed   = "client_label_acl_evaluation_failed"
	reasonCodeClientLabelPolicyDenied    = "client_label_policy_denied_request"
)

// Options configures client admission and per-client container-label ACLs.
type Options struct {
	AllowedCIDRs    []string
	ContainerLabels ContainerLabelOptions
	Profiles        ProfileOptions
}

// ContainerLabelOptions configures opt-in ACLs loaded from the caller
// container's labels after resolving the client by source IP.
type ContainerLabelOptions struct {
	Enabled     bool
	LabelPrefix string
}

// ProfileOptions configures named profile selection for callers.
type ProfileOptions struct {
	DefaultProfile     string
	SourceIPs          []SourceIPProfileAssignment
	ClientCertificates []ClientCertificateProfileAssignment
	UnixPeers          []UnixPeerProfileAssignment
}

// SourceIPProfileAssignment maps one or more source CIDRs to a named profile.
type SourceIPProfileAssignment struct {
	Profile string
	CIDRs   []string
}

// ClientCertificateProfileAssignment maps one or more client-certificate common
// names to a named profile.
type ClientCertificateProfileAssignment struct {
	Profile             string
	CommonNames         []string
	DNSNames            []string
	IPAddresses         []string
	URISANs             []string
	SPIFFEIDs           []string
	PublicKeySHA256Pins []string
}

// UnixPeerProfileAssignment maps unix peer credentials to a named profile.
type UnixPeerProfileAssignment struct {
	Profile string
	UIDs    []uint32
	GIDs    []uint32
	PIDs    []int32
}


type resolvedClient struct {
	ID     string
	Name   string
	Labels map[string]string
}

type compiledOptions struct {
	allowedCIDRs           []netip.Prefix
	labelPrefix            string
	labelsOn               bool
	defaultProfile         string
	sourceIPProfiles       []compiledSourceIPProfileAssignment
	sourceIPProfileIndex   *sourceIPProfileIndex
	clientCertProfiles     []compiledClientCertificateProfileAssignment
	clientCertProfileIndex *clientCertificateProfileIndex
	unixPeerProfiles       []compiledUnixPeerProfileAssignment
}

type profileMatchStrategy string

const (
	profileMatchStrategyClientCertificate profileMatchStrategy = "client_certificate"
	profileMatchStrategyUnixPeer          profileMatchStrategy = "unix_peer"
	profileMatchStrategySourceIP          profileMatchStrategy = "source_ip"
	profileMatchStrategyDefaultProfile    profileMatchStrategy = "default_profile"
)

type profileLookupResult struct {
	profile string
	ok      bool
}

// These per-process runtime indexes avoid re-scanning the configured profile
// assignments on every request for the same concrete client IP or certificate.
// Selection semantics stay the same: the first lookup for a key still walks the
// assignment list in config order, then memoizes that first-match-wins result.
type sourceIPProfileIndex struct {
	mu    sync.RWMutex
	cache map[netip.Addr]profileLookupResult
}

type clientCertificateProfileIndex struct {
	mu    sync.RWMutex
	cache map[[sha256.Size]byte]profileLookupResult
}

type compiledSourceIPProfileAssignment struct {
	profile string
	cidrs   []netip.Prefix
}

type compiledClientCertificateProfileAssignment struct {
	profile             string
	commonNames         []string
	dnsNames            []string
	ipAddresses         []netip.Addr
	uriSANs             []string
	spiffeIDs           []string
	publicKeySHA256Pins []string
}

type compiledUnixPeerProfileAssignment struct {
	profile string
	uids    []uint32
	gids    []uint32
	pids    []int32
}

func (c compiledOptions) hasProfileSelection() bool {
	return c.defaultProfile != "" || len(c.sourceIPProfiles) > 0 || len(c.clientCertProfiles) > 0 || len(c.unixPeerProfiles) > 0
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

type contextKey int

const (
	contextKeyProfile contextKey = iota
	contextKeyConnectionIdentity
)

type connectionIdentity struct {
	unixPeer    *unixPeerCredentials
	unixPeerErr error
}

// Middleware applies client CIDR admission checks and optional per-client
// label ACLs resolved from the caller container's source IP.
func Middleware(upstreamSocket string, logger *slog.Logger, opts Options) func(http.Handler) http.Handler {
	return middlewareWithDeps(logger, opts, newACLResolveClient(upstreamSocket))
}

func middlewareWithDeps(logger *slog.Logger, opts Options, resolveClient func(context.Context, netip.Addr) (resolvedClient, bool, error)) func(http.Handler) http.Handler {
	compiled, err := compileOptions(opts)
	if err != nil {
		logger.Error("invalid client ACL config", "error", err)
		return func(http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				logging.SetDeniedWithCode(w, r, reasonCodeClientACLMisconfigured, "client ACL misconfigured", filter.NormalizePath)
				_ = httpjson.Write(w, http.StatusInternalServerError, httpjson.ErrorResponse{Message: "client ACL misconfigured"})
			})
		}
	}

	if len(compiled.allowedCIDRs) == 0 && !compiled.labelsOn && !compiled.hasProfileSelection() {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP, ipOK := remoteIP(r.RemoteAddr)
			if len(compiled.allowedCIDRs) > 0 {
				if !ipOK || !ipAllowed(clientIP, compiled.allowedCIDRs) {
					logging.SetDeniedWithCode(w, r, reasonCodeClientIPNotAllowed, "client IP not allowed", filter.NormalizePath)
					_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: "client IP not allowed"})
					return
				}
			}

			profile, strategy, ok, err := selectProfile(r, clientIP, ipOK, compiled)
			if err != nil {
				logger.ErrorContext(r.Context(), "client identity lookup failed", "error", err)
				logging.SetDeniedWithCode(w, r, reasonCodeClientIdentityLookupFailed, "client identity lookup failed", filter.NormalizePath)
				_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: "client identity lookup failed"})
				return
			}
			if ok {
				logger.DebugContext(r.Context(), "client ACL profile matched", "profile", profile, "strategy", strategy)
				if meta := logging.MetaForRequest(w, r); meta != nil {
					meta.Profile = profile
				}
				r = r.WithContext(withProfile(r.Context(), profile))
			}

			if !compiled.labelsOn || !ipOK {
				next.ServeHTTP(w, r)
				return
			}

			client, found, err := resolveClient(r.Context(), clientIP)
			if err != nil {
				logger.ErrorContext(r.Context(), "client label ACL lookup failed", "error", err, "client_ip", clientIP.String())
				logging.SetDeniedWithCode(w, r, reasonCodeClientLabelACLLookupFailed, "client label ACL lookup failed", filter.NormalizePath)
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
				logging.SetDeniedWithCode(w, r, reasonCodeClientLabelACLEvalFailed, "client label ACL evaluation failed", filter.NormalizePath)
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

			logging.SetDeniedWithCode(w, r, reasonCodeClientLabelPolicyDenied, "client label policy denied request", filter.NormalizePath)
			_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: "client label policy denied request"})
		})
	}
}

func newACLResolveClient(upstreamSocket string) func(context.Context, netip.Addr) (resolvedClient, bool, error) {
	resolver := upstreamResolver{
		client: dockerclient.New(upstreamSocket),
	}
	cache := newClientCache(clientCacheTTL, clientCacheMaxSize, time.Now, resolver.resolveClient)
	return cache.Lookup
}

func compileOptions(opts Options) (compiledOptions, error) {
	compiled := compiledOptions{
		labelPrefix:    opts.ContainerLabels.LabelPrefix,
		labelsOn:       opts.ContainerLabels.Enabled,
		defaultProfile: strings.TrimSpace(opts.Profiles.DefaultProfile),
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

	compiled.sourceIPProfiles = make([]compiledSourceIPProfileAssignment, 0, len(opts.Profiles.SourceIPs))
	for _, assignment := range opts.Profiles.SourceIPs {
		compiledAssignment := compiledSourceIPProfileAssignment{
			profile: strings.TrimSpace(assignment.Profile),
			cidrs:   make([]netip.Prefix, 0, len(assignment.CIDRs)),
		}
		for _, raw := range assignment.CIDRs {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
			if err != nil {
				return compiled, fmt.Errorf("parse profile CIDR %q: %w", raw, err)
			}
			compiledAssignment.cidrs = append(compiledAssignment.cidrs, prefix.Masked())
		}
		compiled.sourceIPProfiles = append(compiled.sourceIPProfiles, compiledAssignment)
	}

	compiled.clientCertProfiles = make([]compiledClientCertificateProfileAssignment, 0, len(opts.Profiles.ClientCertificates))
	for _, assignment := range opts.Profiles.ClientCertificates {
		compiledAssignment := compiledClientCertificateProfileAssignment{
			profile:             strings.TrimSpace(assignment.Profile),
			commonNames:         make([]string, 0, len(assignment.CommonNames)),
			dnsNames:            make([]string, 0, len(assignment.DNSNames)),
			ipAddresses:         make([]netip.Addr, 0, len(assignment.IPAddresses)),
			uriSANs:             make([]string, 0, len(assignment.URISANs)),
			spiffeIDs:           make([]string, 0, len(assignment.SPIFFEIDs)),
			publicKeySHA256Pins: make([]string, 0, len(assignment.PublicKeySHA256Pins)),
		}
		for _, value := range assignment.CommonNames {
			trimmed := strings.TrimSpace(value)
			if trimmed == "" {
				continue
			}
			compiledAssignment.commonNames = append(compiledAssignment.commonNames, trimmed)
		}
		for _, value := range assignment.DNSNames {
			trimmed := strings.TrimSpace(value)
			if trimmed == "" {
				continue
			}
			compiledAssignment.dnsNames = append(compiledAssignment.dnsNames, trimmed)
		}
		for _, value := range assignment.IPAddresses {
			addr, err := netip.ParseAddr(strings.TrimSpace(value))
			if err != nil {
				return compiled, fmt.Errorf("parse client certificate IP SAN %q: %w", value, err)
			}
			compiledAssignment.ipAddresses = append(compiledAssignment.ipAddresses, addr.Unmap())
		}
		for _, value := range assignment.URISANs {
			parsed, err := url.Parse(strings.TrimSpace(value))
			if err != nil {
				return compiled, fmt.Errorf("parse client certificate URI SAN %q: %w", value, err)
			}
			compiledAssignment.uriSANs = append(compiledAssignment.uriSANs, parsed.String())
		}
		for _, value := range assignment.SPIFFEIDs {
			parsed, err := url.Parse(strings.TrimSpace(value))
			if err != nil {
				return compiled, fmt.Errorf("parse client certificate SPIFFE ID %q: %w", value, err)
			}
			compiledAssignment.spiffeIDs = append(compiledAssignment.spiffeIDs, parsed.String())
		}
		for _, value := range assignment.PublicKeySHA256Pins {
			pin, err := pkipin.NormalizeSubjectPublicKeySHA256Pin(value)
			if err != nil {
				return compiled, fmt.Errorf("parse client certificate public_key_sha256_pins entry %q: %w", value, err)
			}
			compiledAssignment.publicKeySHA256Pins = append(compiledAssignment.publicKeySHA256Pins, pin)
		}
		compiled.clientCertProfiles = append(compiled.clientCertProfiles, compiledAssignment)
	}

	compiled.unixPeerProfiles = make([]compiledUnixPeerProfileAssignment, 0, len(opts.Profiles.UnixPeers))
	for _, assignment := range opts.Profiles.UnixPeers {
		compiled.unixPeerProfiles = append(compiled.unixPeerProfiles, compiledUnixPeerProfileAssignment{
			profile: strings.TrimSpace(assignment.Profile),
			uids:    append([]uint32(nil), assignment.UIDs...),
			gids:    append([]uint32(nil), assignment.GIDs...),
			pids:    append([]int32(nil), assignment.PIDs...),
		})
	}

	if len(compiled.sourceIPProfiles) > 0 {
		compiled.sourceIPProfileIndex = &sourceIPProfileIndex{
			cache: make(map[netip.Addr]profileLookupResult),
		}
	}
	if len(compiled.clientCertProfiles) > 0 {
		compiled.clientCertProfileIndex = &clientCertificateProfileIndex{
			cache: make(map[[sha256.Size]byte]profileLookupResult),
		}
	}

	return compiled, nil
}

func withProfile(ctx context.Context, profile string) context.Context {
	return context.WithValue(ctx, contextKeyProfile, profile)
}

func withConnectionIdentity(ctx context.Context, identity connectionIdentity) context.Context {
	return context.WithValue(ctx, contextKeyConnectionIdentity, identity)
}

func withUnixPeerCredentials(ctx context.Context, creds unixPeerCredentials) context.Context {
	return withConnectionIdentity(ctx, connectionIdentity{unixPeer: &creds})
}

func unixPeerCredentialsFromContext(ctx context.Context) (unixPeerCredentials, bool) {
	identity, _ := ctx.Value(contextKeyConnectionIdentity).(connectionIdentity)
	if identity.unixPeer == nil {
		return unixPeerCredentials{}, false
	}
	return *identity.unixPeer, true
}

// ConnContext captures per-connection client identity selectors so request
// handlers can evaluate unix peer credentials alongside TLS identities.
func ConnContext(ctx context.Context, conn net.Conn) context.Context {
	creds, ok, err := peerCredentialsFromConn(conn)
	if err != nil {
		return withConnectionIdentity(ctx, connectionIdentity{unixPeerErr: err})
	}
	if !ok {
		return ctx
	}
	return withUnixPeerCredentials(ctx, creds)
}

// RequestProfile returns the named policy profile selected for the request.
func RequestProfile(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	value, _ := r.Context().Value(contextKeyProfile).(string)
	return value, value != ""
}

func selectProfile(r *http.Request, clientIP netip.Addr, ipOK bool, compiled compiledOptions) (string, profileMatchStrategy, bool, error) {
	if profile, ok := matchClientCertificateProfile(r, compiled.clientCertProfiles, compiled.clientCertProfileIndex); ok {
		return profile, profileMatchStrategyClientCertificate, true, nil
	}
	if profile, ok, err := matchUnixPeerProfile(r, compiled.unixPeerProfiles); ok || err != nil {
		return profile, profileMatchStrategyUnixPeer, ok, err
	}
	if ipOK {
		if profile, ok := matchSourceIPProfile(clientIP, compiled.sourceIPProfiles, compiled.sourceIPProfileIndex); ok {
			return profile, profileMatchStrategySourceIP, true, nil
		}
	}
	if compiled.defaultProfile != "" {
		return compiled.defaultProfile, profileMatchStrategyDefaultProfile, true, nil
	}
	return "", "", false, nil
}

func matchSourceIPProfile(addr netip.Addr, assignments []compiledSourceIPProfileAssignment, index *sourceIPProfileIndex) (string, bool) {
	if cached, found := index.lookup(addr); found {
		return cached.profile, cached.ok
	}

	result := profileLookupResult{}
	for _, assignment := range assignments {
		for _, prefix := range assignment.cidrs {
			if prefix.Contains(addr) {
				result = profileLookupResult{profile: assignment.profile, ok: true}
				index.store(addr, result)
				return result.profile, result.ok
			}
		}
	}

	index.store(addr, result)
	return "", false
}

func matchClientCertificateProfile(r *http.Request, assignments []compiledClientCertificateProfileAssignment, index *clientCertificateProfileIndex) (string, bool) {
	leaf := clientCertificateLeaf(r)
	if leaf == nil {
		return "", false
	}

	fingerprint, fingerprintOK := clientCertificateFingerprint(leaf)
	if fingerprintOK {
		if cached, found := index.lookup(fingerprint); found {
			return cached.profile, cached.ok
		}
	}

	result := profileLookupResult{}
	for _, assignment := range assignments {
		if assignment.matches(leaf) {
			result = profileLookupResult{profile: assignment.profile, ok: true}
			if fingerprintOK {
				index.store(fingerprint, result)
			}
			return result.profile, result.ok
		}
	}
	if fingerprintOK {
		index.store(fingerprint, result)
	}
	return "", false
}

func clientCertificateLeaf(r *http.Request) *x509.Certificate {
	if r == nil || r.TLS == nil {
		return nil
	}
	if len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0 {
		return r.TLS.VerifiedChains[0][0]
	}
	return nil
}

func matchUnixPeerProfile(r *http.Request, assignments []compiledUnixPeerProfileAssignment) (string, bool, error) {
	if len(assignments) == 0 {
		return "", false, nil
	}
	identity, _ := r.Context().Value(contextKeyConnectionIdentity).(connectionIdentity)
	if identity.unixPeerErr != nil {
		return "", false, identity.unixPeerErr
	}
	creds, ok := unixPeerCredentialsFromContext(r.Context())
	if !ok {
		return "", false, nil
	}
	for _, assignment := range assignments {
		if assignment.matches(creds) {
			return assignment.profile, true, nil
		}
	}
	return "", false, nil
}

func (a compiledUnixPeerProfileAssignment) matches(creds unixPeerCredentials) bool {
	if !a.hasSelectors() {
		return false
	}
	if len(a.uids) > 0 && !containsUint32(a.uids, creds.UID) {
		return false
	}
	if len(a.gids) > 0 && !containsUint32(a.gids, creds.GID) {
		return false
	}
	if len(a.pids) > 0 && !containsInt32(a.pids, creds.PID) {
		return false
	}
	return true
}

func (a compiledUnixPeerProfileAssignment) hasSelectors() bool {
	return len(a.uids) > 0 || len(a.gids) > 0 || len(a.pids) > 0
}

func containsUint32(values []uint32, want uint32) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsInt32(values []int32, want int32) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (a compiledClientCertificateProfileAssignment) matches(cert *x509.Certificate) bool {
	if cert == nil || !a.hasSelectors() {
		return false
	}
	if len(a.commonNames) > 0 && !containsExact(a.commonNames, strings.TrimSpace(cert.Subject.CommonName)) {
		return false
	}
	if len(a.dnsNames) > 0 && !intersectsStrings(a.dnsNames, cert.DNSNames) {
		return false
	}
	if len(a.ipAddresses) > 0 && !intersectsIPAddrs(a.ipAddresses, cert.IPAddresses) {
		return false
	}
	uriSANs := certificateURIStrings(cert)
	if len(a.uriSANs) > 0 && !intersectsStrings(a.uriSANs, uriSANs) {
		return false
	}
	if len(a.spiffeIDs) > 0 && !intersectsStrings(a.spiffeIDs, uriSANs) {
		return false
	}
	if len(a.publicKeySHA256Pins) > 0 && !containsExact(a.publicKeySHA256Pins, pkipin.SubjectPublicKeySHA256Hex(cert)) {
		return false
	}
	return true
}

func (a compiledClientCertificateProfileAssignment) hasSelectors() bool {
	return len(a.commonNames) > 0 ||
		len(a.dnsNames) > 0 ||
		len(a.ipAddresses) > 0 ||
		len(a.uriSANs) > 0 ||
		len(a.spiffeIDs) > 0 ||
		len(a.publicKeySHA256Pins) > 0
}

func containsExact(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func intersectsStrings(allowed []string, actual []string) bool {
	for _, candidate := range actual {
		if containsExact(allowed, candidate) {
			return true
		}
	}
	return false
}

func intersectsIPAddrs(allowed []netip.Addr, actual []net.IP) bool {
	for _, candidate := range actual {
		addr, ok := netip.AddrFromSlice(candidate)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		for _, allowedAddr := range allowed {
			if allowedAddr == addr {
				return true
			}
		}
	}
	return false
}

func certificateURIStrings(cert *x509.Certificate) []string {
	if cert == nil || len(cert.URIs) == 0 {
		return nil
	}
	values := make([]string, 0, len(cert.URIs))
	for _, value := range cert.URIs {
		if value == nil {
			continue
		}
		values = append(values, value.String())
	}
	return values
}

func clientCertificateFingerprint(cert *x509.Certificate) ([sha256.Size]byte, bool) {
	if cert == nil || len(cert.Raw) == 0 {
		return [sha256.Size]byte{}, false
	}
	return sha256.Sum256(cert.Raw), true
}

func (i *sourceIPProfileIndex) lookup(addr netip.Addr) (profileLookupResult, bool) {
	if i == nil {
		return profileLookupResult{}, false
	}
	i.mu.RLock()
	result, ok := i.cache[addr]
	i.mu.RUnlock()
	return result, ok
}

func (i *sourceIPProfileIndex) store(addr netip.Addr, result profileLookupResult) {
	if i == nil {
		return
	}
	i.mu.Lock()
	i.cache[addr] = result
	i.mu.Unlock()
}

func (i *clientCertificateProfileIndex) lookup(fingerprint [sha256.Size]byte) (profileLookupResult, bool) {
	if i == nil {
		return profileLookupResult{}, false
	}
	i.mu.RLock()
	result, ok := i.cache[fingerprint]
	i.mu.RUnlock()
	return result, ok
}

func (i *clientCertificateProfileIndex) store(fingerprint [sha256.Size]byte, result profileLookupResult) {
	if i == nil {
		return
	}
	i.mu.Lock()
	i.cache[fingerprint] = result
	i.mu.Unlock()
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

	// Sort the label keys before iterating so the compiled rule order,
	// error reporting, and first-match-wins evaluation stay deterministic
	// across runs. Go's map iteration is randomized on purpose, so without
	// this sort a container with multiple `com.sockguard.allow.*` labels
	// would see rule indices — and therefore the order in which validation
	// errors surface — change between requests. That drifts into a latent
	// flake and makes first-match-wins debugging confusing.
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	rules := make([]*filter.CompiledRule, 0)
	hasACLLabels := false
	index := 0
	for _, key := range keys {
		if !strings.HasPrefix(key, labelPrefix) {
			continue
		}
		hasACLLabels = true

		method, ok := labelMethod(key, labelPrefix)
		if !ok {
			return nil, true, fmt.Errorf("unsupported client ACL label %q", key)
		}

		value := labels[key]
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
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/json", nil)

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
