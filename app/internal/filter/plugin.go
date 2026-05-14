package filter

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"slices"
	"strings"
)

const maxPluginBodyBytes = 512 << 20  // 512 MiB
const maxPluginConfigBytes = 64 << 10 // 64 KiB
const pluginConfigName = "config.json"

// PluginOptions configures request-body/query inspection for plugin writes.
type PluginOptions struct {
	AllowHostNetwork      bool
	AllowHostIPC          bool
	AllowHostPID          bool
	AllowAllDevices       bool
	AllowedBindMounts     []string
	AllowedDevices        []string
	AllowAllCapabilities  bool
	AllowedCapabilities   []string
	AllowAllRegistries    bool
	AllowOfficial         bool
	AllowedRegistries     []string
	AllowedSetEnvPrefixes []string
}

type pluginPolicy struct {
	allowHostNetwork bool
	allowHostIPC     bool
	allowHostPID     bool
	allowAllDevices       bool
	allowedBindMounts     []string
	allowedDevices        []string
	allowAllCapabilities  bool
	allowedCapabilities   []string
	allowedSetEnvPrefixes []string
	imagePolicy           imagePullPolicy
}

type pluginPrivilege struct {
	Name        string   `json:"Name"`
	Description string   `json:"Description"`
	Value       []string `json:"Value"`
}

type pluginCreateConfig struct {
	Network struct {
		Type string `json:"Type"`
	} `json:"Network"`
	PropagatedMount string `json:"PropagatedMount"`
	IpcHost         bool   `json:"IpcHost"`
	PidHost         bool   `json:"PidHost"`
	Mounts          []struct {
		Source string `json:"Source"`
	} `json:"Mounts"`
	Linux struct {
		Capabilities    []string `json:"Capabilities"`
		AllowAllDevices bool     `json:"AllowAllDevices"`
		Devices         []struct {
			Path string `json:"Path"`
		} `json:"Devices"`
	} `json:"Linux"`
}

func newPluginPolicy(opts PluginOptions) pluginPolicy {
	allowedMounts := normalizePluginPaths(opts.AllowedBindMounts)
	allowedDevices := normalizePluginPaths(opts.AllowedDevices)
	allowedCapabilities := normalizePluginCapabilities(opts.AllowedCapabilities)
	allowedSetEnvPrefixes := normalizePluginSetEnvPrefixes(opts.AllowedSetEnvPrefixes)

	return pluginPolicy{
		allowHostNetwork: opts.AllowHostNetwork,
		allowHostIPC:     opts.AllowHostIPC,
		allowHostPID:     opts.AllowHostPID,
		allowAllDevices:       opts.AllowAllDevices,
		allowedBindMounts:     allowedMounts,
		allowedDevices:        allowedDevices,
		allowAllCapabilities:  opts.AllowAllCapabilities,
		allowedCapabilities:   allowedCapabilities,
		allowedSetEnvPrefixes: allowedSetEnvPrefixes,
		imagePolicy: newImagePullPolicy(ImagePullOptions{
			AllowAllRegistries: opts.AllowAllRegistries,
			AllowOfficial:      opts.AllowOfficial,
			AllowedRegistries:  opts.AllowedRegistries,
		}),
	}
}

func (p pluginPolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost {
		return "", nil
	}

	switch {
	case normalizedPath == "/plugins/pull":
		return p.inspectPluginPull(logger, r)
	case isPluginUpgradePath(normalizedPath):
		return p.inspectPluginUpgrade(logger, r)
	case isPluginSetPath(normalizedPath):
		return p.inspectPluginSet(logger, r)
	case normalizedPath == "/plugins/create":
		return p.inspectPluginCreate(logger, r)
	default:
		return "", nil
	}
}

func (p pluginPolicy) inspectPluginPull(logger *slog.Logger, r *http.Request) (string, error) {
	query := r.URL.Query()
	if remote := strings.TrimSpace(query.Get("remote")); remote != "" {
		if denyReason := p.imagePolicy.denyReasonForReference(remote, "plugin pull"); denyReason != "" {
			return denyReason, nil
		}
	}

	return p.inspectPrivileges(logger, r, "plugin pull")
}

func (p pluginPolicy) inspectPluginUpgrade(logger *slog.Logger, r *http.Request) (string, error) {
	query := r.URL.Query()
	if remote := strings.TrimSpace(query.Get("remote")); remote != "" {
		if denyReason := p.imagePolicy.denyReasonForReference(remote, "plugin upgrade"); denyReason != "" {
			return denyReason, nil
		}
	}

	return p.inspectPrivileges(logger, r, "plugin upgrade")
}

func (p pluginPolicy) inspectPrivileges(logger *slog.Logger, r *http.Request, subject string) (string, error) {
	if r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxPluginBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return fmt.Sprintf("%s denied: request body exceeds %d byte limit", subject, maxPluginBodyBytes), nil
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var privileges []pluginPrivilege
	if err := decodePolicySubsetJSON(body, &privileges); err != nil {
		if logger != nil {
			logger.DebugContext(r.Context(), "plugin privilege body could not be decoded for Sockguard policy inspection; deferring to Docker validation", "error", err, "method", r.Method, "path", r.URL.Path)
		}
		return "plugin denied: request body could not be inspected", nil
	}

	return p.denyReasonForPrivileges(subject, privileges), nil
}

func (p pluginPolicy) inspectPluginSet(logger *slog.Logger, r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxPluginBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return fmt.Sprintf("plugin set denied: request body exceeds %d byte limit", maxPluginBodyBytes), nil
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var settings []string
	if err := decodePolicySubsetJSON(body, &settings); err != nil {
		if logger != nil {
			logger.DebugContext(r.Context(), "plugin set body could not be decoded for Sockguard policy inspection; deferring to Docker validation", "error", err, "method", r.Method, "path", r.URL.Path)
		}
		return "", nil
	}

	for _, setting := range settings {
		key, value, ok := strings.Cut(setting, "=")
		if !ok {
			return fmt.Sprintf("plugin set denied: setting %q is not an allowed assignment", setting), nil
		}
		if kind, normalized, matched := parsePluginSetting(key, value); matched {
			switch kind {
			case pluginSettingMount:
				if !bindPathAllowed(normalized, p.allowedBindMounts) {
					return fmt.Sprintf("plugin set denied: bind mount source %q is not allowlisted", normalized), nil
				}
			case pluginSettingDevice:
				if !p.deviceAllowed(normalized) {
					return fmt.Sprintf("plugin set denied: device path %q is not allowlisted", normalized), nil
				}
			}
			continue
		}
		if !p.setEnvAllowed(setting) {
			return fmt.Sprintf("plugin set denied: setting %q is not allowlisted", setting), nil
		}
	}

	return "", nil
}

func (p pluginPolicy) inspectPluginCreate(logger *slog.Logger, r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}

	spool, size, err := spoolRequestBodyToTempFile(r, "sockguard-plugin-", maxPluginBodyBytes)
	if err != nil {
		return "", err
	}
	if spool.tooLarge {
		spool.closeAndRemove()
		return fmt.Sprintf("plugin create denied: request body exceeds %d byte limit", maxPluginBodyBytes), nil
	}
	if size == 0 {
		spool.closeAndRemove()
		return "", nil
	}

	configBytes, ok, err := extractPluginConfig(spool.file, r.Header.Get("Content-Type"))
	if err != nil {
		spool.closeAndRemove()
		return "", fmt.Errorf("extract plugin config: %w", err)
	}
	if ok {
		var cfg pluginCreateConfig
		if err := decodePolicySubsetJSON(configBytes, &cfg); err != nil {
			if logger != nil {
				logger.DebugContext(r.Context(), "plugin config.json could not be decoded for Sockguard policy inspection; deferring to Docker validation", "error", err, "method", r.Method, "path", r.URL.Path)
			}
		} else if denyReason := p.denyReasonForCreateConfig(cfg); denyReason != "" {
			spool.closeAndRemove()
			return denyReason, nil
		}
	}

	if err := seekToStart(spool.file); err != nil {
		spool.closeAndRemove()
		return "", fmt.Errorf("rewind plugin body: %w", err)
	}
	r.Body = spool.requestBody()
	r.ContentLength = size
	return "", nil
}

func (p pluginPolicy) denyReasonForCreateConfig(cfg pluginCreateConfig) string {
	if !p.allowHostNetwork && strings.EqualFold(strings.TrimSpace(cfg.Network.Type), "host") {
		return "plugin create denied: host network is not allowed"
	}
	if !p.allowHostIPC && cfg.IpcHost {
		return "plugin create denied: host IPC namespace is not allowed"
	}
	if !p.allowHostPID && cfg.PidHost {
		return "plugin create denied: host PID namespace is not allowed"
	}
	if denyReason := p.denyBindMounts(cfg.PropagatedMount, cfg.Mounts); denyReason != "" {
		return denyReason
	}
	if !p.allowAllCapabilities {
		if denyReason := p.denyCapabilities(cfg.Linux.Capabilities); denyReason != "" {
			return denyReason
		}
	}
	if !p.allowAllDevices {
		if cfg.Linux.AllowAllDevices {
			return "plugin create denied: allow-all-devices is not allowed"
		}
		if denyReason := p.denyDevices(cfg.Linux.Devices); denyReason != "" {
			return denyReason
		}
	}
	return ""
}

func (p pluginPolicy) denyReasonForPrivileges(subject string, privileges []pluginPrivilege) string {
	for _, privilege := range privileges {
		switch strings.ToLower(strings.TrimSpace(privilege.Name)) {
		case "network":
			for _, value := range privilege.Value {
				if strings.EqualFold(strings.TrimSpace(value), "host") && !p.allowHostNetwork {
					return fmt.Sprintf("%s denied: host network is not allowed", subject)
				}
			}
		case "mount":
			if denyReason := p.denyBindMountValues(subject, privilege.Value); denyReason != "" {
				return denyReason
			}
		case "device":
			if !p.allowAllDevices {
				for _, value := range privilege.Value {
					path, ok := normalizeContainerCreateBindMount(value)
					if !ok || p.deviceAllowed(path) {
						continue
					}
					return fmt.Sprintf("%s denied: device path %q is not allowlisted", subject, path)
				}
			}
		case "capabilities":
			if !p.allowAllCapabilities {
				for _, value := range privilege.Value {
					capability := normalizePluginCapability(value)
					if capability == "" || p.capabilityAllowed(capability) {
						continue
					}
					return fmt.Sprintf("%s denied: capability %q is not allowlisted", subject, capability)
				}
			}
		}
	}

	return ""
}

func (p pluginPolicy) denyBindMounts(propagatedMount string, mounts []struct {
	Source string `json:"Source"`
}) string {
	if propagatedMount != "" {
		source, ok := normalizeContainerCreateBindMount(propagatedMount)
		if !ok || !bindPathAllowed(source, p.allowedBindMounts) {
			if ok {
				return fmt.Sprintf("plugin create denied: bind mount source %q is not allowlisted", source)
			}
		}
	}

	for _, mount := range mounts {
		source, ok := normalizeContainerCreateBindMount(mount.Source)
		if !ok || bindPathAllowed(source, p.allowedBindMounts) {
			continue
		}
		return fmt.Sprintf("plugin create denied: bind mount source %q is not allowlisted", source)
	}

	return ""
}

func (p pluginPolicy) denyBindMountValues(subject string, values []string) string {
	for _, value := range values {
		source, ok := normalizeContainerCreateBindMount(value)
		if !ok || bindPathAllowed(source, p.allowedBindMounts) {
			continue
		}
		return fmt.Sprintf("%s denied: bind mount source %q is not allowlisted", subject, source)
	}
	return ""
}

func (p pluginPolicy) denyDevices(devices []struct {
	Path string `json:"Path"`
}) string {
	for _, device := range devices {
		path, ok := normalizeContainerCreateBindMount(device.Path)
		if !ok || p.deviceAllowed(path) {
			continue
		}
		return fmt.Sprintf("plugin create denied: device path %q is not allowlisted", path)
	}
	return ""
}

func (p pluginPolicy) denyCapabilities(capabilities []string) string {
	for _, capability := range capabilities {
		normalized := normalizePluginCapability(capability)
		if normalized == "" || p.capabilityAllowed(normalized) {
			continue
		}
		return fmt.Sprintf("plugin create denied: capability %q is not allowlisted", normalized)
	}
	return ""
}

func (p pluginPolicy) deviceAllowed(devicePath string) bool {
	for _, allowed := range p.allowedDevices {
		if allowed == "/" || devicePath == allowed || strings.HasPrefix(devicePath, allowed+"/") {
			return true
		}
	}
	return false
}

func (p pluginPolicy) capabilityAllowed(capability string) bool {
	return slices.Contains(p.allowedCapabilities, capability)
}

func (p pluginPolicy) setEnvAllowed(setting string) bool {
	for _, prefix := range p.allowedSetEnvPrefixes {
		if strings.HasPrefix(setting, prefix) {
			return true
		}
	}
	return false
}

func extractPluginConfig(file *os.File, contentType string) ([]byte, bool, error) {
	if mediaType, params, err := mime.ParseMediaType(contentType); err == nil && strings.EqualFold(mediaType, "multipart/form-data") {
		boundary := strings.TrimSpace(params["boundary"])
		if boundary == "" {
			return nil, false, nil
		}
		if err := seekToStart(file); err != nil {
			return nil, false, fmt.Errorf("rewind plugin reader: %w", err)
		}
		return extractPluginConfigFromMultipart(file, boundary)
	}

	if err := seekToStart(file); err != nil {
		return nil, false, fmt.Errorf("rewind plugin reader: %w", err)
	}

	if config, ok, err := extractPluginConfigFromGzipTar(file); ok || err != nil {
		return config, ok, err
	}
	if err := seekToStart(file); err != nil {
		return nil, false, fmt.Errorf("rewind plugin reader: %w", err)
	}
	return extractPluginConfigFromTar(file)
}

func extractPluginConfigFromMultipart(file *os.File, boundary string) ([]byte, bool, error) {
	reader := multipart.NewReader(file, boundary)
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, fmt.Errorf("read multipart part: %w", err)
		}

		config, ok, err := extractPluginConfigFromArchiveReader(part)
		if err != nil {
			return nil, false, err
		}
		if ok {
			return config, true, nil
		}
	}
}

func extractPluginConfigFromGzipTar(file *os.File) ([]byte, bool, error) {
	return extractPluginConfigFromGzipReader(file)
}

func extractPluginConfigFromTar(file *os.File) ([]byte, bool, error) {
	return extractPluginConfigFromTarReader(tar.NewReader(file))
}

func extractPluginConfigFromArchiveReader(reader io.Reader) ([]byte, bool, error) {
	buffered := bufio.NewReader(reader)
	header, err := buffered.Peek(512)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, fmt.Errorf("peek archive header: %w", err)
	}
	if looksLikeGzipHeader(header) {
		return extractPluginConfigFromGzipReader(buffered)
	}
	if !looksLikeTarHeader(header) {
		return nil, false, nil
	}
	return extractPluginConfigFromTarReader(tar.NewReader(buffered))
}

func extractPluginConfigFromGzipReader(reader io.Reader) ([]byte, bool, error) {
	gzr, err := gzip.NewReader(reader)
	if err != nil {
		if errors.Is(err, gzip.ErrHeader) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("create gzip reader: %w", err)
	}

	config, ok, err := extractPluginConfigFromTarReader(tar.NewReader(gzr))
	if err == nil {
		if drainErr := drainReader(gzr); drainErr != nil {
			err = fmt.Errorf("drain gzip stream: %w", drainErr)
		}
	}
	if closeErr := closeReadCloser(gzr); err == nil && closeErr != nil {
		err = fmt.Errorf("close gzip reader: %w", closeErr)
	}
	return config, ok, err
}

func extractPluginConfigFromTarReader(tr *tar.Reader) ([]byte, bool, error) {
	var config []byte
	found := false

	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return config, found, nil
		}
		if err != nil {
			if strings.Contains(err.Error(), "invalid tar header") {
				return nil, false, nil
			}
			return nil, false, fmt.Errorf("read tar entry: %w", err)
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}
		if normalizePluginConfigPath(header.Name) != pluginConfigName {
			continue
		}

		body, err := readAllLimited(tr, maxPluginConfigBytes+1)
		if err != nil {
			return nil, false, fmt.Errorf("read plugin config entry: %w", err)
		}
		if len(body) > maxPluginConfigBytes {
			return nil, false, fmt.Errorf("plugin config exceeds %d byte limit", maxPluginConfigBytes)
		}
		if !found {
			config = body
			found = true
		}
	}
}

func looksLikeGzipHeader(header []byte) bool {
	return len(header) >= 2 && header[0] == 0x1f && header[1] == 0x8b
}

func looksLikeTarHeader(header []byte) bool {
	return len(header) >= 262 && string(header[257:262]) == "ustar"
}

func normalizePluginConfigPath(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	cleaned := path.Clean(strings.TrimPrefix(trimmed, "/"))
	if cleaned == "." || cleaned == "" {
		return ""
	}
	return cleaned
}

func normalizePluginSetEnvPrefixes(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || slices.Contains(normalized, trimmed) {
			continue
		}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

type pluginSettingType int

const (
	pluginSettingUnknown pluginSettingType = iota
	pluginSettingMount
	pluginSettingDevice
)

func parsePluginSetting(key, value string) (pluginSettingType, string, bool) {
	trimmedKey := strings.TrimSpace(key)
	trimmedValue := strings.TrimSpace(value)
	if trimmedKey == "" || trimmedValue == "" {
		return pluginSettingUnknown, "", false
	}

	lowerKey := strings.ToLower(trimmedKey)
	switch {
	case strings.HasSuffix(lowerKey, ".source"):
		if source, ok := normalizeContainerCreateBindMount(trimmedValue); ok {
			return pluginSettingMount, source, true
		}
		return pluginSettingUnknown, "", false
	case strings.HasSuffix(lowerKey, ".path"):
		if device, ok := normalizeContainerCreateBindMount(trimmedValue); ok {
			return pluginSettingDevice, device, true
		}
		return pluginSettingUnknown, "", false
	}

	if strings.ToUpper(trimmedKey) == trimmedKey {
		return pluginSettingUnknown, "", false
	}

	switch {
	case strings.HasPrefix(trimmedValue, "/dev/"):
		if device, ok := normalizeContainerCreateBindMount(trimmedValue); ok {
			return pluginSettingDevice, device, true
		}
	case strings.HasPrefix(trimmedValue, "/"):
		if source, ok := normalizeContainerCreateBindMount(trimmedValue); ok {
			return pluginSettingMount, source, true
		}
	}

	return pluginSettingUnknown, "", false
}

func normalizePluginPaths(values []string) []string {
	allowed := make([]string, 0, len(values))
	for _, value := range values {
		normalized, ok := normalizeContainerCreateBindMount(value)
		if !ok || slices.Contains(allowed, normalized) {
			continue
		}
		allowed = append(allowed, normalized)
	}
	return allowed
}

func normalizePluginCapabilities(values []string) []string {
	allowed := make([]string, 0, len(values))
	for _, value := range values {
		normalized := normalizePluginCapability(value)
		if normalized == "" || slices.Contains(allowed, normalized) {
			continue
		}
		allowed = append(allowed, normalized)
	}
	return allowed
}

func normalizePluginCapability(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func isPluginUpgradePath(normalizedPath string) bool {
	return strings.HasPrefix(normalizedPath, "/plugins/") && strings.HasSuffix(normalizedPath, "/upgrade")
}

func isPluginSetPath(normalizedPath string) bool {
	return strings.HasPrefix(normalizedPath, "/plugins/") && strings.HasSuffix(normalizedPath, "/set")
}
