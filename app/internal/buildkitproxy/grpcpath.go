package buildkitproxy

import "strings"

// ParseGRPCPath splits an HTTP/2 request path shaped like
// "/{proto.package.Service}/{Method}" (the standard gRPC path convention,
// and the only path shape any of the h2c-terminated streams this package
// bridges ever presents — see bridge.go's per-stream http.Handler) into its
// service and method components. ok is false for anything that doesn't fit
// that shape, including a bare "/", a path with no method segment, or one
// with extra segments — callers must treat a false ok as Deny, not as "try
// again with a different parse", since a fully-qualified gRPC method name
// with a "/" of its own is not a thing the protocol allows.
func ParseGRPCPath(path string) (service, method string, ok bool) {
	trimmed, hadSlash := strings.CutPrefix(path, "/")
	if !hadSlash || trimmed == "" {
		return "", "", false
	}
	idx := strings.LastIndex(trimmed, "/")
	if idx <= 0 || idx == len(trimmed)-1 {
		return "", "", false
	}
	service, method = trimmed[:idx], trimmed[idx+1:]
	if strings.Contains(service, "/") || strings.Contains(method, "/") {
		return "", "", false
	}
	return service, method, true
}
