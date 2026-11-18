// Package otlp is a stdlib-only, opt-in OTLP/HTTP JSON trace exporter.
//
// It deliberately imports nothing outside the Go standard library and
// sockguard's own internal packages: the proxy's request hot path must not
// execute third-party code, and the OTLP JSON encoding is small and fully
// specified (https://opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding).
// Enqueueing a span is O(1) and non-blocking; every network operation runs on
// one worker goroutine, so a slow or dead collector can never delay a request.
package otlp
