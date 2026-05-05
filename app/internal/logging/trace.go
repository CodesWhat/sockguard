package logging

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

const (
	traceparentHeader = "Traceparent"
	tracestateHeader  = "Tracestate"

	traceVersion   = "00"
	traceFlagsNone = "00"
)

// TraceContextMiddleware participates in W3C trace context propagation without
// exporting spans. It preserves a valid incoming trace ID, replaces the parent
// ID with a proxy-local span ID, and records the IDs in RequestMeta for logs.
func TraceContextMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, ok := traceContextFromRequest(r)
			if !ok {
				ctx = newRootTraceContext()
				if r != nil {
					r.Header.Del(tracestateHeader)
				}
			}

			if r != nil {
				traceparent := formatTraceparent(ctx)
				r.Header.Set(traceparentHeader, traceparent)
				w.Header().Set(traceparentHeader, traceparent)

				meta := MetaForRequest(w, r)
				if meta == nil {
					meta = &RequestMeta{}
					r = r.WithContext(WithMeta(r.Context(), meta))
				}
				meta.TraceID = ctx.traceID
				meta.TraceParentID = ctx.parentID
				meta.TraceSpanID = ctx.spanID
				meta.TraceFlags = ctx.flags
			}

			next.ServeHTTP(w, r)
		})
	}
}

type traceContext struct {
	traceID  string
	parentID string
	spanID   string
	flags    string
}

func traceContextFromRequest(r *http.Request) (traceContext, bool) {
	if r == nil {
		return traceContext{}, false
	}
	traceID, parentID, flags, ok := parseTraceparent(r.Header.Get(traceparentHeader))
	if !ok {
		return traceContext{}, false
	}
	return traceContext{
		traceID:  traceID,
		parentID: parentID,
		spanID:   newTraceSpanID(),
		flags:    flags,
	}, true
}

func newRootTraceContext() traceContext {
	return traceContext{
		traceID: newTraceID(),
		spanID:  newTraceSpanID(),
		flags:   traceFlagsNone,
	}
}

func formatTraceparent(ctx traceContext) string {
	return traceVersion + "-" + ctx.traceID + "-" + ctx.spanID + "-" + ctx.flags
}

func parseTraceparent(value string) (traceID string, parentID string, flags string, ok bool) {
	if len(value) != 55 ||
		value[2] != '-' ||
		value[35] != '-' ||
		value[52] != '-' ||
		value[:2] != traceVersion {
		return "", "", "", false
	}

	traceID = value[3:35]
	parentID = value[36:52]
	flags = value[53:55]
	if !isLowerHex(traceID) ||
		!isLowerHex(parentID) ||
		!isLowerHex(flags) ||
		isZeroHex(traceID) ||
		isZeroHex(parentID) {
		return "", "", "", false
	}
	return traceID, parentID, flags, true
}

func traceSampled(flags string) bool {
	if len(flags) != 2 {
		return false
	}
	high, ok := lowerHexValue(flags[0])
	if !ok {
		return false
	}
	low, ok := lowerHexValue(flags[1])
	if !ok {
		return false
	}
	return ((high<<4)|low)&1 == 1
}

func newTraceID() string {
	var raw [16]byte
	if fillRandomNonZero(raw[:]) {
		return hex.EncodeToString(raw[:])
	}
	fallback := fallbackRequestIDRaw()
	return hex.EncodeToString(fallback[:])
}

func newTraceSpanID() string {
	var raw [8]byte
	if fillRandomNonZero(raw[:]) {
		return hex.EncodeToString(raw[:])
	}
	fallback := fallbackRequestIDRaw()
	return hex.EncodeToString(fallback[8:])
}

func fillRandomNonZero(dst []byte) bool {
	for range 3 {
		n, err := rand.Read(dst)
		if err == nil && n == len(dst) && !allZero(dst) {
			return true
		}
	}
	return false
}

func allZero(dst []byte) bool {
	for _, value := range dst {
		if value != 0 {
			return false
		}
	}
	return true
}

func isLowerHex(value string) bool {
	for i := 0; i < len(value); i++ {
		if _, ok := lowerHexValue(value[i]); !ok {
			return false
		}
	}
	return true
}

func isZeroHex(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] != '0' {
			return false
		}
	}
	return true
}

func lowerHexValue(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	default:
		return 0, false
	}
}
