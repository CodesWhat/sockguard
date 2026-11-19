package otlp

import (
	"strconv"
	"time"
)

// Attr is one span attribute. Exactly one of the string or integer forms is
// used, selected by IsInt.
type Attr struct {
	Key   string
	Str   string
	Int   int64
	IsInt bool
}

// StringAttr builds a string attribute.
func StringAttr(key, value string) Attr { return Attr{Key: key, Str: value} }

// IntAttr builds an integer attribute.
func IntAttr(key string, value int64) Attr { return Attr{Key: key, Int: value, IsInt: true} }

// Span is the exporter's input. It is a plain value with no references into
// pooled request state.
type Span struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	Name         string
	Start        time.Time
	End          time.Time
	// Error marks the span status as ERROR.
	Error bool
	Attrs []Attr
}

// OTLP/HTTP JSON encoding: lowerCamelCase field names, hex trace/span IDs,
// integer enums, and uint64 nanosecond timestamps as decimal strings.

const (
	spanKindServer  = 2
	statusCodeError = 2
)

type exportRequest struct {
	ResourceSpans []resourceSpans `json:"resourceSpans"`
}

type resourceSpans struct {
	Resource   resource     `json:"resource"`
	ScopeSpans []scopeSpans `json:"scopeSpans"`
}

type resource struct {
	Attributes []keyValue `json:"attributes"`
}

type scopeSpans struct {
	Scope scope      `json:"scope"`
	Spans []jsonSpan `json:"spans"`
}

type scope struct {
	Name string `json:"name"`
}

type jsonSpan struct {
	TraceID           string     `json:"traceId"`
	SpanID            string     `json:"spanId"`
	ParentSpanID      string     `json:"parentSpanId,omitempty"`
	Name              string     `json:"name"`
	Kind              int        `json:"kind"`
	StartTimeUnixNano string     `json:"startTimeUnixNano"`
	EndTimeUnixNano   string     `json:"endTimeUnixNano"`
	Attributes        []keyValue `json:"attributes,omitempty"`
	Status            *status    `json:"status,omitempty"`
}

type status struct {
	Code int `json:"code"`
}

type keyValue struct {
	Key   string   `json:"key"`
	Value anyValue `json:"value"`
}

type anyValue struct {
	StringValue *string `json:"stringValue,omitempty"`
	// IntValue is a decimal string: OTLP JSON encodes int64 as a string.
	IntValue *string `json:"intValue,omitempty"`
}

func toKeyValue(a Attr) keyValue {
	if a.IsInt {
		v := strconv.FormatInt(a.Int, 10)
		return keyValue{Key: a.Key, Value: anyValue{IntValue: &v}}
	}
	v := a.Str
	return keyValue{Key: a.Key, Value: anyValue{StringValue: &v}}
}

func toJSONSpan(s Span) jsonSpan {
	js := jsonSpan{
		TraceID:           s.TraceID,
		SpanID:            s.SpanID,
		ParentSpanID:      s.ParentSpanID,
		Name:              s.Name,
		Kind:              spanKindServer,
		StartTimeUnixNano: strconv.FormatInt(s.Start.UnixNano(), 10),
		EndTimeUnixNano:   strconv.FormatInt(s.End.UnixNano(), 10),
	}
	if len(s.Attrs) > 0 {
		js.Attributes = make([]keyValue, len(s.Attrs))
		for i, a := range s.Attrs {
			js.Attributes[i] = toKeyValue(a)
		}
	}
	if s.Error {
		js.Status = &status{Code: statusCodeError}
	}
	return js
}
