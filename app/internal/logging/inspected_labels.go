package logging

import "maps"

// InspectedLabelsRecord is one successful single-resource inspect result a
// request-scoped layer left on RequestMeta for the layers after it.
type InspectedLabelsRecord struct {
	Labels map[string]string
	Found  bool
}

func inspectedLabelsKey(kind, identifier string) string {
	return kind + "\x00" + identifier
}

// RecordInspectedLabels memoizes a successful inspect of kind/identifier for
// the rest of this request, so a later layer that needs the same labels (owner
// isolation after visibility) does not dial the daemon a second time. Only
// successful lookups belong here: callers never record an error. The labels
// are copied. Safe on a nil receiver.
//
// This is per-request reuse only, the same inspect-then-proxy window the
// request already has. Nothing here survives the request.
func (m *RequestMeta) RecordInspectedLabels(kind, identifier string, labels map[string]string, found bool) {
	if m == nil {
		return
	}
	if m.inspectedLabels == nil {
		m.inspectedLabels = make(map[string]InspectedLabelsRecord)
	}
	m.inspectedLabels[inspectedLabelsKey(kind, identifier)] = InspectedLabelsRecord{
		Labels: maps.Clone(labels),
		Found:  found,
	}
}

// InspectedLabels returns a result recorded by RecordInspectedLabels as
// (labels, found, ok); ok is false when nothing was recorded for the key. The
// returned map is a copy. Safe on a nil receiver.
func (m *RequestMeta) InspectedLabels(kind, identifier string) (map[string]string, bool, bool) {
	if m == nil {
		return nil, false, false
	}
	rec, ok := m.inspectedLabels[inspectedLabelsKey(kind, identifier)]
	if !ok {
		return nil, false, false
	}
	return maps.Clone(rec.Labels), rec.Found, true
}
