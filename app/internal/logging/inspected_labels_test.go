package logging

import (
	"reflect"
	"testing"
)

func TestInspectedLabelsRoundTrip(t *testing.T) {
	m := &RequestMeta{}
	if _, _, ok := m.InspectedLabels("container", "web"); ok {
		t.Fatal("empty meta reported a recorded inspect")
	}

	src := map[string]string{"a": "1"}
	m.RecordInspectedLabels("container", "web", src, true)
	src["a"] = "mutated"

	labels, found, ok := m.InspectedLabels("container", "web")
	if !ok || !found || !reflect.DeepEqual(labels, map[string]string{"a": "1"}) {
		t.Fatalf("InspectedLabels = %v, %v, %v", labels, found, ok)
	}
	labels["a"] = "changed"
	if again, _, _ := m.InspectedLabels("container", "web"); again["a"] != "1" {
		t.Fatalf("returned map aliases the stored record: %v", again)
	}

	if _, _, ok := m.InspectedLabels("network", "web"); ok {
		t.Fatal("kind is not part of the key")
	}

	m.RecordInspectedLabels("container", "gone", nil, false)
	if labels, found, ok := m.InspectedLabels("container", "gone"); !ok || found || labels != nil {
		t.Fatalf("not-found record = %v, %v, %v", labels, found, ok)
	}
}

func TestInspectedLabelsNilMeta(t *testing.T) {
	var m *RequestMeta
	m.RecordInspectedLabels("container", "web", map[string]string{"a": "1"}, true)
	if _, _, ok := m.InspectedLabels("container", "web"); ok {
		t.Fatal("nil meta reported a recorded inspect")
	}
}
