package compat

import (
	"encoding"
	"encoding/json"
	"reflect"
	"strconv"
)

const (
	maxFillDepth    = 12
	visibleLabelKey = "com.example.visible"
	ownerLabelKey   = "com.sockguard.owner"
	ownerLabelValue = "compat"
)

// textCandidates are tried in order against types implementing
// encoding.TextUnmarshaler or json.Unmarshaler (netip.Addr, netip.Prefix, HardwareAddr, time.Time,
// network.Port, ...), so the filler needs no per-type knowledge.
var textCandidates = []string{
	"10.0.0.1",
	"10.0.0.0/24",
	"02:42:ac:11:00:02",
	"80/tcp",
	"2025-01-02T03:04:05Z",
}

var (
	textUnmarshalerType = reflect.TypeFor[encoding.TextUnmarshaler]()
	jsonUnmarshalerType = reflect.TypeFor[json.Unmarshaler]()
	rawBytesType        = reflect.TypeFor[[]byte]()
)

// fillValue returns a pointer to a fully populated value of typ: every exported
// field non-zero and wire-valid, which is what a busy daemon emits and what
// gives every redaction something to overwrite.
func fillValue(typ reflect.Type) reflect.Value {
	v := reflect.New(typ)
	fill(v.Elem(), "", "", 0)
	return v
}

func fill(v reflect.Value, name, parent string, depth int) {
	if depth > maxFillDepth {
		return
	}
	t := v.Type()

	if reflect.PointerTo(t).Implements(textUnmarshalerType) {
		for _, text := range textCandidates {
			p := reflect.New(t)
			if err := p.Interface().(encoding.TextUnmarshaler).UnmarshalText([]byte(text)); err == nil {
				v.Set(p.Elem())
				return
			}
		}
	}

	if reflect.PointerTo(t).Implements(jsonUnmarshalerType) {
		for _, text := range textCandidates {
			p := reflect.New(t)
			if err := p.Interface().(json.Unmarshaler).UnmarshalJSON([]byte(strconv.Quote(text))); err == nil {
				v.Set(p.Elem())
				return
			}
		}
	}

	switch v.Kind() {
	case reflect.Pointer:
		p := reflect.New(t.Elem())
		fill(p.Elem(), name, parent, depth+1)
		v.Set(p)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() || f.Tag.Get("json") == "-" {
				continue
			}
			fill(v.Field(i), f.Name, t.Name(), depth+1)
		}
	case reflect.Slice:
		if t == rawBytesType || t.Elem().Kind() == reflect.Uint8 {
			v.SetBytes([]byte("fixture-" + name))
			return
		}
		s := reflect.MakeSlice(t, 1, 1)
		fill(s.Index(0), name, parent, depth+1)
		v.Set(s)
	case reflect.Map:
		m := reflect.MakeMap(t)
		if name == "Labels" && t.Key().Kind() == reflect.String && t.Elem().Kind() == reflect.String {
			m.SetMapIndex(reflect.ValueOf(visibleLabelKey).Convert(t.Key()), reflect.ValueOf("true").Convert(t.Elem()))
			m.SetMapIndex(reflect.ValueOf(ownerLabelKey).Convert(t.Key()), reflect.ValueOf(ownerLabelValue).Convert(t.Elem()))
			v.Set(m)
			return
		}
		key := reflect.New(t.Key()).Elem()
		fill(key, name+"Key", parent, depth+1)
		val := reflect.New(t.Elem()).Elem()
		fill(val, name, parent, depth+1)
		m.SetMapIndex(key, val)
		v.Set(m)
	case reflect.Interface:
		// Left nil: an arbitrary-JSON field has no wire type to violate.
	case reflect.String:
		v.SetString(stringFor(name, parent))
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(1)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1)
	}
}

func stringFor(name, parent string) string {
	switch {
	case name == "Env":
		return "SECRET_KEY=fixture-secret"
	case name == "Type" && parent == "Mount":
		return "bind"
	}
	return "fixture-" + name
}
