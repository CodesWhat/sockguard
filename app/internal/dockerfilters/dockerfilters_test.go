package dockerfilters

import (
	"reflect"
	"strings"
	"testing"
)

func TestDecode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		want    map[string][]string
		wantErr string
	}{
		{
			name:  "empty",
			input: "",
			want:  map[string][]string{},
		},
		{
			name:  "modern array syntax",
			input: `{"label":["a=b"],"type":["container"]}`,
			want: map[string][]string{
				"label": {"a=b"},
				"type":  {"container"},
			},
		},
		{
			name:  "legacy object syntax flattens to sorted keys",
			input: `{"label":{"c=d":true,"a=b":true}}`,
			want: map[string][]string{
				"label": {"a=b", "c=d"},
			},
		},
		{
			name:  "mixed modern and legacy keys",
			input: `{"label":["a=1"],"dangling":{"b=2":true}}`,
			want: map[string][]string{
				"label":    {"a=1"},
				"dangling": {"b=2"},
			},
		},
		{
			name:    "legacy object rejects non-boolean values",
			input:   `{"label":{"a=b":1}}`,
			wantErr: "unexpected label filter value type",
		},
		{
			// Docker's and Podman's own filter parsers only install a
			// legacy-object entry whose value is true; a false-valued entry
			// is not a filter and must not survive decode as one, or a
			// client can use it to fake out an "already present" check on
			// a selector the proxy is about to inject.
			name:  "legacy object drops false-valued entry",
			input: `{"label":{"com.example.visible=true":false}}`,
			want: map[string][]string{
				"label": {},
			},
		},
		{
			name:  "legacy object keeps true-valued entry",
			input: `{"label":{"com.example.visible=true":true}}`,
			want: map[string][]string{
				"label": {"com.example.visible=true"},
			},
		},
		{
			name:  "legacy object mixed true and false under one key keeps only true",
			input: `{"label":{"a=1":true,"b=2":false,"c=3":true}}`,
			want: map[string][]string{
				"label": {"a=1", "c=3"},
			},
		},
		{
			// The array form has no boolean to drop, so a false-valued
			// legacy entry under the same key must not affect an array-form
			// key that names its own distinct filter type — the two forms
			// never share a JSON key (json.Unmarshal only keeps one value
			// per key), so this exercises the array form's independence,
			// not a merge of the two.
			name:  "array form keeps values regardless of a false entry elsewhere",
			input: `{"label":["a=1"],"dangling":{"b=2":false,"c=3":true}}`,
			want: map[string][]string{
				"label":    {"a=1"},
				"dangling": {"c=3"},
			},
		},
		{
			// Negation (key!=value) must pass through verbatim. Docker treats
			// `!=` as an in-string sentinel; callers don't parse it, so round-
			// tripping the literal string keeps the original semantics.
			name:  "negation passes through verbatim",
			input: `{"label":["com.example.role!=worker"]}`,
			want: map[string][]string{
				"label": {"com.example.role!=worker"},
			},
		},
		{
			name:    "non string array entry",
			input:   `{"label":[true]}`,
			wantErr: "unexpected label filter element type",
		},
		{
			name:    "numeric array entry",
			input:   `{"label":[1]}`,
			wantErr: "unexpected label filter element type",
		},
		{
			name:    "string filter value",
			input:   `{"label":"bad"}`,
			wantErr: "unexpected label filter type",
		},
		{
			// Unknown future shapes (numbers, booleans) must be rejected so
			// the decoder never silently drops a filter and weakens ownership
			// or visibility checks.
			name:    "numeric filter value",
			input:   `{"label":42}`,
			wantErr: "unexpected label filter type",
		},
		{
			name:    "bool filter value",
			input:   `{"label":true}`,
			wantErr: "unexpected label filter type",
		},
		{
			name:    "invalid JSON",
			input:   `{`,
			wantErr: "decode filters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Decode(tt.input)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Decode(%q) error = nil, want %q", tt.input, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Decode(%q) error = %v, want substring %q", tt.input, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Decode(%q) error = %v, want nil", tt.input, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Decode(%q) = %#v, want %#v", tt.input, got, tt.want)
			}
		})
	}
}

func FuzzDecode(f *testing.F) {
	for _, seed := range []string{
		`{"label":["a=b"]}`,
		`{"label":{"a=b":true}}`,
		`{"label":{"a=b":1}}`,
		`{"label":true}`,
		`{`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded string) {
		if len(encoded) > MaxEncodedBytes+1 {
			t.Skip()
		}
		_, _ = Decode(encoded)
	})
}
