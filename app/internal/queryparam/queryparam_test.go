package queryparam

import (
	"net/url"
	"slices"
	"testing"
)

func mustParseQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	query, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatalf("ParseQuery(%q): %v", raw, err)
	}
	return query
}

func TestScalar(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		query       url.Values
		param       string
		wantValue   string
		wantPresent bool
		wantOK      bool
	}{
		{name: "single exact spelling", raw: "force=1", param: "force", wantValue: "1", wantPresent: true, wantOK: true},
		{name: "camel-case documented spelling", raw: "fromImage=alpine", param: "fromImage", wantValue: "alpine", wantPresent: true, wantOK: true},
		{name: "absent", raw: "other=1", param: "force", wantOK: true},
		{name: "empty query", raw: "", param: "force", wantOK: true},
		{name: "single empty value", raw: "driver=", param: "driver", wantPresent: true, wantOK: true},
		{name: "bare key", raw: "force", param: "force", wantPresent: true, wantOK: true},
		{name: "other parameters are ignored", raw: "t=a&t=b&force=1&V=1", param: "force", wantValue: "1", wantPresent: true, wantOK: true},
		{name: "repeated exact spelling", raw: "force=0&force=1", param: "force", wantPresent: true},
		{name: "repeated empty values", raw: "driver=&driver=", param: "driver", wantPresent: true},
		{name: "single other case", raw: "Force=1", param: "force", wantPresent: true},
		{name: "single lower case of a camel-case name", raw: "fromimage=alpine", param: "fromImage", wantPresent: true},
		{name: "exact and other case", raw: "driver=&Driver=shell", param: "driver", wantPresent: true},
		{name: "two other cases", raw: "DRIVER=a&Driver=b", param: "driver", wantPresent: true},
		{name: "percent-encoded exact spelling", raw: "%66orce=1", param: "force", wantValue: "1", wantPresent: true, wantOK: true},
		{name: "percent-encoded other case", raw: "%46orce=1", param: "force", wantPresent: true},
		{name: "long s folds to s", raw: "ru%C5%BFagelogfile=%2Fetc%2Fx", param: "rusagelogfile", wantPresent: true},
		{name: "Kelvin sign folds to k", raw: "lin%E2%84%AA=1", param: "link", wantPresent: true},
		{name: "a key that only looks alike is another parameter", raw: "force%00=1&forcex=1", param: "force", wantOK: true},
		{name: "nil value slice", query: url.Values{"path": nil}, param: "path", wantPresent: true, wantOK: true},
		{name: "empty value slice", query: url.Values{"path": {}}, param: "path", wantPresent: true, wantOK: true},
		{name: "nil value slice beside another spelling", query: url.Values{"path": nil, "Path": {"/x"}}, param: "path", wantPresent: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := tt.query
			if query == nil {
				query = mustParseQuery(t, tt.raw)
			}
			value, present, ok := Scalar(query, tt.param)
			if value != tt.wantValue || present != tt.wantPresent || ok != tt.wantOK {
				t.Fatalf("Scalar(%v, %q) = (%q, %v, %v), want (%q, %v, %v)",
					query, tt.param, value, present, ok, tt.wantValue, tt.wantPresent, tt.wantOK)
			}
		})
	}
}

// TestScalarAmbiguityDoesNotDependOnMapOrder repeats the two-spelling case
// enough times for Go's randomized map iteration to visit both orders.
func TestScalarAmbiguityDoesNotDependOnMapOrder(t *testing.T) {
	query := url.Values{"force": {"0"}, "Force": {"1"}, "FORCE": {"1"}, "fOrce": {"1"}}
	for range 64 {
		if value, present, ok := Scalar(query, "force"); ok || !present || value != "" {
			t.Fatalf("Scalar() = (%q, %v, %v), want an ambiguous present parameter", value, present, ok)
		}
	}
}

func TestPresent(t *testing.T) {
	tests := []struct {
		raw   string
		param string
		want  bool
	}{
		{raw: "volume=%2Fa%3A%2Fb", param: "volume", want: true},
		{raw: "volume=", param: "volume", want: true},
		{raw: "Volume=%2Fa%3A%2Fb&volume=x", param: "volume", want: true},
		{raw: "transientRunMounts=type%3Dbind", param: "transientrunmounts", want: true},
		{raw: "volume%C5%BF=x", param: "volumes", want: true},
		{raw: "volumex=x&other=1", param: "volume"},
		{raw: "", param: "volume"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			if got := Present(mustParseQuery(t, tt.raw), tt.param); got != tt.want {
				t.Fatalf("Present(%q, %q) = %v, want %v", tt.raw, tt.param, got, tt.want)
			}
		})
	}
}

func TestList(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		param      string
		wantValues []string
		wantOK     bool
	}{
		{name: "one value", raw: "volume=%2Fa%3A%2Fb", param: "volume", wantValues: []string{"/a:/b"}, wantOK: true},
		{name: "repeats keep their order", raw: "t=b%3A1&t=a%3A1&t=", param: "t", wantValues: []string{"b:1", "a:1", ""}, wantOK: true},
		{name: "absent", raw: "other=1", param: "volume", wantOK: true},
		{name: "other case alone", raw: "Volume=%2Fa%3A%2Fb", param: "volume"},
		{name: "exact and other case", raw: "volume=%2Fa%3A%2Fb&VOLUME=%2Fc%3A%2Fd", param: "volume"},
		{name: "long s folds to s", raw: "additionalbuildcontexts=a%3Dimage%3Ax&additionalbuildcontext%C5%BF=b%3Durl%3Ay", param: "additionalbuildcontexts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values, ok := List(mustParseQuery(t, tt.raw), tt.param)
			if !slices.Equal(values, tt.wantValues) || ok != tt.wantOK {
				t.Fatalf("List(%q, %q) = (%q, %v), want (%q, %v)", tt.raw, tt.param, values, ok, tt.wantValues, tt.wantOK)
			}
		})
	}
}
