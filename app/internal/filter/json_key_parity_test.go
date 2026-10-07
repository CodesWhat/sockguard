package filter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// jsoniterMatchesField is how json-iterator v1.1.12 binds an object key to a
// struct field under ConfigCompatibleWithStandardLibrary, the config Podman
// 6's utils.ReadJSONFromBody decodes with (pkg/api/handlers/utils/handler.go:
// `var json = jsoniter.ConfigCompatibleWithStandardLibrary`).
//
// decoderOfStruct (reflect_struct_decoder.go) builds a map holding each field
// name and its strings.ToLower. generalStructDecoder.decodeOneField looks the
// key up as written, and when that misses, looks up strings.ToLower(key):
//
//	fieldDecoder = decoder.fields[field]
//	if fieldDecoder == nil && !iter.cfg.caseSensitive {
//		fieldDecoder = decoder.fields[strings.ToLower(field)]
//	}
//
// The module isn't a dependency of this repo, so the rule is restated here.
// It was checked against the real decoder outside the repo: a scan of every
// rune against structs shaped like Podman's found the same two characters
// this test does.
func jsoniterMatchesField(key, field string) bool {
	if key == field || key == strings.ToLower(field) {
		return true
	}
	lowered := strings.ToLower(key)
	return lowered == field || lowered == strings.ToLower(field)
}

// encodingJSONMatchesField asks encoding/json itself, by decoding an object
// with that one key into a struct with that one field.
func encodingJSONMatchesField(t *testing.T, key string) bool {
	t.Helper()
	encodedKey, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	var probe struct {
		Kiss bool `json:"kiss"`
	}
	if err := json.Unmarshal([]byte("{"+string(encodedKey)+":true}"), &probe); err != nil {
		t.Fatalf("unmarshal probe for %q: %v", key, err)
	}
	return probe.Kiss
}

// TestDecoderDivergentKeyRunesCoverBothDecoders pins the characters a key is
// refused for against the two matching rules they exist to reconcile. Every
// rune is put in place of each letter of a field name that has a `k`, an `i`
// and an `s` in it, and both decoders are asked whether the key still binds.
//
// Where they disagree, the request has to be refused, and the test fails if
// isDecoderDivergentKeyRune lets one through. It also pins which runes those
// are, so a Go release that changes a case table shows up here and not in
// production.
func TestDecoderDivergentKeyRunesCoverBothDecoders(t *testing.T) {
	const field = "kiss"
	var jsoniterOnly, encodingJSONOnly []rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		for i := range len(field) {
			key := field[:i] + string(r) + field[i+1:]
			inJsoniter := jsoniterMatchesField(key, field)
			// encoding/json folds a key with bytes.EqualFold, so a rune
			// outside every fold orbit of an ASCII letter can't match and
			// isn't worth a decode.
			inEncodingJSON := strings.EqualFold(key, field) && encodingJSONMatchesField(t, key)
			if inJsoniter == inEncodingJSON {
				continue
			}
			if !isDecoderDivergentKeyRune(r) {
				t.Errorf("%U: key %+q binds to %q in json-iterator=%v and encoding/json=%v, and isn't refused", r, key, field, inJsoniter, inEncodingJSON)
			}
			if inJsoniter && !slices.Contains(jsoniterOnly, r) {
				jsoniterOnly = append(jsoniterOnly, r)
			}
			if inEncodingJSON && !slices.Contains(encodingJSONOnly, r) {
				encodingJSONOnly = append(encodingJSONOnly, r)
			}
		}
	}
	// The dangerous direction: the engine binds a key the gate never saw.
	if want := []rune{0x0130}; !slices.Equal(jsoniterOnly, want) {
		t.Errorf("runes only json-iterator matches = %U, want %U", jsoniterOnly, want)
	}
	// The other direction makes sockguard the stricter reader.
	if want := []rune{0x017F}; !slices.Equal(encodingJSONOnly, want) {
		t.Errorf("runes only encoding/json matches = %U, want %U", encodingJSONOnly, want)
	}
}

// TestDecoderDivergentKeyRunesAreTheCaseTablesWholeAnswer pins the rule
// against Go's case tables instead of against two decoders: the characters
// refused are every non-ASCII one that lowers, uppers, titles or folds to an
// ASCII letter, and no others. A decoder built on any of those primitives
// can only disagree with another over one of these.
func TestDecoderDivergentKeyRunesAreTheCaseTablesWholeAnswer(t *testing.T) {
	asciiLetter := func(r rune) bool { return r < utf8.RuneSelf && unicode.IsLetter(r) }
	var want, got []rune
	for r := rune(utf8.RuneSelf); r <= unicode.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		related := asciiLetter(unicode.ToLower(r)) || asciiLetter(unicode.ToUpper(r)) || asciiLetter(unicode.ToTitle(r))
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			related = related || asciiLetter(f)
		}
		if related {
			want = append(want, r)
		}
		if isDecoderDivergentKeyRune(r) {
			got = append(got, r)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("refused runes = %U, case tables give %U", got, want)
	}
	if pinned := []rune{0x0130, 0x0131, 0x017F, 0x212A}; !slices.Equal(got, pinned) {
		t.Fatalf("refused runes = %U, want %U", got, pinned)
	}
	for r := rune(0); r < utf8.RuneSelf; r++ {
		if isDecoderDivergentKeyRune(r) {
			t.Errorf("ASCII %U is refused", r)
		}
	}
}

// TestAmbiguousKeysAreRefusedAtEveryDepth drives both forms of the guard: the
// byte scan every inspected body goes through, and the walk owner isolation
// runs over the body it has already decoded. They have to agree.
func TestAmbiguousKeysAreRefusedAtEveryDepth(t *testing.T) {
	t.Parallel()
	refused := []struct {
		name string
		body string
		want rune
	}{
		{"libpod privileged", "{\"image\":\"alpine\",\"pr\u0130v\u0130leged\":true}", 0x0130},
		{"libpod pod pidns", "{\"name\":\"p\",\"p\u0130dns\":{\"nsmode\":\"host\"}}", 0x0130},
		{"compat HostConfig.Privileged", "{\"Image\":\"alpine\",\"HostConfig\":{\"Pr\u0130v\u0130leged\":true}}", 0x0130},
		{"escaped in the key", `{"HostConfig":{"Pr\u0130vileged":true}}`, 0x0130},
		{"under an array", "{\"mounts\":[{\"type\":\"bind\",\"dest\u0130nation\":\"/x\"}]}", 0x0130},
		{"a namespace's own key", "{\"pidns\":{\"n\u017fmode\":\"host\"}}", 0x017F},
		{"long s", "{\"u\u017fer\":\"0\"}", 0x017F},
		{"Kelvin sign", "{\"HostConfig\":{\"Networ\u212aMode\":\"host\"}}", 0x212A},
		{"dotless i", "{\"HostConfig\":{\"Pr\u0131vileged\":true}}", 0x0131},
		{"a label key", "{\"Labels\":{\"\u0130stanbul\":\"1\"}}", 0x0130},
		{"an env name", "{\"env\":{\"\u017f\":\"1\"}}", 0x017F},
		{"a struct under a data map", "{\"Networks\":{\"web\":{\"stat\u0130c_mac\":\"aa\"}}}", 0x0130},
		{"a key in a top-level array", "[{\"Na\u0130me\":\"network\"}]", 0x0130},
		{"after invalid UTF-8", "{\"a\xff\u0130\":1}", 0x0130},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := RejectDuplicateCaseVariantJSONKeys([]byte(tt.body))
			if !errors.Is(err, errDecoderDivergentKey) {
				t.Fatalf("RejectDuplicateCaseVariantJSONKeys() error = %v, want an ambiguous key", err)
			}
			if code := fmt.Sprintf("%U", tt.want); !strings.Contains(err.Error(), code) {
				t.Fatalf("error = %q, want it to name %s", err, code)
			}
			if strings.ContainsRune(err.Error(), tt.want) {
				t.Fatalf("error = %q, want the character escaped, not written out", err)
			}

			var decoded any
			dec := json.NewDecoder(strings.NewReader(tt.body))
			dec.UseNumber()
			if err := dec.Decode(&decoded); err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			if tt.name == "after invalid UTF-8" {
				// The decode turns the stray byte into U+FFFD, which changes
				// nothing about the character that follows it.
				decoded = map[string]any{"a\ufffd\u0130": json.Number("1")}
			}
			if err := RejectDuplicateCaseVariantJSONValue(decoded); !errors.Is(err, errDecoderDivergentKey) {
				t.Fatalf("RejectDuplicateCaseVariantJSONValue() error = %v, want an ambiguous key", err)
			}
		})
	}

	allowed := []string{
		`{"Image":"alpine","HostConfig":{"Privileged":false},"Labels":{"a":"b"}}`,
		// Non-ASCII keys are legal wherever a client names something.
		"{\"Labels\":{\"\u043a\u043b\u044e\u0447\":\"1\",\"\u65e5\u672c\u8a9e\":\"2\",\"caf\u00e9\":\"3\",\"\U0001F600\":\"4\"}}",
		"{\"env\":{\"\u00dcBER\":\"1\"},\"annotations\":{\"\u00e9\":\"2\"}}",
		"{\"\u00fcnknown\":1}",
		// The same characters as values are nobody's key.
		"{\"Labels\":{\"city\":\"\u0130stanbul\"},\"Env\":[\"K=\u212a\",\"S=\u017f\"],\"Cmd\":[\"\u0131\"]}",
		// Invalid UTF-8 matches no field in either decoder.
		"{\"privile\xffged\":true}",
	}
	for _, body := range allowed {
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			if err := RejectDuplicateCaseVariantJSONKeys([]byte(body)); err != nil {
				t.Fatalf("RejectDuplicateCaseVariantJSONKeys() error = %v, want nil", err)
			}
			var decoded any
			dec := json.NewDecoder(strings.NewReader(body))
			dec.UseNumber()
			if err := dec.Decode(&decoded); err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			if err := RejectDuplicateCaseVariantJSONValue(decoded); err != nil {
				t.Fatalf("RejectDuplicateCaseVariantJSONValue() error = %v, want nil", err)
			}
		})
	}
}

// TestLibpodDataMapsKeepCaseVariantEntries pins the Podman-native maps the
// sibling check spares. They hold names a client chose, where two entries
// that differ in case are two entries: an environment with both `http_proxy`
// and `HTTP_PROXY` is the one real clients send. A struct under one of them
// is still checked.
func TestLibpodDataMapsKeepCaseVariantEntries(t *testing.T) {
	t.Parallel()
	allowed := []string{
		`{"env":{"http_proxy":"a","HTTP_PROXY":"b"}}`,
		`{"secret_env":{"token":"s1","TOKEN":"s2"}}`,
		`{"sysctl":{"net.x":"1","NET.x":"2"}}`,
		`{"storage_opts":{"size":"1","Size":"2"}}`,
		`{"network_options":{"a":["1"],"A":["2"]}}`,
		`{"Networks":{"web":{},"Web":{}}}`,
		`{"networks":{"web":{},"Web":{}}}`,
		`{"ipam_options":{"driver":"a","Driver":"b"}}`,
		`{"unified":{"memory.high":"1","MEMORY.high":"2"}}`,
		`{"weightDevice":{"/dev/a":{},"/dev/A":{}}}`,
		`{"throttleReadBpsDevice":{"/dev/a":{},"/dev/A":{}},"throttleWriteBpsDevice":{"/dev/a":{},"/dev/A":{}}}`,
		`{"throttleReadIOPSDevice":{"/dev/a":{},"/dev/A":{}},"throttleWriteIOPSDevice":{"/dev/a":{},"/dev/A":{}}}`,
		`{"Label":{"a":"1","A":"2"}}`,
		`{"resource_limits":{"unified":{"a":"1","A":"2"}}}`,
	}
	for _, body := range allowed {
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			if err := RejectDuplicateCaseVariantJSONKeys([]byte(body)); err != nil {
				t.Fatalf("RejectDuplicateCaseVariantJSONKeys() error = %v, want nil", err)
			}
			var decoded any
			if err := json.Unmarshal([]byte(body), &decoded); err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			if err := RejectDuplicateCaseVariantJSONValue(decoded); err != nil {
				t.Fatalf("RejectDuplicateCaseVariantJSONValue() error = %v, want nil", err)
			}
		})
	}

	refused := []string{
		`{"env":{"A":"1"},"ENV":{"a":"2"}}`,
		`{"Networks":{"web":{"static_mac":"a","STATIC_MAC":"b"}}}`,
		`{"Networks":{"env":{"static_mac":"a","Static_Mac":"b"}}}`,
		`{"secret_env":{"K":"s"},"secret_env":{"K":"t"}}`,
	}
	for _, body := range refused {
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			if err := RejectDuplicateCaseVariantJSONKeys([]byte(body)); err == nil {
				t.Fatal("RejectDuplicateCaseVariantJSONKeys() error = nil, want a duplicate-key rejection")
			}
		})
	}

	for _, name := range []string{
		"env", "secret_env", "sysctl", "storage_opts", "expose", "network_options", "networks", "ipam_options",
		"unified", "weightdevice", "throttlereadbpsdevice", "throttlewritebpsdevice", "throttlereadiopsdevice",
		"throttlewriteiopsdevice", "label",
	} {
		if !isCaseSensitiveDataMapField(name) || !isCaseSensitiveDataMapField(strings.ToUpper(name)) {
			t.Errorf("isCaseSensitiveDataMapField(%q) = false in some case", name)
		}
		if len(name) > caseSensitiveDataMapFieldMaxLen {
			t.Errorf("%q is longer than caseSensitiveDataMapFieldMaxLen (%d)", name, caseSensitiveDataMapFieldMaxLen)
		}
	}
}

// TestReadBoundedBodyRefusesAmbiguousKeys pins the one place every inspector
// reads its body: a body that reads two ways comes back as a 400 rejection
// naming the key, and the request still carries every byte, because warn and
// audit forward what enforce refuses.
func TestReadBoundedBodyRefusesAmbiguousKeys(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		body       string
		wantReason string
	}{
		{
			name:       "a key holding U+0130",
			body:       "{\"image\":\"alpine\",\"pr\u0130v\u0130leged\":true}",
			wantReason: `request body denied: ambiguous JSON object key "pr\u0130v\u0130leged": U+0130 matches a field name in some JSON decoders and not in others`,
		},
		{
			name:       "a repeated key",
			body:       `{"HostConfig":{"Memory":268435456},"HostConfig":null}`,
			wantReason: `request body denied: duplicate case-variant JSON keys "HostConfig" and "HostConfig"`,
		},
		{
			name:       "a string followed by a null under the same key",
			body:       `{"user":"1000","USER":null}`,
			wantReason: `request body denied: duplicate case-variant JSON keys "user" and "USER"`,
		},
		{
			name:       "a long key is cut where it's quoted",
			body:       "{\"" + strings.Repeat("a", 200) + "\u0130\":1}",
			wantReason: `request body denied: ambiguous JSON object key "` + strings.Repeat("a", 64) + `...": U+0130 matches a field name in some JSON decoders and not in others`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(tt.body))
			body, err := readBoundedBody(req, maxContainerCreateBodyBytes)
			if body != nil {
				t.Fatalf("readBoundedBody() body = %q, want nil", body)
			}
			// Inspectors wrap what they get back, and the middleware has to
			// find the rejection through the wrap.
			rejection, ok := requestRejectionFromError(errors.Join(errors.New("read body"), err))
			if !ok {
				t.Fatalf("readBoundedBody() error = %v, want a request rejection", err)
			}
			if rejection.status != http.StatusBadRequest || rejection.reasonCode != reasonCodeRequestBodyAmbiguous || rejection.reason != tt.wantReason {
				t.Fatalf("rejection = %d %q %q, want %d %q %q", rejection.status, rejection.reasonCode, rejection.reason, http.StatusBadRequest, reasonCodeRequestBodyAmbiguous, tt.wantReason)
			}
			restored, err := io.ReadAll(req.Body)
			if err != nil || string(restored) != tt.body {
				t.Fatalf("restored body = %q, %v, want the bytes the client sent", restored, err)
			}
			if req.ContentLength != int64(len(tt.body)) {
				t.Fatalf("ContentLength = %d, want %d", req.ContentLength, len(tt.body))
			}
		})
	}

	// A body the scan can't parse is the inspector's to refuse, under its
	// own name, and so is one that isn't JSON at all.
	for _, body := range []string{`{"a":`, `{bad}`, `not json`, ``, `{"a":1}{"a":2}`} {
		t.Run("left to the inspector: "+body, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(body))
			got, err := readBoundedBody(req, maxContainerCreateBodyBytes)
			if err != nil || !bytes.Equal(got, []byte(body)) {
				t.Fatalf("readBoundedBody() = %q, %v, want the body and no error", got, err)
			}
		})
	}
}

// TestEveryBodyInspectorRefusesAmbiguousKeys sends the same two bodies down
// every route an inspector reads a JSON body on. A route missing here would
// be one where a gate reads a body the engine reads differently.
func TestEveryBodyInspectorRefusesAmbiguousKeys(t *testing.T) {
	t.Parallel()
	routes := []struct{ method, path string }{
		{http.MethodPost, "/containers/create"},
		{http.MethodPost, "/v5.8.6/libpod/containers/create"},
		{http.MethodPost, "/v5.8.6/libpod/pods/create"},
		{http.MethodPost, "/containers/abc/exec"},
		{http.MethodPost, "/v5.8.6/libpod/containers/abc/exec"},
		{http.MethodPost, "/containers/abc/update"},
		{http.MethodPost, "/v5.8.6/libpod/containers/abc/update"},
		{http.MethodPost, "/volumes/create"},
		{http.MethodPut, "/volumes/abc"},
		{http.MethodPost, "/v5.8.6/libpod/volumes/create"},
		{http.MethodPost, "/networks/create"},
		{http.MethodPost, "/networks/abc/connect"},
		{http.MethodPost, "/networks/abc/disconnect"},
		{http.MethodPost, "/v5.8.6/libpod/networks/create"},
		{http.MethodPost, "/v5.8.6/libpod/networks/abc/connect"},
		{http.MethodPost, "/v5.8.6/libpod/networks/abc/disconnect"},
		{http.MethodPost, "/v5.8.6/libpod/networks/abc/update"},
		{http.MethodPost, "/secrets/create"},
		{http.MethodPost, "/configs/create"},
		{http.MethodPost, "/services/create"},
		{http.MethodPost, "/services/abc/update"},
		{http.MethodPost, "/swarm/init"},
		{http.MethodPost, "/swarm/join"},
		{http.MethodPost, "/swarm/update"},
		{http.MethodPost, "/swarm/unlock"},
		{http.MethodPost, "/nodes/abc/update"},
		{http.MethodPost, "/plugins/pull"},
		{http.MethodPost, "/plugins/abc/upgrade"},
		{http.MethodPost, "/plugins/abc/set"},
	}
	bodies := []struct{ name, body, wantReason string }{
		{
			"a key holding U+0130",
			"{\"Pr\u0130vileged\":true}",
			`request body denied: ambiguous JSON object key "Pr\u0130vileged": U+0130 matches a field name in some JSON decoders and not in others`,
		},
		{
			"a repeated key",
			`{"Name":"a","Name":null}`,
			`request body denied: duplicate case-variant JSON keys "Name" and "Name"`,
		},
	}
	for _, route := range routes {
		for _, b := range bodies {
			t.Run(route.method+" "+route.path+"/"+b.name, func(t *testing.T) {
				t.Parallel()
				rule, err := CompileRule(Rule{Methods: []string{route.method}, Pattern: "/**", Action: ActionAllow, Index: 0})
				if err != nil {
					t.Fatalf("CompileRule: %v", err)
				}
				reached := false
				handler := MiddlewareWithOptions([]*CompiledRule{rule}, nil, Options{
					PolicyConfig: PolicyConfig{DenyResponseVerbosity: DenyResponseVerbosityVerbose},
				})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					reached = true
					w.WriteHeader(http.StatusNoContent)
				}))
				req := httptest.NewRequest(route.method, route.path, strings.NewReader(b.body))
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				if reached {
					t.Fatalf("the request reached the upstream; status %d", rec.Code)
				}
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
				}
				var denial DenialResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &denial); err != nil || denial.Reason != b.wantReason {
					t.Fatalf("body = %s, want reason %q", rec.Body.String(), b.wantReason)
				}
			})
		}
	}
}

// TestRepeatedKeyReadsDifferentlyByTypeShape is why a repeated key is refused
// outright instead of being read the way the engine reads it. What a repeat
// means depends on the Go type it lands in, and sockguard's types aren't the
// engine's: dockerd's container.CreateRequest holds HostConfig as a pointer
// (api/types/container/create_request.go), which a later null resets, and
// sockguard's containerCreateRequest holds it as a struct, which a null
// leaves alone. Same bytes, same decoder, and the gate sees a memory limit
// the daemon doesn't.
func TestRepeatedKeyReadsDifferentlyByTypeShape(t *testing.T) {
	body := []byte(`{"HostConfig":{"Memory":268435456},"HostConfig":null}`)

	var sockguard containerCreateRequest
	if err := json.Unmarshal(body, &sockguard); err != nil {
		t.Fatalf("decode as sockguard: %v", err)
	}
	if sockguard.HostConfig.Memory != 268435456 {
		t.Fatalf("sockguard reads Memory = %d, want the first HostConfig kept", sockguard.HostConfig.Memory)
	}

	var dockerd struct {
		HostConfig *struct{ Memory int64 }
	}
	if err := json.Unmarshal(body, &dockerd); err != nil {
		t.Fatalf("decode as dockerd: %v", err)
	}
	if dockerd.HostConfig != nil {
		t.Fatalf("dockerd reads HostConfig = %+v, want it reset by the null", dockerd.HostConfig)
	}

	if err := RejectDuplicateCaseVariantJSONKeys(body); err == nil {
		t.Fatal("RejectDuplicateCaseVariantJSONKeys() error = nil, want the repeat refused")
	}
}
