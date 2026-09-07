package filter

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"
)

// Eight mutants covered by this file's subjects stay alive on purpose, all
// verified by hand-applying the mutation and re-running this package:
//
//   - libpod_container_update.go buildLibpodContainerUpdateKnownFields, the
//     four `+` in the make([]string, 0, ...) capacity: the five gate lists are
//     5, 9, 1, 3 and 14 entries, so flipping any one `+` to `-` still gives a
//     non-negative capacity, and capacity is a hint that append ignores.
//   - libpod_container_update.go libpodContainerUpdateUnknownFields,
//     `len(unknown) > limit`: at exactly the limit, `>=` computes extra == 0
//     and reslices to the same elements, so the reported list is unchanged.
//   - libpod_container_update.go libpodContainerUpdateLogFieldName,
//     `len(trimmed) > 0`: `>= 0` makes the guard always true, and the loop
//     still stops because the empty string is valid UTF-8.
//   - container_create_types.go acquireContainerCreateRequest, `req == nil`:
//     the pool carries a New func, so Get never yields nil and both arms
//     return a request with every field at its zero value.
//   - registry_auth.go decodeRegistryAuthHeaderBytes,
//     `len(decoded) > maxRegistryAuthHeaderBytes`: the encoded form is already
//     capped at 8 KiB above, and base64 shrinks 4 bytes to 3, so a decode can
//     never exceed 6 KiB and the check is unreachable either way.

// TestOversizedForReuseAcceptsExactlyTheReuseCap pins the at-limit side of the
// three map gates in oversizedForReuse. A decode target holding exactly
// containerCreateReuseCap entries is still worth recycling; only one past the
// cap is not. Every existing case sits well clear of 64 in both directions, so
// the three gates can all slip a step without a test noticing.
func TestOversizedForReuseAcceptsExactlyTheReuseCap(t *testing.T) {
	labels := func(n int) map[string]string {
		m := make(map[string]string, n)
		for i := range n {
			m[string(rune('a'+i%26))+strings.Repeat("x", 1+i/26)] = "v"
		}
		if len(m) != n {
			t.Fatalf("labels(%d) built %d distinct keys", n, len(m))
		}
		return m
	}
	endpoints := func(n int) map[string]*networkEndpointConfig {
		m := make(map[string]*networkEndpointConfig, n)
		for i := range n {
			m[string(rune('a'+i%26))+strings.Repeat("x", 1+i/26)] = &networkEndpointConfig{}
		}
		if len(m) != n {
			t.Fatalf("endpoints(%d) built %d distinct keys", n, len(m))
		}
		return m
	}

	tests := []struct {
		name  string
		build func(*containerCreateRequest)
		want  bool
	}{
		{name: "empty request", build: func(*containerCreateRequest) {}, want: false},
		{
			name:  "labels exactly at the cap",
			build: func(r *containerCreateRequest) { r.Labels = labels(containerCreateReuseCap) },
			want:  false,
		},
		{
			name:  "labels one past the cap",
			build: func(r *containerCreateRequest) { r.Labels = labels(containerCreateReuseCap + 1) },
			want:  true,
		},
		{
			name:  "sysctls exactly at the cap",
			build: func(r *containerCreateRequest) { r.HostConfig.Sysctls = labels(containerCreateReuseCap) },
			want:  false,
		},
		{
			name:  "sysctls one past the cap",
			build: func(r *containerCreateRequest) { r.HostConfig.Sysctls = labels(containerCreateReuseCap + 1) },
			want:  true,
		},
		{
			name: "endpoints config exactly at the cap",
			build: func(r *containerCreateRequest) {
				r.NetworkingConfig.EndpointsConfig = endpoints(containerCreateReuseCap)
			},
			want: false,
		},
		{
			name: "endpoints config one past the cap",
			build: func(r *containerCreateRequest) {
				r.NetworkingConfig.EndpointsConfig = endpoints(containerCreateReuseCap + 1)
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := new(containerCreateRequest)
			tt.build(req)
			if got := req.oversizedForReuse(); got != tt.want {
				t.Fatalf("oversizedForReuse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsContainerRemovePathNeedsAnIdentifier pins that the bare collection
// path is not a remove target. DELETE /containers/ carries no container id, so
// treating it as a remove would run the remove policy against nothing.
func TestIsContainerRemovePathNeedsAnIdentifier(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "bare collection path", path: "/containers/", want: false},
		{name: "collection path without the trailing slash", path: "/containers", want: false},
		{name: "single character identifier", path: "/containers/a", want: true},
		{name: "full identifier", path: "/containers/abc123", want: true},
		{name: "unrelated path", path: "/images/abc123", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isContainerRemovePath(tt.path); got != tt.want {
				t.Fatalf("isContainerRemovePath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestFoldedScalarQueryValueHandlesAKeyWithNoValues covers a url.Values entry
// whose value slice is empty. url.ParseQuery never builds one, but the type is
// a plain exported map and callers hand it in directly, so the read has to
// answer "present, empty" instead of indexing off the front of the slice.
func TestFoldedScalarQueryValueHandlesAKeyWithNoValues(t *testing.T) {
	tests := []struct {
		name          string
		query         url.Values
		field         string
		wantValue     string
		wantFound     bool
		wantAmbiguous bool
	}{
		{name: "nil value slice", query: url.Values{"path": nil}, field: "path", wantValue: "", wantFound: true},
		{name: "empty value slice", query: url.Values{"path": {}}, field: "path", wantValue: "", wantFound: true},
		{name: "single value", query: url.Values{"path": {"/etc"}}, field: "path", wantValue: "/etc", wantFound: true},
		{name: "case folded key", query: url.Values{"PATH": {"/etc"}}, field: "path", wantValue: "/etc", wantFound: true},
		{name: "missing key", query: url.Values{"other": {"x"}}, field: "path"},
		{name: "repeated values are ambiguous", query: url.Values{"path": {"/a", "/b"}}, field: "path", wantFound: true, wantAmbiguous: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, found, ambiguous := FoldedScalarQueryValue(tt.query, tt.field)
			if value != tt.wantValue || found != tt.wantFound || ambiguous != tt.wantAmbiguous {
				t.Fatalf("FoldedScalarQueryValue(%v, %q) = (%q, %v, %v), want (%q, %v, %v)",
					tt.query, tt.field, value, found, ambiguous, tt.wantValue, tt.wantFound, tt.wantAmbiguous)
			}
		})
	}
}

// TestLibpodContainerUpdateLogFieldNameBounds pins the two edges of the
// reported-name bound: a name exactly at the limit is reported whole, and a
// name cut mid-rune is backed off to a rune boundary so the log line never
// carries invalid UTF-8.
func TestLibpodContainerUpdateLogFieldNameBounds(t *testing.T) {
	atLimit := strings.Repeat("a", libpodContainerUpdateUnknownFieldNameLimit)
	// Two bytes short of the limit, then two three-byte runes, so the cut at
	// the limit lands inside the first of them.
	splitRune := strings.Repeat("a", libpodContainerUpdateUnknownFieldNameLimit-2) + "€€"

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "short name unchanged", in: "CpuShares", want: "CpuShares"},
		{name: "name exactly at the limit unchanged", in: atLimit, want: atLimit},
		{
			name: "name one past the limit is cut and marked",
			in:   atLimit + "b",
			want: atLimit + "...",
		},
		{
			name: "cut backs off to a rune boundary",
			in:   splitRune,
			want: strings.Repeat("a", libpodContainerUpdateUnknownFieldNameLimit-2) + "...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := libpodContainerUpdateLogFieldName(tt.in)
			if got != tt.want {
				t.Fatalf("libpodContainerUpdateLogFieldName(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("libpodContainerUpdateLogFieldName(%q) = %q, which is not valid UTF-8", tt.in, got)
			}
		})
	}
}

// TestInspectLibpodDoesNotReportUnknownFieldsWhenThereAreNone pins that the
// unrecognized-field debug line is a signal and not noise: a body whose root
// keys the build already models must not produce it, or the line stops meaning
// "Podman's update body has grown past what we inspect".
func TestInspectLibpodDoesNotReportUnknownFieldsWhenThereAreNone(t *testing.T) {
	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))

	policy := newContainerUpdatePolicy(ContainerUpdateOptions{
		AllowRestartPolicy:   true,
		AllowResourceUpdates: true,
		AllowBlindWrites:     true,
		AllowAllDevices:      true,
	})
	body := `{"memory":{"limit":1}}`
	r := httptest.NewRequest(http.MethodPost, "/libpod/containers/abc/update", strings.NewReader(body))

	reason, err := policy.inspectLibpod(logger, r, "/libpod/containers/abc/update")
	if err != nil {
		t.Fatalf("inspectLibpod(%s) error = %v", body, err)
	}
	if reason != "" {
		t.Fatalf("inspectLibpod(%s) reason = %q, want no denial", body, reason)
	}
	if strings.Contains(logged.String(), "root fields this build does not inspect") {
		t.Fatalf("inspectLibpod(%s) reported unknown root fields for a body that has none:\n%s", body, logged.String())
	}
}

// TestInspectLibpodReportsUnknownRootFields is the positive half of the same
// contract, so the guard above cannot be satisfied by never logging at all.
func TestInspectLibpodReportsUnknownRootFields(t *testing.T) {
	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))

	policy := newContainerUpdatePolicy(ContainerUpdateOptions{
		AllowRestartPolicy:   true,
		AllowResourceUpdates: true,
		AllowBlindWrites:     true,
		AllowAllDevices:      true,
	})
	body := `{"SomeFieldPodmanGrew":1}`
	r := httptest.NewRequest(http.MethodPost, "/libpod/containers/abc/update", strings.NewReader(body))

	if _, err := policy.inspectLibpod(logger, r, "/libpod/containers/abc/update"); err != nil {
		t.Fatalf("inspectLibpod(%s) error = %v", body, err)
	}
	if !strings.Contains(logged.String(), "root fields this build does not inspect") {
		t.Fatalf("inspectLibpod(%s) did not report the unknown root field:\n%s", body, logged.String())
	}
	if !strings.Contains(logged.String(), "SomeFieldPodmanGrew") {
		t.Fatalf("inspectLibpod(%s) did not name the unknown root field:\n%s", body, logged.String())
	}
}
