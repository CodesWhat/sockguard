package responsefilter

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

const volumeOptionsJSON = `{"type":"cifs","device":"//nas/share","o":"username=svc,password=S3cret"}`

var volumeOptionSecrets = []string{"S3cret", "//nas/share", "username=svc"}

func volumeBody(options string) string {
	return `{"Name":"data","Mountpoint":"/var/lib/docker/volumes/data/_data","Options":` + options + `}`
}

func TestVolumeDriverOptionsRedacted(t *testing.T) {
	t.Parallel()

	vol := volumeBody(volumeOptionsJSON)
	routes := []struct {
		name string
		path string
		body string
	}{
		{"list", "/volumes", `{"Volumes":[` + vol + `],"Warnings":null}`},
		{"inspect", "/v1.45/volumes/data", vol},
		{"df-usage", "/system/df", `{"VolumeUsage":{"Items":[` + vol + `]}}`},
		{"df-legacy", "/v1.45/system/df", `{"Volumes":[` + vol + `]}`},
		{"libpod-list", "/v5.8.1/libpod/volumes/json", `[` + vol + `]`},
		{"libpod-inspect", "/v5.8.1/libpod/volumes/data/json", vol},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()
			f := New(Options{RedactMountPaths: true})
			resp := newResponseForTest(t, http.MethodGet, route.path, route.body)
			if err := f.ModifyResponse(resp); err != nil {
				t.Fatalf("ModifyResponse: %v", err)
			}
			raw, _ := io.ReadAll(resp.Body)
			got := string(raw)
			for _, secret := range volumeOptionSecrets {
				if strings.Contains(got, secret) {
					t.Fatalf("body still contains %q: %s", secret, got)
				}
			}
			for _, key := range []string{`"type"`, `"device"`, `"o"`} {
				if !strings.Contains(got, key) {
					t.Fatalf("body lost option key %s: %s", key, got)
				}
			}
			if strings.Contains(got, "/var/lib/docker/volumes") {
				t.Fatalf("Mountpoint not redacted: %s", got)
			}
		})
	}
}

func TestVolumeDriverOptionsShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		options    Options
		body       string
		wantReject bool
		wantBody   string
	}{
		{"null passes through", Options{RedactMountPaths: true}, `{"Name":"d","Options":null}`, false, `"Options":null`},
		{"absent passes through", Options{RedactMountPaths: true}, `{"Name":"d"}`, false, `{"Name":"d"}`},
		{"string rejected", Options{RedactMountPaths: true}, `{"Name":"d","Options":"x"}`, true, ""},
		{"array rejected", Options{RedactMountPaths: true}, `{"Name":"d","Options":["x"]}`, true, ""},
		{"sensitive data only redacts options not mountpoint", Options{RedactSensitiveData: true},
			volumeBody(volumeOptionsJSON), false, `"Mountpoint":"/var/lib/docker/volumes/data/_data"`},
		{"all off leaves body untouched", Options{}, volumeBody(volumeOptionsJSON), false, "S3cret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := New(tt.options)
			resp := newResponseForTest(t, http.MethodGet, "/v1.45/volumes/d", tt.body)
			err := f.ModifyResponse(resp)
			if tt.wantReject {
				if err == nil {
					t.Fatal("ModifyResponse error = nil, want rejection")
				}
				return
			}
			if err != nil {
				t.Fatalf("ModifyResponse: %v", err)
			}
			raw, _ := io.ReadAll(resp.Body)
			got := string(raw)
			if !strings.Contains(got, tt.wantBody) {
				t.Fatalf("body %s missing %q", got, tt.wantBody)
			}
			if tt.options == (Options{RedactSensitiveData: true}) {
				for _, secret := range volumeOptionSecrets {
					if strings.Contains(got, secret) {
						t.Fatalf("body still contains %q: %s", secret, got)
					}
				}
			}
		})
	}
}

func TestSystemDataUsageVolumeOptionsWithSensitiveDataOnly(t *testing.T) {
	t.Parallel()

	f := New(Options{RedactSensitiveData: true})
	resp := newResponseForTest(t, http.MethodGet, "/system/df", `{"VolumeUsage":{"Items":[`+volumeBody(volumeOptionsJSON)+`]}}`)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(raw), "S3cret") {
		t.Fatalf("password leaked: %s", raw)
	}
}
