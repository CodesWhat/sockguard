package upstreamflavor

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbePodmanVolumeCapabilities(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, version, header string
		want                  bool
	}{
		{"old", "5.8.1", "", false},
		{"six", "6.0.0", "", true},
		{"later", "6.2.1", "", true},
		{"next major", "7.0.0", "", true},
		{"unknown", "", "", false},
		{"prerelease", "6.0.0-rc.1", "", false},
		{"release with build", "6.0.0+vendor.1", "", true},
		{"malformed build", "6.0.0+..", "", false},
		{"partial", "6.0", "", false},
		{"leading zero", "06.0.0", "", false},
		{"overflow", "999999999999999999999999.0.0", "", false},
		{"consistent header", "6.0.1", "Libpod/6.0.1", true},
		{"old header", "6.0.1", "Libpod/5.8.1", false},
		{"unknown header version", "6.0.1", "Libpod/", false},
		{"old component", "5.8.1", "Libpod/6.0.1", false},
		{"mixed headers", "6.0.1", "Libpod/6.0.1 Libpod/5.8.1", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Server", test.header)
				_, _ = fmt.Fprintf(w, `{"Components":[{"Name":"Podman Engine","Version":%q}]}`, test.version)
			}))
			defer server.Close()
			got, err := Probe(t.Context(), clientFor(server.Listener.Addr().String()))
			if err != nil || got.Flavor != Podman || got.PodmanConjunctiveVolumeFilters != test.want {
				t.Fatalf("Probe=%+v error=%v, want Podman volume capability %v", got, err, test.want)
			}
		})
	}
}

func TestProbeHeaderIdentityAndAmbiguity(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, header, body  string
		status              int
		flavor              Flavor
		capability, wantErr bool
	}{
		{"header only", "Libpod/6.0.0", `{}`, 200, Podman, true, false},
		{"header case insensitive", "libpod/6.0.0", `{}`, 200, Podman, true, false},
		{"unknown header version", "Libpod/unknown", `{}`, 200, Podman, false, false},
		{"failed route", "Libpod/6.0.0", `failed`, 503, Podman, false, true},
		{"malformed response", "Libpod/6.0.0", `{`, 200, Podman, false, true},
		{"contradiction", "Libpod/6.0.0", dockerVersionBody, 200, Podman, false, true},
		{"ambiguous components", "", `{"Components":[{"Name":"Engine"},{"Name":"Podman Engine","Version":"6.0.0"}]}`, 200, Podman, false, true},
		{"duplicate old component", "", `{"Components":[{"Name":"Podman Engine","Version":"6.0.0"},{"Name":"Podman Engine","Version":"5.8.1"}]}`, 200, Podman, false, false},
		{"docker", "", dockerVersionBody, 200, Docker, false, false},
		{"unknown", "", `{}`, 200, "", false, true},
		{"similar header", "NotLibpod/6.0.0", `{}`, 200, "", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Server", test.header)
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			got, err := Probe(t.Context(), clientFor(server.Listener.Addr().String()))
			if (err != nil) != test.wantErr || got.Flavor != test.flavor || got.PodmanConjunctiveVolumeFilters != test.capability {
				t.Fatalf("Probe=%+v err=%v, want flavor=%s capability=%v error=%v", got, err, test.flavor, test.capability, test.wantErr)
			}
		})
	}
}

func TestProbeDoesNotFollowRedirectsThatHideIdentity(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			w.Header().Set("Server", "Libpod/6.0.0")
			w.Header().Set("Location", "/different-version")
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(dockerVersionBody))
	}))
	defer server.Close()
	client := clientFor(server.Listener.Addr().String())
	got, err := Probe(t.Context(), client)
	if err == nil || got.Flavor != Podman || got.PodmanConjunctiveVolumeFilters {
		t.Fatalf("redirect hid identity: result=%+v error=%v", got, err)
	}
	if client.CheckRedirect != nil {
		t.Fatal("Probe mutated its shared client's redirect policy")
	}
}
