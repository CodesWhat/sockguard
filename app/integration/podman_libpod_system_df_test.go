//go:build podmanintegration

package integration_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/ownership"
	"github.com/codeswhat/sockguard/app/internal/responsefilter"
)

// libpodDFTestLabelKey is the owner label this file stamps on the container it
// creates, so the assertion below is about what Podman omits from its report
// rather than about a host that happens to have no labeled resources.
const libpodDFTestLabelKey = "com.sockguard.test.libpod-df"

// libpodSystemDFReportForTest is GET /libpod/system/df decoded one level down:
// the three item arrays are left raw so the test can inspect the exact keys
// Podman sent rather than the keys a Go struct would have invented.
type libpodSystemDFReportForTest struct {
	ImagesSize int64             `json:"ImagesSize"`
	Images     []json.RawMessage `json:"Images"`
	Containers []json.RawMessage `json:"Containers"`
	Volumes    []json.RawMessage `json:"Volumes"`
}

// TestRealPodmanLibpodSystemDFOmitsLabels is the load-bearing test for the
// refusal in internal/ownership and internal/visibility: it proves against a
// live daemon that GET /libpod/system/df strips the very labels sockguard
// isolates on, so there is no filter that could scope that response.
//
// It creates a container carrying an owner-shaped label, confirms through
// libpod's own inspect route that Podman stored it, and then shows that the
// same container's entry in the disk-usage report has no Labels key at all.
// Podman v5.8.1's abi.ContainerEngine.SystemDf builds each entry field by
// field and never calls c.Labels(), so this is the daemon's behavior and not
// a property of the request.
//
// A failure here is good news, not a regression: it means Podman started
// reporting labels and the refusal can become a FilterSystemDataUsage-style
// item filter.
func TestRealPodmanLibpodSystemDFOmitsLabels(t *testing.T) {
	socketPath := podmanSocketForIntegration(t)
	apiVersion := podmanLibpodAPIVersion(t, socketPath)
	versionPrefix := "/v" + apiVersion

	// No ownership options: this leg is about what Podman reports, so the
	// proxy is only used to create the fixture container.
	handler := newIntegrationProxyHandlerWithOptions(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/start"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	}, filter.Options{}, ownership.Options{})

	createPayload := `{"image":"` + busyboxPinnedRef + `","command":["sleep","30"],"systemd":"false",` +
		`"labels":{"` + libpodDFTestLabelKey + `":"team-a"}}`
	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodPost, versionPrefix+"/libpod/containers/create", strings.NewReader(createPayload))
	createReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d; body: %s", createRec.Code, http.StatusCreated, createRec.Body.String())
	}
	var created libpodContainerCreateResponse
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode libpod create response: %v", err)
	}
	if created.Id == "" {
		t.Fatal("expected libpod create response Id")
	}
	t.Cleanup(func() { removeLibpodContainer(t, socketPath, apiVersion, created.Id) })

	// The daemon must actually be holding the label, otherwise the disk-usage
	// assertion below would pass on a host with nothing to omit.
	if !libpodContainerHasTestLabel(t, socketPath, apiVersion, created.Id) {
		t.Fatalf("podman did not store label %q on the created container, so this test proves nothing", libpodDFTestLabelKey)
	}

	report := readLibpodSystemDF(t, socketPath, apiVersion)
	if len(report.Containers) == 0 {
		t.Fatal("libpod disk-usage report listed no containers even though one was just created")
	}

	// Transcribed from Podman v5.8.1 pkg/domain/entities/types/system.go. The
	// structs declare no json tags, so these Go field names are the wire
	// names.
	wantFields := map[string][]string{
		"Images":     {"Containers", "Created", "ImageID", "Repository", "SharedSize", "Size", "Tag", "UniqueSize"},
		"Containers": {"Command", "ContainerID", "Created", "Image", "LocalVolumes", "Names", "RWSize", "Size", "Status"},
		"Volumes":    {"Links", "ReclaimableSize", "Size", "VolumeName"},
	}
	sections := map[string][]json.RawMessage{
		"Images":     report.Images,
		"Containers": report.Containers,
		"Volumes":    report.Volumes,
	}
	foundOurs := false
	for section, items := range sections {
		for i, raw := range items {
			var item map[string]json.RawMessage
			if err := json.Unmarshal(raw, &item); err != nil {
				t.Fatalf("decode %s[%d]: %v", section, i, err)
			}
			if _, labeled := item["Labels"]; labeled {
				t.Errorf("%s[%d] carries Labels; /libpod/system/df is now classifiable and the refusal should become a filter: %s", section, i, raw)
			}
			got := make([]string, 0, len(item))
			for field := range item {
				got = append(got, field)
			}
			sort.Strings(got)
			if want := wantFields[section]; !slices.Equal(got, want) {
				t.Errorf("%s[%d] fields = %v, want %v (Podman v5.8.1 SystemDf*Report)", section, i, got, want)
			}
			if section == "Containers" && strings.Contains(string(raw), created.Id) {
				foundOurs = true
			}
		}
	}
	if !foundOurs {
		t.Errorf("the labeled container %q is absent from the disk-usage report, so the Labels assertion did not cover it", created.Id)
	}
	// Belt and braces against a future report that carries the label under
	// some key other than "Labels": the string the daemon is demonstrably
	// holding must not appear anywhere in the report at all.
	if encoded := mustMarshal(t, report); strings.Contains(string(encoded), libpodDFTestLabelKey) {
		t.Errorf("label key %q surfaced in the disk-usage report: %s", libpodDFTestLabelKey, encoded)
	}
}

// TestProxyRefusesLibpodSystemDFUnderOwnershipAgainstRealPodman is the
// end-to-end half: with owner isolation configured, an explicit allow rule for
// GET /libpod/system/df no longer opens the host inventory. Podman is never
// asked for the report.
func TestProxyRefusesLibpodSystemDFUnderOwnershipAgainstRealPodman(t *testing.T) {
	socketPath := podmanSocketForIntegration(t)
	apiVersion := podmanLibpodAPIVersion(t, socketPath)

	rules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/libpod/system/df"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	}

	t.Run("refused with owner isolation", func(t *testing.T) {
		handler := newIntegrationProxyHandlerWithOptions(t, socketPath, rules, filter.Options{},
			ownership.Options{Owner: "team-a"})

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v"+apiVersion+"/libpod/system/df", nil))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
		}
		for _, hostField := range []string{"ImagesSize", "ContainerID", "VolumeName", "Repository"} {
			if strings.Contains(rec.Body.String(), hostField) {
				t.Errorf("host inventory field %q reached the client: %s", hostField, rec.Body.String())
			}
		}
		if !strings.Contains(rec.Body.String(), "carry no labels") {
			t.Errorf("refusal does not say why it happened: %s", rec.Body.String())
		}
	})

	t.Run("forwarded without owner isolation", func(t *testing.T) {
		handler := newIntegrationProxyHandlerWithOptions(t, socketPath, rules, filter.Options{}, ownership.Options{})

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v"+apiVersion+"/libpod/system/df", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
		}
		// Podman initializes all three item slices, so a report always
		// carries the four top-level keys even on an idle host. Asserting
		// them proves the refused leg above is being compared against a real
		// answer rather than an endpoint that was broken anyway.
		var report map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
			t.Fatalf("decode forwarded report: %v; body: %s", err, rec.Body.String())
		}
		for _, key := range []string{"ImagesSize", "Images", "Containers", "Volumes"} {
			if _, ok := report[key]; !ok {
				t.Errorf("forwarded report has no %s key: %s", key, rec.Body.String())
			}
		}
	})
}

// TestLibpodSystemDFPathConstantMatchesPodmanRoute pins that the constant the
// two middlewares key on is the path a real client's request normalizes to.
func TestLibpodSystemDFPathConstantMatchesPodmanRoute(t *testing.T) {
	socketPath := podmanSocketForIntegration(t)
	apiVersion := podmanLibpodAPIVersion(t, socketPath)

	requested := "/v" + apiVersion + "/libpod/system/df"
	if got := filter.NormalizePath(requested); got != responsefilter.LibpodSystemDataUsagePath {
		t.Fatalf("NormalizePath(%q) = %q, want %q", requested, got, responsefilter.LibpodSystemDataUsagePath)
	}
}

func readLibpodSystemDF(t *testing.T, socketPath, apiVersion string) libpodSystemDFReportForTest {
	t.Helper()

	client, closeIdle := dockerHTTPClient(socketPath)
	defer closeIdle()

	req, err := http.NewRequest(http.MethodGet, "http://podman/v"+apiVersion+"/libpod/system/df", nil)
	if err != nil {
		t.Fatalf("new libpod system df request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("libpod system df request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<22))
	if err != nil {
		t.Fatalf("read libpod system df response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("libpod system df status = %d, want %d; body: %s", resp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}

	var report libpodSystemDFReportForTest
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatalf("decode libpod system df response: %v; body: %s", err, body)
	}
	return report
}

func libpodContainerHasTestLabel(t *testing.T, socketPath, apiVersion, containerID string) bool {
	t.Helper()

	client, closeIdle := dockerHTTPClient(socketPath)
	defer closeIdle()

	req, err := http.NewRequest(http.MethodGet, "http://podman/v"+apiVersion+"/libpod/containers/"+containerID+"/json", nil)
	if err != nil {
		t.Fatalf("new libpod inspect request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("libpod inspect request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<22))
	if err != nil {
		t.Fatalf("read libpod inspect response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("libpod inspect status = %d, want %d; body: %s", resp.StatusCode, http.StatusOK, strings.TrimSpace(string(body)))
	}
	return strings.Contains(string(body), libpodDFTestLabelKey)
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return encoded
}
