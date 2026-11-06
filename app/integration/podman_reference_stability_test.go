//go:build podmanintegration

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/filter"
	"github.com/codeswhat/sockguard/v3/app/internal/ownership"
	"strings"
	"testing"
	"time"
)

type podmanReferenceProbe struct {
	t      *testing.T
	client *http.Client
	prefix string
}

func newPodmanReferenceProbe(t *testing.T) podmanReferenceProbe {
	t.Helper()
	socket := podmanSocketForIntegration(t)
	client, closeIdle := dockerHTTPClient(socket)
	t.Cleanup(closeIdle)
	return podmanReferenceProbe{t: t, client: client, prefix: "/v" + podmanLibpodAPIVersion(t, socket) + "/libpod"}
}

func (p podmanReferenceProbe) request(method, path, contentType string, body []byte) (int, []byte) {
	p.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "http://podman"+path, bytes.NewReader(body))
	if err != nil {
		p.t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		p.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		p.t.Fatalf("%s %s: response read error=%v size=%d", method, path, err, len(data))
	}
	return resp.StatusCode, data
}

func (p podmanReferenceProbe) json(method, path string, body any) []byte {
	p.t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			p.t.Fatal(err)
		}
	}
	status, result := p.request(method, path, "application/json", data)
	if status < 200 || status >= 300 {
		p.t.Fatalf("%s %s: status=%d body=%s", method, path, status, result)
	}
	return result
}

func TestPodmanNetworkReferenceStability(t *testing.T) {
	p := newPodmanReferenceProbe(t)
	name := fmt.Sprintf("sockguard-ref-%d", time.Now().UnixNano())
	networkPath := p.prefix + "/networks/" + name
	created := p.json(http.MethodPost, p.prefix+"/networks/create", map[string]any{"name": name, "labels": map[string]string{"fixture": "original", "com.sockguard.owner": "job-123"}})
	var network struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created, &network); err != nil || network.ID == "" {
		t.Fatalf("network create: %s (%v)", created, err)
	}
	t.Cleanup(func() { p.request(http.MethodDelete, networkPath, "", nil) })
	created = p.json(http.MethodPost, p.prefix+"/containers/create", map[string]any{
		"image": busyboxPinnedRef, "command": []string{"sleep", "30"}, "systemd": "false",
		"netns": map[string]string{"nsmode": "bridge"}, "Networks": map[string]any{name: map[string]any{}},
	})
	var container libpodContainerCreateResponse
	if err := json.Unmarshal(created, &container); err != nil || container.Id == "" {
		t.Fatalf("container create: %s (%v)", created, err)
	}
	containerPath := p.prefix + "/containers/" + container.Id
	t.Cleanup(func() { p.request(http.MethodDelete, containerPath+"?force=true", "", nil) })
	var inspect struct {
		NetworkSettings struct{ Networks map[string]json.RawMessage }
	}
	data := p.json(http.MethodGet, containerPath+"/json", nil)
	if err := json.Unmarshal(data, &inspect); err != nil {
		t.Fatal(err)
	}
	if _, ok := inspect.NetworkSettings.Networks[name]; !ok {
		t.Fatalf("created container does not retain network name %q: %s", name, data)
	}
	handler := newIntegrationProxyHandlerWithOptions(t, podmanSocketForIntegration(t), []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodDelete, Path: "/libpod/networks/**"}, Action: "allow"},
	}, filter.Options{}, ownership.Options{Owner: "job-123", LabelKey: "com.sockguard.owner"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, p.prefix+"/networks/"+network.ID, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("proxy network ID delete: status=%d body=%s, want 404", rec.Code, rec.Body.String())
	}
	if status, data := p.request(http.MethodGet, networkPath+"/json", "", nil); status != http.StatusOK {
		t.Fatalf("proxy removed network: status=%d body=%s", status, data)
	}
	nameStatus, _ := p.request(http.MethodDelete, networkPath, "", nil)
	if status, body := p.request(http.MethodGet, networkPath+"/json", "", nil); status != http.StatusOK {
		t.Fatalf("name deletion removed an in-use network: delete=%d inspect=%d body=%s", nameStatus, status, body)
	}
	idStatus, _ := p.request(http.MethodDelete, p.prefix+"/networks/"+network.ID, "", nil)
	status, data := p.request(http.MethodGet, networkPath+"/json", "", nil)
	if status == http.StatusOK {
		t.Logf("network reference: name delete=%d ID delete=%d; engine retains in-use network", nameStatus, idStatus)
		return
	}
	if status != http.StatusNotFound {
		t.Fatalf("inspect after ID deletion: status=%d body=%s", status, data)
	}
	data = p.json(http.MethodGet, containerPath+"/json", nil)
	if err := json.Unmarshal(data, &inspect); err != nil {
		t.Fatal(err)
	}
	if _, ok := inspect.NetworkSettings.Networks[name]; !ok {
		t.Fatalf("network deletion unexpectedly removed the stored reference: %s", data)
	}
	replacement := p.json(http.MethodPost, p.prefix+"/networks/create", map[string]any{"name": name, "labels": map[string]string{"fixture": "replacement"}})
	var next struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(replacement, &next); err != nil || next.ID == "" || next.ID == network.ID {
		t.Fatalf("replacement network: %s (%v)", replacement, err)
	}
	t.Logf("network reference rebound: original=%s replacement=%s stored_name=%s name_delete=%d ID_delete=%d", network.ID, next.ID, name, nameStatus, idStatus)
}

func TestPodmanManifestFullIDReferenceStability(t *testing.T) {
	p := newPodmanReferenceProbe(t)
	nonce := fmt.Sprint(time.Now().UnixNano())
	var ids []string
	var refs []string
	for _, suffix := range []string{"a", "b"} {
		ref := "localhost/sockguard-ref:" + nonce + "-" + suffix
		archive, id := podmanHistoryArchive(t, ref, suffix, []string{"RUN fixture-" + suffix})
		status, data := p.request(http.MethodPost, p.prefix+"/images/load", "application/x-tar", archive)
		if status != http.StatusOK {
			t.Fatalf("load fixture: status=%d body=%s", status, data)
		}
		t.Cleanup(func() { p.request(http.MethodDelete, "/v1.40/images/"+ref+"?force=true", "", nil) })
		ids, refs = append(ids, id), append(refs, ref)
	}
	name := "localhost/sockguard-ref-list:" + nonce
	created := p.json(http.MethodPost, p.prefix+"/manifests/"+name, map[string]any{"images": []string{"containers-storage:" + refs[0]}})
	var list struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(created, &list); err != nil || list.ID == "" {
		t.Fatalf("manifest create: %s (%v)", created, err)
	}
	t.Cleanup(func() { p.request(http.MethodDelete, p.prefix+"/manifests/"+name, "", nil) })
	inspectID := func() string {
		data := p.json(http.MethodGet, p.prefix+"/images/"+list.ID+"/json", nil)
		var image struct {
			ID string `json:"Id"`
		}
		if err := json.Unmarshal(data, &image); err != nil {
			t.Fatal(err)
		}
		return strings.TrimPrefix(image.ID, "sha256:")
	}
	before := inspectID()
	data := p.json(http.MethodGet, p.prefix+"/manifests/"+list.ID+"/json", nil)
	var manifest struct {
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil || len(manifest.Manifests) != 1 {
		t.Fatalf("manifest inspect: %s (%v)", data, err)
	}
	for _, change := range []map[string]any{
		{"operation": "remove", "images": []string{manifest.Manifests[0].Digest}},
		{"operation": "update", "images": []string{"containers-storage:" + refs[1]}},
	} {
		data := p.json(http.MethodPut, p.prefix+"/manifests/"+list.ID, change)
		var changed struct {
			ID     string   `json:"Id"`
			Errors []string `json:"errors"`
		}
		if err := json.Unmarshal(data, &changed); err != nil || len(changed.Errors) != 0 || changed.ID != list.ID {
			t.Fatalf("modify manifest: %s (%v)", data, err)
		}
	}
	after := inspectID()
	if before != ids[0] || after != ids[1] {
		t.Fatalf("full list ID resolution: before=%s after=%s want=%v", before, after, ids)
	}
	t.Logf("manifest full ID rebound: list=%s before=%s after=%s", list.ID, before, after)
}
