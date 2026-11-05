//go:build podmanintegration

package integration_test

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/proxy"
	"github.com/codeswhat/sockguard/v3/app/internal/responsefilter"
)

func TestProxyRedactsImageHistoryAgainstRealPodman(t *testing.T) {
	socketPath := podmanSocketForIntegration(t)
	apiVersion := podmanLibpodAPIVersion(t, socketPath)
	client, closeIdle := dockerHTTPClient(socketPath)
	t.Cleanup(closeIdle)
	nonce := fmt.Sprint(time.Now().UnixNano())
	imageRef := "localhost/sockguard-history:fixture-" + nonce
	marker := "history-canary-" + nonce
	instructions := []string{
		"ENV SOCKGUARD_HISTORY_CANARY=" + marker,
		"ARG SOCKGUARD_BUILD_CANARY=" + marker,
		"RUN echo retained-history",
	}
	archive, imageID := podmanHistoryArchive(t, imageRef, marker, instructions)
	t.Cleanup(func() {
		req, err := http.NewRequest(http.MethodDelete, "http://podman/v1.40/images/"+imageRef+"?force=true", nil)
		if err != nil {
			t.Error(err)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("remove history fixture: %v", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			t.Errorf("remove history fixture: status %d", resp.StatusCode)
		}
	})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://podman/v"+apiVersion+"/libpod/images/load", bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-tar")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("load history fixture: %v", err)
	}
	loaded, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if readErr != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("load history fixture: status=%d error=%v body=%s", resp.StatusCode, readErr, loaded)
	}
	for _, route := range []struct{ name, prefix string }{
		{name: "compat", prefix: "/v1.40"},
		{name: "native", prefix: "/v" + apiVersion + "/libpod"},
	} {
		t.Run(route.name, func(t *testing.T) {
			path := route.prefix + "/images/" + imageID + "/history"
			direct, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://podman"+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := client.Do(direct)
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(io.LimitReader(raw.Body, 1<<20))
			_ = raw.Body.Close()
			if readErr != nil || raw.StatusCode != http.StatusOK {
				t.Fatalf("raw history: status=%d error=%v body=%s", raw.StatusCode, readErr, body)
			}
			var original []map[string]any
			if err := json.Unmarshal(body, &original); err != nil {
				t.Fatalf("decode raw history: %v; body=%s", err, body)
			}
			redactor := responsefilter.New(responsefilter.Options{RedactContainerEnv: true})
			transport := dockerSocketRoundTripper(socketPath)
			t.Cleanup(transport.CloseIdleConnections)
			handler := proxy.NewWithTransport(transport, newIntegrationLogger(), proxy.Options{ModifyResponse: redactor.ModifyResponse})
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("filtered history: status=%d body=%s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), marker) {
				t.Fatal("filtered history still contains the canary value")
			}
			var filtered []map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &filtered); err != nil {
				t.Fatal(err)
			}
			if len(filtered) != len(original) {
				t.Fatalf("history entries = %d, want %d", len(filtered), len(original))
			}
			for i, instruction := range instructions {
				found := false
				for row, entry := range original {
					for key, value := range entry {
						if text, ok := value.(string); !ok || text != instruction {
							continue
						}
						found = true
						want := instruction
						if i < 2 {
							want = strings.Fields(instruction)[0] + " <redacted>"
						}
						if got := filtered[row][key]; got != want {
							t.Errorf("history[%d][%q] = %q, want %q", row, key, got, want)
						}
						t.Logf("Podman API %s %s history instruction key=%q", apiVersion, route.name, key)
					}
				}
				if !found {
					t.Fatalf("real daemon did not report fixture instruction %q; body=%s", instruction, body)
				}
			}
		})
	}
}

func podmanHistoryArchive(t *testing.T, imageRef, marker string, instructions []string) ([]byte, string) {
	t.Helper()
	created := time.Now().UTC().Format(time.RFC3339Nano)
	history := make([]map[string]any, 0, len(instructions))
	for _, instruction := range instructions {
		history = append(history, map[string]any{"created": created, "created_by": instruction, "empty_layer": true})
	}
	config, err := json.Marshal(map[string]any{
		"created": created, "architecture": "amd64", "os": "linux",
		"config": map[string]any{"Env": []string{"SOCKGUARD_HISTORY_CANARY=" + marker}},
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{}}, "history": history,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(config)
	imageID := hex.EncodeToString(digest[:])
	configName := imageID + ".json"
	manifest, err := json.Marshal([]map[string]any{{"Config": configName, "RepoTags": []string{imageRef}, "Layers": []string{}}})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for _, file := range []struct {
		name string
		body []byte
	}{{configName, config}, {"manifest.json", manifest}} {
		if err := w.WriteHeader(&tar.Header{Name: file.name, Mode: 0o600, Size: int64(len(file.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(file.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), imageID
}
