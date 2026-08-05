//go:build integration

package integration_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/ownership"
)

func TestResourceLimitContainerUpdatesAgainstRealDocker(t *testing.T) {
	socketPath := dockerSocketForIntegration(t)
	rules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/update"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	}
	handler := newIntegrationProxyHandlerWithOptions(t, socketPath, rules, filter.Options{
		PolicyConfig: filter.PolicyConfig{
			ContainerUpdate: filter.ContainerUpdateOptions{
				AllowResourceUpdates: true,
				RequireMemoryLimit:   true,
			},
		},
	}, ownership.Options{})

	t.Run("legacy unlimited container ratchets on omitted update", func(t *testing.T) {
		containerID := createDockerContainer(t, socketPath, dockerContainerCreateRequest{
			Image: busyboxPinnedRef,
			Cmd:   []string{"sh", "-c", "sleep 1"},
		})

		if got := inspectDockerContainerMemory(t, socketPath, containerID); got != 0 {
			t.Fatalf("real daemon HostConfig.Memory = %d, want 0 for an unset limit", got)
		}
		status, body := serveIntegrationRequest(handler, http.MethodPost, "/containers/"+url.PathEscape(containerID)+"/update", `{}`)
		if status != http.StatusForbidden {
			t.Fatalf("omitted-memory update status = %d, want 403; body: %s", status, body)
		}
		if got := inspectDockerContainerMemory(t, socketPath, containerID); got != 0 {
			t.Fatalf("denied update changed legacy container memory to %d, want 0", got)
		}
	})

	t.Run("positive weaker update is forwarded verbatim and denial leaves state unchanged", func(t *testing.T) {
		const initialMemory = int64(256 << 20)
		const weakerMemory = int64(128 << 20)
		containerID := createDockerContainer(t, socketPath, dockerContainerCreateRequest{
			Image: busyboxPinnedRef,
			Cmd:   []string{"sh", "-c", "sleep 1"},
			HostConfig: dockerContainerHostConfig{
				Memory: initialMemory,
			},
		})

		status, body := serveIntegrationRequest(handler, http.MethodPost, "/containers/"+url.PathEscape(containerID)+"/update", fmt.Sprintf(`{"Memory":%d}`, weakerMemory))
		if status != http.StatusOK {
			t.Fatalf("weaker positive update status = %d, want 200; body: %s", status, body)
		}
		if got := inspectDockerContainerMemory(t, socketPath, containerID); got != weakerMemory {
			t.Fatalf("real daemon HostConfig.Memory = %d, want forwarded weaker value %d", got, weakerMemory)
		}

		status, body = serveIntegrationRequest(handler, http.MethodPost, "/containers/"+url.PathEscape(containerID)+"/update", `{"Memory":-1}`)
		if status != http.StatusForbidden {
			t.Fatalf("negative update status = %d, want 403; body: %s", status, body)
		}
		if got := inspectDockerContainerMemory(t, socketPath, containerID); got != weakerMemory {
			t.Fatalf("denied update changed real daemon state: Memory=%d, want %d", got, weakerMemory)
		}
	})
}

func TestResourceLimitServicesAgainstIsolatedRealSwarm(t *testing.T) {
	if os.Getenv("SOCKGUARD_TEST_ENABLE_SWARM") != "1" {
		t.Skip("set SOCKGUARD_TEST_ENABLE_SWARM=1 to run isolated swarm resource-limit tests")
	}
	socketPath := dockerSocketForIntegration(t)
	if status, body := directDockerRequest(t, socketPath, http.MethodGet, "/swarm", ""); status == http.StatusOK {
		t.Skip("docker daemon already belongs to a swarm; refusing to inspect, leave, or mutate a pre-existing swarm")
	} else if status != http.StatusServiceUnavailable {
		t.Fatalf("preflight GET /swarm status = %d, want 503 for inactive swarm; body: %s", status, body)
	}

	status, body := directDockerRequest(t, socketPath, http.MethodPost, "/swarm/init", `{"ListenAddr":"127.0.0.1:2377","AdvertiseAddr":"127.0.0.1"}`)
	if status != http.StatusOK {
		t.Fatalf("initialize isolated test swarm status = %d, want 200; body: %s", status, body)
	}
	t.Cleanup(func() {
		leaveStatus, leaveBody := directDockerRequest(t, socketPath, http.MethodPost, "/swarm/leave?force=1", "")
		if leaveStatus != http.StatusOK {
			t.Errorf("leave test-created swarm status = %d, want 200; body: %s", leaveStatus, leaveBody)
		}
	})

	rules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/services/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/services/*/update"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "no matching allow rule"},
	}
	handler := newIntegrationProxyHandlerWithOptions(t, socketPath, rules, filter.Options{
		PolicyConfig: filter.PolicyConfig{
			Service: filter.ServiceOptions{
				AllowOfficial:       true,
				RequireCPULimitHard: true,
			},
		},
	}, ownership.Options{})

	t.Run("create and full replacement update", func(t *testing.T) {
		weakCreate := swarmServiceSpec("sockguard-resource-create-denied", 0, "pause")
		status, body := serveIntegrationRequest(handler, http.MethodPost, "/services/create", weakCreate)
		if status != http.StatusForbidden {
			t.Fatalf("weak service create status = %d, want 403; body: %s", status, body)
		}

		serviceID := createDockerService(t, socketPath, "sockguard-resource-update", 1_000_000_000)
		version, currentNano, _ := inspectDockerServiceResourceState(t, socketPath, serviceID)
		if currentNano <= 0 {
			t.Fatalf("created service NanoCPUs = %d, want positive", currentNano)
		}
		status, body = serveIntegrationRequest(handler, http.MethodPost, fmt.Sprintf("/services/%s/update?version=%d", url.PathEscape(serviceID), version), swarmServiceSpec("sockguard-resource-update", 0, "pause"))
		if status != http.StatusForbidden {
			t.Fatalf("omitted/unset full-replacement update status = %d, want 403; body: %s", status, body)
		}
		_, afterNano, _ := inspectDockerServiceResourceState(t, socketPath, serviceID)
		if afterNano != currentNano {
			t.Fatalf("denied service update changed NanoCPUs from %d to %d", currentNano, afterNano)
		}
	})

	t.Run("manual and automatic rollback targets", func(t *testing.T) {
		serviceName := "sockguard-resource-rollback"
		serviceID := createDockerService(t, socketPath, serviceName, 0)
		version, _, _ := inspectDockerServiceResourceState(t, socketPath, serviceID)

		// A pause remediation is allowed without trusting the weak current Spec
		// as a future rollback target; this creates a weak PreviousSpec.
		status, body := serveIntegrationRequest(handler, http.MethodPost, fmt.Sprintf("/services/%s/update?version=%d", url.PathEscape(serviceID), version), swarmServiceSpec(serviceName, 1_000_000_000, "pause"))
		if status != http.StatusOK {
			t.Fatalf("pause remediation status = %d, want 200; body: %s", status, body)
		}
		version, currentNano, previousNano := inspectDockerServiceResourceState(t, socketPath, serviceID)
		if currentNano <= 0 || previousNano > 0 {
			t.Fatalf("post-remediation current/previous NanoCPUs = %d/%d, want positive/weak", currentNano, previousNano)
		}

		status, body = serveIntegrationRequest(handler, http.MethodPost, fmt.Sprintf("/services/%s/update?version=%d&rollback=previous", url.PathEscape(serviceID), version), swarmServiceSpec(serviceName, 1_000_000_000, "pause"))
		if status != http.StatusForbidden {
			t.Fatalf("manual rollback to weak PreviousSpec status = %d, want 403; body: %s", status, body)
		}

		status, body = serveIntegrationRequest(handler, http.MethodPost, fmt.Sprintf("/services/%s/update?version=%d", url.PathEscape(serviceID), version), swarmServiceSpec(serviceName, 500_000_000, "rollback"))
		if status != http.StatusOK {
			t.Fatalf("automatic-rollback-capable update with safe current Spec status = %d, want 200; body: %s", status, body)
		}
		version, _, previousNano = inspectDockerServiceResourceState(t, socketPath, serviceID)
		if previousNano <= 0 {
			t.Fatalf("safe update PreviousSpec NanoCPUs = %d, want positive", previousNano)
		}
		status, body = serveIntegrationRequest(handler, http.MethodPost, fmt.Sprintf("/services/%s/update?version=%d&rollback=previous", url.PathEscape(serviceID), version), `{}`)
		if status != http.StatusOK {
			t.Fatalf("manual rollback to safe daemon PreviousSpec status = %d, want 200; body: %s", status, body)
		}

		weakServiceID := createDockerService(t, socketPath, "sockguard-resource-auto-weak", 0)
		weakVersion, _, _ := inspectDockerServiceResourceState(t, socketPath, weakServiceID)
		status, body = serveIntegrationRequest(handler, http.MethodPost, fmt.Sprintf("/services/%s/update?version=%d", url.PathEscape(weakServiceID), weakVersion), swarmServiceSpec("sockguard-resource-auto-weak", 1_000_000_000, "rollback"))
		if status != http.StatusForbidden {
			t.Fatalf("automatic rollback with weak current Spec status = %d, want 403; body: %s", status, body)
		}
	})
}

func serveIntegrationRequest(handler http.Handler, method, target, body string) (int, string) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func inspectDockerContainerMemory(t *testing.T, socketPath, containerID string) int64 {
	t.Helper()
	status, body := directDockerRequest(t, socketPath, http.MethodGet, "/containers/"+url.PathEscape(containerID)+"/json", "")
	if status != http.StatusOK {
		t.Fatalf("inspect container status = %d, want 200; body: %s", status, body)
	}
	var inspect struct {
		HostConfig struct {
			Memory int64 `json:"Memory"`
		} `json:"HostConfig"`
	}
	if err := json.Unmarshal([]byte(body), &inspect); err != nil {
		t.Fatalf("decode container inspect: %v", err)
	}
	return inspect.HostConfig.Memory
}

func directDockerRequest(t *testing.T, socketPath, method, target, body string) (int, string) {
	t.Helper()
	client, closeIdle := dockerHTTPClient(socketPath)
	defer closeIdle()
	req, err := http.NewRequest(method, "http://docker"+target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new Docker request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Docker request %s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		t.Fatalf("read Docker response: %v", err)
	}
	return resp.StatusCode, string(raw)
}

func swarmServiceSpec(name string, nanoCPUs int64, failureAction string) string {
	resources := map[string]any{}
	if nanoCPUs > 0 {
		resources["Limits"] = map[string]any{"NanoCPUs": nanoCPUs}
	}
	spec := map[string]any{
		"Name": name,
		"TaskTemplate": map[string]any{
			"ContainerSpec": map[string]any{
				"Image":   busyboxPinnedRef,
				"Command": []string{"sh", "-c", "sleep 3600"},
			},
			"Resources": resources,
		},
		"Mode": map[string]any{"Replicated": map[string]any{"Replicas": 0}},
	}
	if failureAction != "" {
		spec["UpdateConfig"] = map[string]any{
			"Parallelism":   1,
			"FailureAction": failureAction,
			"Monitor":       int64(time.Second),
		}
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func createDockerService(t *testing.T, socketPath, name string, nanoCPUs int64) string {
	t.Helper()
	status, body := directDockerRequest(t, socketPath, http.MethodPost, "/services/create", swarmServiceSpec(name, nanoCPUs, "pause"))
	if status != http.StatusCreated {
		t.Fatalf("create service status = %d, want 201; body: %s", status, body)
	}
	var response struct {
		ID string `json:"ID"`
	}
	if err := json.Unmarshal([]byte(body), &response); err != nil || response.ID == "" {
		t.Fatalf("decode service create response: id=%q err=%v body=%s", response.ID, err, body)
	}
	t.Cleanup(func() {
		deleteStatus, deleteBody := directDockerRequest(t, socketPath, http.MethodDelete, "/services/"+url.PathEscape(response.ID), "")
		if deleteStatus != http.StatusOK && deleteStatus != http.StatusNotFound {
			t.Errorf("delete service status = %d, want 200/404; body: %s", deleteStatus, deleteBody)
		}
	})
	return response.ID
}

func inspectDockerServiceResourceState(t *testing.T, socketPath, serviceID string) (version uint64, currentNano, previousNano int64) {
	t.Helper()
	status, body := directDockerRequest(t, socketPath, http.MethodGet, "/services/"+url.PathEscape(serviceID), "")
	if status != http.StatusOK {
		t.Fatalf("inspect service status = %d, want 200; body: %s", status, body)
	}
	var inspect struct {
		Version struct {
			Index uint64 `json:"Index"`
		} `json:"Version"`
		Spec struct {
			TaskTemplate struct {
				Resources struct {
					Limits struct {
						NanoCPUs int64 `json:"NanoCPUs"`
					} `json:"Limits"`
				} `json:"Resources"`
			} `json:"TaskTemplate"`
		} `json:"Spec"`
		PreviousSpec *struct {
			TaskTemplate struct {
				Resources struct {
					Limits struct {
						NanoCPUs int64 `json:"NanoCPUs"`
					} `json:"Limits"`
				} `json:"Resources"`
			} `json:"TaskTemplate"`
		} `json:"PreviousSpec"`
	}
	if err := json.NewDecoder(bytes.NewBufferString(body)).Decode(&inspect); err != nil {
		t.Fatalf("decode service inspect: %v", err)
	}
	if inspect.PreviousSpec != nil {
		previousNano = inspect.PreviousSpec.TaskTemplate.Resources.Limits.NanoCPUs
	}
	return inspect.Version.Index, inspect.Spec.TaskTemplate.Resources.Limits.NanoCPUs, previousNano
}
