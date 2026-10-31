package filter

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/logging"
)

func TestCreateLaunchPolicyMiddleware(t *testing.T) {
	commands := [][]string{{"/app/server"}, {"/app/server", "--config", "/etc/**"}}
	entrypoints := [][]string{{"/app/init"}}
	policy := PolicyConfig{
		ContainerCreate:       ContainerCreateOptions{AllowedCommands: commands, AllowedEntrypoints: entrypoints, AllowedEnvVars: []string{"MODE", "SECRET"}, DeniedEnvVars: []string{"SECRET"}, AllowedEnvValues: []string{"MODE=safe"}},
		LibpodContainerCreate: LibpodContainerCreateOptions{AllowedCommands: commands, AllowedEntrypoints: entrypoints, AllowedEnvVars: []string{"MODE", "SECRET"}, DeniedEnvVars: []string{"SECRET"}, AllowedEnvValues: []string{"MODE=safe"}},
	}
	for _, native := range []bool{false, true} {
		path, cmdField, entryField, envField := "/v1.47/containers/create", "Cmd", "Entrypoint", "Env"
		if native {
			path, cmdField, entryField, envField = "/v5.8.1/libpod/containers/create", "command", "entrypoint", "env"
		}
		for _, tc := range []struct {
			name, field    string
			compat, libpod any
			denied         bool
		}{
			{"allowed command", cmdField, []string{"/app/server"}, []string{"/app/server"}, false},
			{"glob argument", cmdField, []string{"/app/server", "--config", "/etc/app/config.yaml"}, []string{"/app/server", "--config", "/etc/app/config.yaml"}, false},
			{"wrong command", cmdField, []string{"sh"}, []string{"sh"}, true},
			{"extra argument", cmdField, []string{"/app/server", "evil"}, []string{"/app/server", "evil"}, true},
			{"inherited command", cmdField, nil, nil, true},
			{"empty command", cmdField, []string{}, []string{}, true},
			{"wrong entrypoint", entryField, []string{"sh"}, []string{"sh"}, true},
			{"null entrypoint element", entryField, []any{nil}, []any{nil}, true},
			{"unknown environment", envField, []string{"OTHER=safe"}, map[string]string{"OTHER": "safe"}, true},
			{"denied environment wins", envField, []string{"SECRET=safe"}, map[string]string{"SECRET": "safe"}, true},
			{"environment value", envField, []string{"MODE=unsafe"}, map[string]string{"MODE": "unsafe"}, true},
			{"environment duplicates", envField, []string{"MODE=unsafe", "MODE=safe"}, map[string]string{"MODE": "unsafe"}, true},
			{"null environment element", envField, []any{nil}, []any{nil}, true},
		} {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				body := map[string]any{cmdField: []string{"/app/server"}, entryField: []string{"/app/init"}, envField: []string{"MODE=safe"}, "systemd": "false"}
				value := tc.compat
				if native {
					body[envField] = map[string]string{"MODE": "safe"}
					value = tc.libpod
				}
				body[tc.field] = value
				encoded, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				assertFilterCreateRoundTrip(t, path, string(encoded), policy, tc.denied)
			})
		}
	}
	for _, field := range []string{"Cmd", "Entrypoint"} {
		body := `{"Cmd":["/app/server"],"Entrypoint":["/app/init"],"Env":["MODE=safe"]}`
		allowed := "/app/server"
		if field == "Entrypoint" {
			allowed = "/app/init"
		}
		var request map[string]any
		if err := json.Unmarshal([]byte(body), &request); err != nil {
			t.Fatal(err)
		}
		request[field] = allowed
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		assertFilterCreateRoundTrip(t, "/containers/create", string(encoded), policy, false)
		request[field] = map[string]string{}
		encoded, err = json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		assertFilterCreateRoundTrip(t, "/containers/create", string(encoded), policy, true)
	}
	for _, addition := range []string{`"env_host":true`, `"httpproxy":true`, `"secret_env":{"MODE":"secret-name"}`, `"secret_env":[]`, `"envmerge":["MODE=unsafe"]`} {
		body := `{"systemd":"false","command":["/app/server"],"entrypoint":["/app/init"],"env":{"MODE":"safe"},` + addition + `}`
		assertFilterCreateRoundTrip(t, "/libpod/containers/create", body, policy, true)
	}
	for _, native := range []bool{false, true} {
		for _, empty := range []bool{false, true} {
			path := "/containers/create"
			if native {
				path = "/libpod/containers/create"
			}
			request := httptest.NewRequest(http.MethodPost, path, nil)
			if empty {
				request.Body = io.NopCloser(strings.NewReader(""))
			} else {
				request.Body = nil
			}
			var reason string
			var err error
			if native {
				reason, err = newLibpodContainerCreatePolicy(policy.LibpodContainerCreate).inspect(testLogger(), request, path)
			} else {
				reason, err = newContainerCreatePolicy(policy.ContainerCreate).inspect(testLogger(), request, path)
			}
			if err != nil || !strings.Contains(reason, "command") {
				t.Fatalf("empty create bypass: %q, %v", reason, err)
			}
		}
	}
}

func TestCreateLaunchPolicyProfilesAndRollout(t *testing.T) {
	rule, err := CompileRule(Rule{Methods: []string{"POST"}, Pattern: "/**", Action: ActionAllow})
	if err != nil {
		t.Fatal(err)
	}
	policy := PolicyConfig{ContainerCreate: ContainerCreateOptions{AllowedCommands: [][]string{{"/app/server"}}}, LibpodContainerCreate: LibpodContainerCreateOptions{AllowedCommands: [][]string{{"/app/server"}}}}
	for _, surface := range []struct{ path, body string }{{"/containers/create", `{"Cmd":["sh"]}`}, {"/libpod/containers/create", `{"command":["sh"],"systemd":"false"}`}} {
		for _, mode := range []string{"enforce", "warn", "audit"} {
			for _, profile := range []string{"restricted", ""} {
				handler := MiddlewareWithOptions([]*CompiledRule{rule}, testLogger(), Options{Profiles: map[string]Policy{"restricted": {Rules: []*CompiledRule{rule}, PolicyConfig: policy}}, ResolveProfile: func(r *http.Request) (string, bool) { return profile, profile != "" }})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, readErr := io.ReadAll(r.Body)
					if readErr != nil {
						t.Error(readErr)
					}
					_, _ = w.Write(body)
				}))
				request := httptest.NewRequest(http.MethodPost, surface.path, strings.NewReader(surface.body))
				meta := &logging.RequestMeta{RolloutMode: mode}
				request = request.WithContext(logging.WithMeta(request.Context(), meta))
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if profile == "restricted" && mode == "enforce" {
					if response.Code != http.StatusForbidden {
						t.Errorf("profile bypass: %d", response.Code)
					}
					continue
				}
				if response.Code != http.StatusOK || response.Body.String() != surface.body {
					t.Errorf("%s %s profile=%q: pass-through changed: %d %s", surface.path, mode, profile, response.Code, response.Body.String())
				}
				if profile != "" && meta.Decision != logging.DecisionWouldDeny {
					t.Errorf("missing rollout verdict: %+v", meta)
				}
			}
		}
	}
}
