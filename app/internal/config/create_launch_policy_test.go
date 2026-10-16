package config

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateLaunchPolicyRoutes(t *testing.T) {
	for _, native := range []bool{false, true} {
		group, route, envField, cmdField, entryField := "container_create", "/v1.56/containers/create", "Env", "Cmd", "Entrypoint"
		if native {
			group, route, envField, cmdField, entryField = "libpod_container_create", "/v5.8.1/libpod/containers/create", "env", "command", "entrypoint"
		}
		for _, tc := range []struct {
			name, policy, fields string
			allow                bool
		}{
			{"default", "{}", `"%s":["sh"]`, true},
			{"command match", `allowed_commands: [["/app/server", "**"]]`, `"%s":["/app/server","/etc/app.conf"]`, true},
			{"command mismatch", `allowed_commands: [["/app/server"]]`, `"%s":["sh"]`, false},
			{"command extra arg", `allowed_commands: [["/app/server"]]`, `"%s":["/app/server","evil"]`, false},
			{"command newline", `allowed_commands: [["/app/server"]]`, `"%s":["/app/server\n"]`, false},
			{"command inherited", `allowed_commands: [["/app/server"]]`, `"unused":null`, false},
			{"command empty", `allowed_commands: [["/app/server"]]`, `"%s":[]`, false},
			{"entrypoint match", `allowed_entrypoints: [["/app/init"]]`, `"%s":["/app/init"]`, true},
			{"entrypoint mismatch", `allowed_entrypoints: [["/app/init"]]`, `"%s":["sh"]`, false},
			{"entrypoint inherited", `allowed_entrypoints: [["/app/init"]]`, `"unused":null`, false},
			{"env allowed", `allowed_env_vars: [MODE]`, `"%s":["MODE=safe"]`, true},
			{"env not allowed", `allowed_env_vars: [MODE]`, `"%s":["SECRET=never-log-me"]`, false},
			{"env denied wins", `allowed_env_vars: [MODE], denied_env_vars: [MODE]`, `"%s":["MODE=safe"]`, false},
			{"env value match", `allowed_env_values: [MODE=safe]`, `"%s":["MODE=safe"]`, true},
			{"env value mismatch", `allowed_env_values: [MODE=safe]`, `"%s":["MODE=never-log-me"]`, false},
			{"env duplicate", `allowed_env_values: [MODE=safe]`, `"%s":["MODE=never-log-me","MODE=safe"]`, false},
		} {
			t.Run(group+"/"+tc.name, func(t *testing.T) {
				field := cmdField
				if strings.HasPrefix(tc.name, "entrypoint") {
					field = entryField
				}
				if strings.HasPrefix(tc.name, "env") {
					field = envField
				}
				fields := strings.ReplaceAll(tc.fields, "%s", field)
				if native && strings.HasPrefix(tc.name, "env") {
					switch tc.name {
					case "env allowed", "env denied wins", "env value match":
						fields = `"env":{"MODE":"safe"},"httpproxy":false`
					case "env not allowed":
						fields = `"env":{"SECRET":"never-log-me"},"httpproxy":false`
					default:
						fields = `"env":{"MODE":"never-log-me"},"httpproxy":false`
					}
				}
				handler := imageAllowlistHandler(t, fmt.Sprintf("request_body:\n  %s: {%s}\n", group, strings.Trim(tc.policy, "{}")))
				body := `{"Image":"docker.io/library/alpine:3.22","systemd":"false",` + fields + `}`
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, route, strings.NewReader(body)))
				want := http.StatusForbidden
				if tc.allow {
					want = http.StatusOK
				}
				if response.Code != want {
					t.Errorf("status %d, want %d: %s", response.Code, want, response.Body.String())
				}
				if !tc.allow && strings.Contains(response.Body.String(), "never-log-me") {
					t.Error("environment value leaked")
				}
			})
		}
	}
}

func TestCreateLaunchPolicyValidation(t *testing.T) {
	for _, group := range []string{"container_create", "libpod_container_create"} {
		for _, entry := range []string{`allowed_commands: [[]]`, `allowed_entrypoints: [[""]]`, `allowed_env_vars: ["MODE=value"]`, `denied_env_vars: ["bad name"]`, `allowed_env_values: ["invalid"]`} {
			cfg, err := LoadBytes([]byte(fmt.Sprintf("request_body:\n  %s: {%s}\n", group, entry)))
			if err != nil {
				t.Fatal(err)
			}
			if err = ValidateStructural(cfg); err == nil || !strings.Contains(err.Error(), group) {
				t.Errorf("%s: got %v", entry, err)
			}
		}
	}
}

func TestCreateLaunchPolicyRejectsMalformedAndIndirectEnvironment(t *testing.T) {
	for _, group := range []string{"container_create", "libpod_container_create"} {
		route, fields := "/containers/create", []string{`"Env":{}`, `"Cmd":42`, `"Entrypoint":[42]`}
		if group == "libpod_container_create" {
			route = "/libpod/containers/create"
			fields = []string{`"env":[]`, `"command":42`, `"entrypoint":[42]`, `"env_host":true`, `"httpproxy":true`, `"secret_env":{"MODE":"secret-name"}`, `"envmerge":["MODE=unsafe"]`}
		}
		handler := imageAllowlistHandler(t, fmt.Sprintf("request_body:\n  %s: {allowed_env_vars: [MODE]}\n", group))
		for _, field := range fields {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, route, strings.NewReader(`{"systemd":"false",`+field+`}`)))
			if response.Code != http.StatusForbidden {
				t.Errorf("%s %s: %d", group, field, response.Code)
			}
		}
	}
}

func TestCreateLaunchPolicyProfileAndEnv(t *testing.T) {
	for _, group := range []string{"container_create", "libpod_container_create"} {
		cfg, err := LoadBytes([]byte(fmt.Sprintf(`clients:
  profiles:
    - name: worker
      rules:
        - match: {method: POST, path: /containers/create}
          action: allow
      request_body:
        %s:
          allowed_commands: [[/app/server]]
          allowed_entrypoints: [[/app/init]]
          allowed_env_vars: [MODE]
          denied_env_vars: [SECRET]
          allowed_env_values: [MODE=safe]
`, group)))
		if err != nil {
			t.Fatal(err)
		}
		if err = ValidateStructural(cfg); err != nil {
			t.Fatal(err)
		}
		body := cfg.Clients.Profiles[0].RequestBody.ToFilterOptions()
		commands, entries, allowed, denied, values := body.ContainerCreate.AllowedCommands, body.ContainerCreate.AllowedEntrypoints, body.ContainerCreate.AllowedEnvVars, body.ContainerCreate.DeniedEnvVars, body.ContainerCreate.AllowedEnvValues
		if group == "libpod_container_create" {
			commands, entries, allowed, denied, values = body.LibpodContainerCreate.AllowedCommands, body.LibpodContainerCreate.AllowedEntrypoints, body.LibpodContainerCreate.AllowedEnvVars, body.LibpodContainerCreate.DeniedEnvVars, body.LibpodContainerCreate.AllowedEnvValues
		}
		if len(commands) != 1 || commands[0][0] != "/app/server" || len(entries) != 1 || entries[0][0] != "/app/init" || len(allowed) != 1 || allowed[0] != "MODE" || len(denied) != 1 || denied[0] != "SECRET" || len(values) != 1 || values[0] != "MODE=safe" {
			t.Errorf("profile lost launch policy: %+v", body)
		}
		t.Setenv("SOCKGUARD_REQUEST_BODY_"+strings.ToUpper(group)+"_ALLOWED_ENV_VALUES", "MODE=safe,MODE=test")
		loaded, err := Load("")
		if err != nil {
			t.Fatal(err)
		}
		got := loaded.RequestBody.ToFilterOptions().ContainerCreate.AllowedEnvValues
		if group == "libpod_container_create" {
			got = loaded.RequestBody.ToFilterOptions().LibpodContainerCreate.AllowedEnvValues
		}
		if len(got) != 2 || got[1] != "MODE=test" {
			t.Errorf("env loading = %v", got)
		}
	}
}

func TestCreateLaunchPolicyLegacyDockerStrings(t *testing.T) {
	for _, field := range []string{"Cmd", "Entrypoint"} {
		key := "allowed_commands"
		if field == "Entrypoint" {
			key = "allowed_entrypoints"
		}
		for _, tc := range []struct {
			name, policy, value string
			allow               bool
		}{
			{"unrestricted", "{}", `"/app/server"`, true},
			{"explicit match", key + `: [["/app/server"]]`, `"/app/server"`, true},
			{"not shell split", key + `: [["/app/server","--help"]]`, `"/app/server --help"`, false},
			{"different", key + `: [["/app/server"]]`, `"sh"`, false},
			{"wrong shape", key + `: [["/app/server"]]`, `{}`, false},
		} {
			t.Run(field+"/"+tc.name, func(t *testing.T) {
				handler := imageAllowlistHandler(t, "request_body:\n  container_create: {"+strings.Trim(tc.policy, "{}")+"}\n")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1.47/containers/create", strings.NewReader(`{"`+field+`":`+tc.value+`}`)))
				want := http.StatusForbidden
				if tc.allow {
					want = http.StatusOK
				}
				if response.Code != want {
					t.Errorf("status %d, want %d: %s", response.Code, want, response.Body.String())
				}
			})
		}
	}
}
