package filter_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/filter"
)

// dozzleShellCmd is the argv Dozzle v11.5.0 sends for every shell session
// (internal/web/terminal.go, handler.exec). It must match the allowed_commands
// entry in dozzle-with-shell.yaml exactly.
var dozzleShellCmd = []string{"sh", "-c", "command -v bash >/dev/null 2>&1 && exec bash || exec sh"}

// dozzleExecCreateBody builds the exec create body the Docker SDK sends for
// Client.ContainerExec in internal/container/docker/client.go: AttachStdin,
// AttachStdout, AttachStderr, Tty and the Cmd, with no User, Privileged,
// Env or WorkingDir.
func dozzleExecCreateBody(t *testing.T, fields map[string]any) string {
	t.Helper()
	body := map[string]any{
		"AttachStdin":  true,
		"AttachStdout": true,
		"AttachStderr": true,
		"Tty":          true,
		"Cmd":          dozzleShellCmd,
	}
	for k, v := range fields {
		body[k] = v
	}
	out, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal exec body: %v", err)
	}
	return string(out)
}

// TestDozzleShellPresetConformance pins what dozzle-with-shell.yaml adds for
// DOZZLE_ENABLE_SHELL in Dozzle v11.5.0. The Shell tab opens a websocket at
// GET /api/hosts/{host}/containers/{id}/exec, and Client.ContainerExec makes
// these Engine API calls:
//
//	ExecCreate  POST /containers/{id}/exec   Cmd above, AttachStdin/Stdout/Stderr, Tty
//	ExecAttach  POST /exec/{id}/start        Tty, hijacked
//	ExecResize  POST /exec/{id}/resize?h=40&w=100 (then on each window resize)
//
// Dozzle never calls exec inspect. The Attach tab (ContainerAttach,
// POST /containers/{id}/attach) is also behind the flag; the exec allowlist
// does not cover it, so the preset leaves it denied.
func TestDozzleShellPresetConformance(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "dozzle-with-shell.yaml"))
	if err != nil {
		t.Fatalf("load preset: %v", err)
	}
	if cfg.InsecureAllowBodyBlindWrites {
		t.Fatal("dozzle-with-shell.yaml must pin exec with allowed_commands, not acknowledge body-blind writes")
	}

	handler := drydockPresetHandlerFromConfig(t, cfg)
	cases := []presetCase{
		// Base preset reads still work.
		{"ping", http.MethodGet, "/_ping", "", true},
		{"info", http.MethodGet, "/info", "", true},
		{"events", http.MethodGet, "/events", "", true},
		{"containers-list", http.MethodGet, "/containers/json?all=1", "", true},
		{"container-inspect", http.MethodGet, "/containers/abc/json", "", true},
		{"container-stats", http.MethodGet, "/containers/abc/stats?stream=1", "", true},
		{"container-logs", http.MethodGet, "/containers/abc/logs?follow=1&stdout=1&stderr=1", "", true},

		// Dozzle's real shell calls.
		{"exec-create", http.MethodPost, "/containers/abc/exec", dozzleExecCreateBody(t, nil), true},
		{"v-prefixed-exec-create", http.MethodPost, "/v1.45/containers/abc/exec", dozzleExecCreateBody(t, nil), true},
		{"exec-resize", http.MethodPost, "/exec/abc/resize?h=40&w=100", "", true},
		{"v-prefixed-exec-resize", http.MethodPost, "/v1.45/exec/abc/resize?h=40&w=100", "", true},

		// Any other command is refused.
		{"exec-cat-shadow-denied", http.MethodPost, "/containers/abc/exec", dozzleExecCreateBody(t, map[string]any{"Cmd": []string{"cat", "/etc/shadow"}}), false},
		{"exec-plain-sh-denied", http.MethodPost, "/containers/abc/exec", dozzleExecCreateBody(t, map[string]any{"Cmd": []string{"sh"}}), false},
		{"exec-sh-c-other-denied", http.MethodPost, "/containers/abc/exec", dozzleExecCreateBody(t, map[string]any{"Cmd": []string{"sh", "-c", "id"}}), false},
		{"exec-extra-arg-denied", http.MethodPost, "/containers/abc/exec", dozzleExecCreateBody(t, map[string]any{"Cmd": append(append([]string{}, dozzleShellCmd...), "x")}), false},
		{"exec-string-cmd-denied", http.MethodPost, "/containers/abc/exec", dozzleExecCreateBody(t, map[string]any{"Cmd": "sh"}), false},
		{"exec-no-cmd-denied", http.MethodPost, "/containers/abc/exec", `{"AttachStdin":true,"Tty":true}`, false},
		{"exec-privileged-denied", http.MethodPost, "/containers/abc/exec", dozzleExecCreateBody(t, map[string]any{"Privileged": true}), false},

		// Methods and routes outside the shell.
		{"exec-inspect-denied", http.MethodGet, "/exec/abc/json", "", false},
		{"exec-create-get-denied", http.MethodGet, "/containers/abc/exec", "", false},
		{"container-attach-denied", http.MethodPost, "/containers/abc/attach?stream=1&stdin=1&stdout=1&stderr=1", "", false},
		{"container-attach-ws-denied", http.MethodGet, "/containers/abc/attach/ws", "", false},

		// Container writes stay denied: actions are a separate variant.
		{"container-start-denied", http.MethodPost, "/containers/abc/start", "", false},
		{"container-stop-denied", http.MethodPost, "/containers/abc/stop", "", false},
		{"container-restart-denied", http.MethodPost, "/containers/abc/restart", "", false},
		{"container-kill-denied", http.MethodPost, "/containers/abc/kill", "", false},
		{"container-remove-denied", http.MethodDelete, "/containers/abc", "", false},
		{"container-create-denied", http.MethodPost, "/containers/create", `{"Image":"alpine"}`, false},
		{"container-archive-denied", http.MethodGet, "/containers/abc/archive?path=/etc", "", false},
		{"image-pull-denied", http.MethodPost, "/images/create?fromImage=nginx", "", false},
	}
	for _, c := range cases {
		fireDrydockCase(t, handler, c)
	}
}

// TestDozzleShellPresetRootUserPolicy checks the user policy on exec create.
// Dozzle's own Shell tab runs as the container's default user, but it sends an
// empty User, which sockguard reads as root, so allow_root_user has to be true
// and sockguard cannot pin the User. The preset therefore admits any exec User
// (root included) with the pinned argv: treat the grant as a root-capable
// shell. The argv pin is the only gate, and it holds for every User.
func TestDozzleShellPresetRootUserPolicy(t *testing.T) {
	handler := buildDrydockPresetHandler(t, "dozzle-with-shell.yaml")
	for _, user := range []string{"root", "0", "0:0", "app", "1000"} {
		// The pinned argv is the gate. A different User does not widen it, and
		// the preset permits root only because Dozzle never sets a User.
		fireDrydockCase(t, handler, presetCase{
			"exec-create-user-" + user, http.MethodPost, "/containers/abc/exec",
			dozzleExecCreateBody(t, map[string]any{"User": user}), true,
		})
		fireDrydockCase(t, handler, presetCase{
			"exec-create-user-" + user + "-other-cmd-denied", http.MethodPost, "/containers/abc/exec",
			dozzleExecCreateBody(t, map[string]any{"User": user, "Cmd": []string{"cat", "/etc/shadow"}}), false,
		})
	}
}

// TestDozzleShellPresetExecStartRecheck drives POST /exec/{id}/start the way
// serve.go wires it: the start is re-checked against the stored exec metadata.
// Dozzle's own command passes, and a stored exec with a different command or
// the privileged flag is refused, even if the create happened on another path.
func TestDozzleShellPresetExecStartRecheck(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "dozzle-with-shell.yaml"))
	if err != nil {
		t.Fatalf("load preset: %v", err)
	}

	stored := map[string]filter.ExecInspectResult{
		"dozzle":   {ContainerID: "abc", Command: dozzleShellCmd},
		"other":    {ContainerID: "abc", Command: []string{"cat", "/etc/shadow"}},
		"priv":     {ContainerID: "abc", Command: dozzleShellCmd, Privileged: true},
		"othercmd": {ContainerID: "abc", Command: []string{"sh", "-c", "id"}},
	}
	handler := drydockPresetHandlerFromConfig(t, cfg, func(p *filter.PolicyConfig) {
		p.Exec.InspectStart = func(_ context.Context, id string) (filter.ExecInspectResult, bool, error) {
			r, ok := stored[id]
			return r, ok, nil
		}
	})

	cases := []struct {
		name string
		id   string
		want int
	}{
		{"dozzle-command-allowed", "dozzle", http.StatusOK},
		{"other-command-denied", "other", http.StatusForbidden},
		{"other-shell-command-denied", "othercmd", http.StatusForbidden},
		{"privileged-denied", "priv", http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/exec/"+c.id+"/start", strings.NewReader(`{"Detach":false,"Tty":true}`))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != c.want {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, c.want, strings.TrimSpace(rec.Body.String()))
			}
		})
	}
}

// TestDozzleShellPresetProtectedTargetDenied checks that exec create into a
// container labeled com.sockguard.exec=deny is refused even with the pinned
// argv, and that an unprotected target still passes.
func TestDozzleShellPresetProtectedTargetDenied(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "dozzle-with-shell.yaml"))
	if err != nil {
		t.Fatalf("load preset: %v", err)
	}
	const goodID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	handler := drydockPresetHandlerFromConfig(t, cfg, func(p *filter.PolicyConfig) {
		p.Exec.InspectTarget = func(_ context.Context, id string) (filter.ExecTargetInspectResult, bool, error) {
			return filter.ExecTargetInspectResult{ContainerID: goodID, Protected: id == "proxy"}, true, nil
		}
	})
	body := dozzleExecCreateBody(t, nil)
	fireDrydockCase(t, handler, presetCase{"exec-create-protected-denied", http.MethodPost, "/containers/proxy/exec", body, false})
	fireDrydockCase(t, handler, presetCase{"exec-create-unprotected-allowed", http.MethodPost, "/containers/web/exec", body, true})
}
