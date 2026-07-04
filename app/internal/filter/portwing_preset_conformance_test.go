package filter_test

import (
	"net/http"
	"testing"
)

// TestPortwingPresetConformance fires portwing's actual internal/docker/client.go
// call surface (ListContainers, InspectContainer, RemoveContainer,
// GetContainerLogs with follow, ContainerStats, GetEvents, GetDockerInfo,
// GetVersion, Ping, CreateExec/StartExec/ResizeExec) at a filter chain built
// from the shipped portwing presets, asserting which requests survive and
// which the default-deny blocks. It guards the integration contract the
// presets exist to satisfy:
//
//   - the base portwing.yaml preset denies exec entirely — every exec sub-path
//     falls to the default-deny catch-all;
//   - portwing-with-exec.yaml's rule layer additionally allows all four exec
//     paths (create, start, resize, inspect);
//   - the bulk-data exfiltration surface (archive, export, attach) and
//     /secrets stay denied on both presets, same as /build.
//
// POST /containers/{id}/exec (exec create): portwing-with-exec.yaml ships with
// request_body.exec.allowed_commands empty and insecure_allow_body_blind_writes:
// true. insecure_allow_body_blind_writes is wired all the way into
// filter.ExecOptions.AllowBlindWrites (see attachRuntimeInspectors in
// internal/cmd/serve.go and buildDrydockPresetHandler below, which mirrors that
// wiring), so an otherwise-clean exec create is allowed even with an empty
// allowlist. The flag only lifts the "no commands are allowlisted" gate —
// allow_privileged/allow_root_user/allowed_env_vars/denied_env_vars still apply
// exactly as configured (see TestPortwingWithExecPresetStillDeniesPrivilegedExec
// below and the unit-level TestExecDenyReasonAllowBlindWritesOnBypassesOnlyTheAllowlistGate
// in exec_test.go). TestMiddlewareDeniesUnallowlistedExecCreateCommand in
// exec_test.go keeps the flag-off default-deny behavior covered independently
// of any preset.
//
// POST /exec/{id}/start needs a docker-backed InspectStart lookup (wired at
// serve time, not by config) to re-inspect the exec's Cmd/Privileged/User; the
// stub upstream in this unit test has none, so start always denies with
// "no exec inspection configured" regardless of preset — and on
// portwing-with-exec.yaml it would deny anyway per the empty-allowlist gap
// above. Excluded from the assertions for the same daemon-round-trip reason
// TestDrydockPresetConformance excludes it.
func TestPortwingPresetConformance(t *testing.T) {
	base := []presetCase{
		// Health + metadata.
		{"ping-get", http.MethodGet, "/_ping", "", true},
		{"ping-head", http.MethodHead, "/_ping", "", true},
		{"version", http.MethodGet, "/version", "", true},
		{"info", http.MethodGet, "/info", "", true},
		{"events", http.MethodGet, "/events", "", true},

		// Container reads Portwing's docker client uses.
		{"containers-list", http.MethodGet, "/containers/json", "", true},
		{"container-inspect", http.MethodGet, "/containers/abc/json", "", true},
		{"container-remove", http.MethodDelete, "/containers/abc", "", true},
		{"container-logs-follow", http.MethodGet, "/containers/abc/logs?follow=1", "", true},
		{"container-stats", http.MethodGet, "/containers/abc/stats?stream=false&one-shot=true", "", true},

		// Default-deny surface: bulk-data exfiltration streams, build, secrets
		// — none are in either preset.
		{"build-denied", http.MethodPost, "/build", "", false},
		{"archive-denied", http.MethodGet, "/containers/abc/archive", "", false},
		{"export-denied", http.MethodGet, "/containers/abc/export", "", false},
		{"attach-denied", http.MethodPost, "/containers/abc/attach", "", false},
		{"secrets-create-denied", http.MethodPost, "/secrets/create", "", false},
	}

	t.Run("portwing.yaml", func(t *testing.T) {
		handler := buildDrydockPresetHandler(t, "portwing.yaml")
		cases := append([]presetCase{}, base...)
		// No exec rules at all in the base preset — every exec sub-path falls
		// to the default-deny catch-all.
		cases = append(cases,
			presetCase{"exec-create-denied", http.MethodPost, "/containers/abc/exec", "", false},
			presetCase{"exec-resize-denied", http.MethodPost, "/exec/abc/resize", "", false},
			presetCase{"exec-inspect-denied", http.MethodGet, "/exec/abc/json", "", false},
		)
		for _, c := range cases {
			fireDrydockCase(t, handler, c)
		}
	})

	t.Run("portwing-with-exec.yaml", func(t *testing.T) {
		handler := buildDrydockPresetHandler(t, "portwing-with-exec.yaml")
		cases := append([]presetCase{}, base...)
		cases = append(cases,
			// insecure_allow_body_blind_writes: true + empty allowed_commands:
			// an otherwise-clean exec is now genuinely allowed — the preset's
			// header claim delivers.
			presetCase{"exec-create-allowed-blind-write-flag", http.MethodPost, "/containers/abc/exec", `{"Cmd":["sh","-c","id"]}`, true},
			// The blind-write flag only lifts the allowlist gate: privileged
			// exec still hits allow_privileged: false and is denied.
			presetCase{"exec-create-privileged-still-denied", http.MethodPost, "/containers/abc/exec", `{"Cmd":["sh"],"Privileged":true}`, false},
			// Resize and inspect carry no exec-specific body inspection
			// (isExecCreatePath/isExecStartPath don't match them), so the
			// rule layer alone governs — both are genuinely allowed here.
			presetCase{"exec-resize-allowed", http.MethodPost, "/exec/abc/resize", "", true},
			presetCase{"exec-inspect-allowed", http.MethodGet, "/exec/abc/json", "", true},
		)
		for _, c := range cases {
			fireDrydockCase(t, handler, c)
		}
	})
}
