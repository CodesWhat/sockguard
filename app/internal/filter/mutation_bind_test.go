package filter

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRemapBindSourcePath(t *testing.T) {
	const from, to = "/builds", "/srv/runner/builds"
	tests := []struct {
		name        string
		source      string
		want        string
		wantMatched bool
		wantErr     bool
	}{
		{name: "exact", source: "/builds", want: to, wantMatched: true},
		{name: "child", source: "/builds/job1/cache", want: to + "/job1/cache", wantMatched: true},
		{name: "trailing slash cleaned", source: "/builds/job1/", want: to + "/job1", wantMatched: true},
		{name: "double slash cleaned", source: "/builds//job1", want: to + "/job1", wantMatched: true},
		{name: "dot segment cleaned", source: "/builds/./job1", want: to + "/job1", wantMatched: true},
		{name: "prefix confusion", source: "/builds2/x", want: "/builds2/x"},
		{name: "prefix confusion suffix", source: "/buildsX", want: "/buildsX"},
		{name: "unrelated", source: "/etc", want: "/etc"},
		{name: "named volume untouched", source: "builds", want: "builds"},
		{name: "relative untouched", source: "builds/x", want: "builds/x"},
		{name: "empty untouched", source: "", want: ""},
		{name: "already host path untouched", source: "/srv/runner/builds/x", want: "/srv/runner/builds/x"},
		{name: "traversal out of tree", source: "/builds/../../etc", wantErr: true},
		{name: "traversal stays inside tree still refused", source: "/builds/a/../b", wantErr: true},
		{name: "traversal into tree refused", source: "/x/../builds/y", wantErr: true},
		{name: "traversal out of from refused", source: "/builds/..", wantErr: true},
		{name: "dotdot elsewhere untouched", source: "/etc/../tmp", want: "/etc/../tmp"},
		{name: "dotdot-like name allowed", source: "/builds/..hidden", want: to + "/..hidden", wantMatched: true},
		{name: "control character refused", source: "/builds/a\x01b", wantErr: true},
		{name: "case differs untouched", source: "/Builds/x", want: "/Builds/x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, matched, err := remapBindSourcePath(tt.source, from, to)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if matched != tt.wantMatched || got != tt.want {
				t.Fatalf("remapBindSourcePath(%q) = (%q, %v), want (%q, %v)", tt.source, got, matched, tt.want, tt.wantMatched)
			}
		})
	}
}

func TestRemapBindSpecPreservesTargetAndOptions(t *testing.T) {
	tests := []struct {
		spec, want string
		matched    bool
	}{
		{"/builds/x:/work", "/srv/runner/builds/x:/work", true},
		{"/builds/x:/work:ro,z", "/srv/runner/builds/x:/work:ro,z", true},
		{"/builds:/builds:rw", "/srv/runner/builds:/builds:rw", true},
		{"/builds2:/work", "/builds2:/work", false},
		{"/data:/builds", "/data:/builds", false},
		{"namedvol:/work", "namedvol:/work", false},
		{"/anonymous-no-colon", "/anonymous-no-colon", false},
		{"/builds", "/builds", false},
	}
	for _, tt := range tests {
		got, matched, err := remapBindSpec(tt.spec, "/builds", "/srv/runner/builds")
		if err != nil || got != tt.want || matched != tt.matched {
			t.Errorf("remapBindSpec(%q) = (%q, %v, %v), want (%q, %v, nil)", tt.spec, got, matched, err, tt.want, tt.matched)
		}
	}
}

func bindRemapOptions(surface string, allowed []string) Options {
	return Options{
		PolicyConfig: PolicyConfig{
			ContainerCreate:       ContainerCreateOptions{AllowedBindMounts: allowed},
			LibpodContainerCreate: LibpodContainerCreateOptions{AllowedBindMounts: allowed},
		},
		Mutation: MutationOptions{Rules: []MutationRuleOptions{{
			ID:              "dood-workspace",
			Mode:            "enforce",
			Surfaces:        []string{surface},
			RemapBindSource: &BindSourceRemapMutationOptions{From: "/builds", To: "/srv/runner/builds"},
		}}},
	}
}

func serveBindRemap(t *testing.T, opts Options, path, body string) (int, map[string]any) {
	t.Helper()
	var forwarded []byte
	handler := mutationMiddleware(t, opts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	var doc map[string]any
	if len(forwarded) > 0 {
		if err := json.Unmarshal(forwarded, &doc); err != nil {
			t.Fatalf("decode forwarded: %v", err)
		}
	}
	return rec.Code, doc
}

func hostConfigOf(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	hc, ok := doc["HostConfig"].(map[string]any)
	if !ok {
		t.Fatalf("forwarded body has no HostConfig: %#v", doc)
	}
	return hc
}

func TestBindRemapContainerCreateRewritesBindsAndMounts(t *testing.T) {
	opts := bindRemapOptions(mutationSurfaceContainerCreate, []string{"/srv/runner/builds"})
	body := `{"Image":"alpine:3.21","HostConfig":{"Binds":["/builds/j1:/work:ro","/srv/runner/builds/j2:/other"],"Mounts":[{"Type":"bind","Source":"/builds/j3","Target":"/m"},{"Type":"volume","Source":"vol","Target":"/v"}]}}`
	status, doc := serveBindRemap(t, opts, "/v1.53/containers/create", body)
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", status)
	}
	hc := hostConfigOf(t, doc)
	binds := hc["Binds"].([]any)
	if binds[0] != "/srv/runner/builds/j1:/work:ro" || binds[1] != "/srv/runner/builds/j2:/other" {
		t.Fatalf("Binds = %#v", binds)
	}
	mounts := hc["Mounts"].([]any)
	if mounts[0].(map[string]any)["Source"] != "/srv/runner/builds/j3" {
		t.Fatalf("bind mount source = %#v", mounts[0])
	}
	if mounts[1].(map[string]any)["Source"] != "vol" {
		t.Fatalf("volume mount source rewritten: %#v", mounts[1])
	}
}

func TestBindRemapResultStillHitsAllowlist(t *testing.T) {
	// Privilege: the rewrite must not exempt the host path from the allowlist.
	opts := bindRemapOptions(mutationSurfaceContainerCreate, []string{"/srv/other"})
	body := `{"Image":"alpine:3.21","HostConfig":{"Binds":["/builds/j1:/work"]}}`
	if status, _ := serveBindRemap(t, opts, "/containers/create", body); status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (rewritten source outside allowlist)", status)
	}

	// The client-visible spelling being allowlisted is not enough either: the
	// policy sees only the rewritten host path.
	opts = bindRemapOptions(mutationSurfaceContainerCreate, []string{"/builds"})
	if status, _ := serveBindRemap(t, opts, "/containers/create", body); status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (allowlisting the client path must not admit the host path)", status)
	}
}

func TestBindRemapTraversalDenied(t *testing.T) {
	opts := bindRemapOptions(mutationSurfaceContainerCreate, []string{"/srv/runner", "/etc"})
	for _, source := range []string{"/builds/../../etc", "/builds/../x", "/x/../builds/y", "/builds/.."} {
		body := `{"Image":"alpine:3.21","HostConfig":{"Binds":["` + source + `:/work"]}}`
		if status, doc := serveBindRemap(t, opts, "/containers/create", body); status != http.StatusBadRequest || doc != nil {
			t.Errorf("Binds %q: status = %d, forwarded = %v, want 400 and nothing forwarded", source, status, doc != nil)
		}
		body = `{"Image":"alpine:3.21","HostConfig":{"Mounts":[{"Type":"bind","Source":"` + source + `","Target":"/work"}]}}`
		if status, doc := serveBindRemap(t, opts, "/containers/create", body); status != http.StatusBadRequest || doc != nil {
			t.Errorf("Mounts %q: status = %d, forwarded = %v, want 400 and nothing forwarded", source, status, doc != nil)
		}
	}
}

func TestBindRemapPrefixConfusionNotRewritten(t *testing.T) {
	opts := bindRemapOptions(mutationSurfaceContainerCreate, []string{"/srv/runner/builds"})
	body := `{"Image":"alpine:3.21","HostConfig":{"Binds":["/builds2/x:/work"]}}`
	// Not rewritten, so /builds2/x is judged as itself and is not allowlisted.
	if status, _ := serveBindRemap(t, opts, "/containers/create", body); status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", status)
	}
}

func TestBindRemapNonStringShapesFailClosed(t *testing.T) {
	opts := bindRemapOptions(mutationSurfaceContainerCreate, []string{"/srv/runner/builds"})
	for _, hostConfig := range []string{
		`{"Binds":"/builds/x:/w"}`,
		`{"Binds":[1]}`,
		`{"Mounts":{"Type":"bind"}}`,
		`{"Mounts":["x"]}`,
		`{"Mounts":[{"Type":"bind","Source":5}]}`,
	} {
		body := `{"Image":"alpine:3.21","HostConfig":` + hostConfig + `}`
		if status, doc := serveBindRemap(t, opts, "/containers/create", body); status != http.StatusBadRequest || doc != nil {
			t.Errorf("HostConfig %s: status = %d, want 400 and nothing forwarded", hostConfig, status)
		}
	}
}

func TestBindRemapAbsentFieldsAreNoop(t *testing.T) {
	opts := bindRemapOptions(mutationSurfaceContainerCreate, nil)
	for _, body := range []string{
		`{"Image":"alpine:3.21"}`,
		`{"Image":"alpine:3.21","HostConfig":{}}`,
		`{"Image":"alpine:3.21","HostConfig":{"Binds":null,"Mounts":null}}`,
	} {
		if status, _ := serveBindRemap(t, opts, "/containers/create", body); status != http.StatusNoContent {
			t.Errorf("body %s: status = %d, want 204", body, status)
		}
	}
}

func TestBindRemapCaseVariantKeysRewrittenInPlace(t *testing.T) {
	opts := bindRemapOptions(mutationSurfaceContainerCreate, []string{"/srv/runner/builds"})
	body := `{"Image":"alpine:3.21","hostconfig":{"binds":["/builds/x:/w"],"mounts":[{"type":"BIND","source":"/builds/y","target":"/m"}]}}`
	status, doc := serveBindRemap(t, opts, "/containers/create", body)
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", status)
	}
	hc := doc["hostconfig"].(map[string]any)
	if hc["binds"].([]any)[0] != "/srv/runner/builds/x:/w" {
		t.Fatalf("binds = %#v", hc["binds"])
	}
	if hc["mounts"].([]any)[0].(map[string]any)["source"] != "/srv/runner/builds/y" {
		t.Fatalf("mounts = %#v", hc["mounts"])
	}
}

func TestBindRemapWarnModeDoesNotRewrite(t *testing.T) {
	opts := bindRemapOptions(mutationSurfaceContainerCreate, []string{"/builds"})
	opts.Mutation.Rules[0].Mode = "audit"
	body := `{"Image":"alpine:3.21","HostConfig":{"Binds":["/builds/x:/w"]}}`
	status, doc := serveBindRemap(t, opts, "/containers/create", body)
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", status)
	}
	if got := hostConfigOf(t, doc)["Binds"].([]any)[0]; got != "/builds/x:/w" {
		t.Fatalf("audit mode rewrote Binds: %v", got)
	}
}

func TestBindRemapOwnershipReferencesUnaffected(t *testing.T) {
	// A named volume (what ownership scopes) is never touched, even when its
	// name looks like the mapped path's last segment.
	opts := bindRemapOptions(mutationSurfaceContainerCreate, []string{"/srv/runner/builds"})
	body := `{"Image":"alpine:3.21","HostConfig":{"Binds":["builds:/work","/builds/x:/w"],"Mounts":[{"Type":"volume","Source":"builds","Target":"/v"}]}}`
	status, doc := serveBindRemap(t, opts, "/containers/create", body)
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", status)
	}
	hc := hostConfigOf(t, doc)
	binds := hc["Binds"].([]any)
	if binds[0] != "builds:/work" || binds[1] != "/srv/runner/builds/x:/w" {
		t.Fatalf("Binds = %#v", binds)
	}
	if hc["Mounts"].([]any)[0].(map[string]any)["Source"] != "builds" {
		t.Fatalf("named volume mount rewritten: %#v", hc["Mounts"])
	}
}

func TestBindRemapLibpodMounts(t *testing.T) {
	opts := bindRemapOptions(mutationSurfaceLibpodContainerCreate, []string{"/srv/runner/builds"})
	body := `{"image":"alpine:3.21","systemd":"false","mounts":[{"type":"bind","source":"/builds/a","destination":"/a"},{"type":"tmpfs","destination":"/t","options":["noexec","nosuid","nodev"]},{"type":"volume","source":"/builds/v","destination":"/v","options":["rbind"]}]}`
	status, doc := serveBindRemap(t, opts, "/v5.0.0/libpod/containers/create", body)
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", status)
	}
	mounts := doc["mounts"].([]any)
	if mounts[0].(map[string]any)["source"] != "/srv/runner/builds/a" {
		t.Fatalf("bind mount = %#v", mounts[0])
	}
	if _, has := mounts[1].(map[string]any)["source"]; has {
		t.Fatalf("tmpfs mount gained a source: %#v", mounts[1])
	}
	if mounts[2].(map[string]any)["source"] != "/srv/runner/builds/v" {
		t.Fatalf("rbind-option mount = %#v", mounts[2])
	}
}

func TestBindRemapLibpodTraversalAndAllowlist(t *testing.T) {
	opts := bindRemapOptions(mutationSurfaceLibpodContainerCreate, []string{"/srv/runner/builds"})
	body := `{"image":"alpine:3.21","systemd":"false","mounts":[{"type":"bind","source":"/builds/../../etc","destination":"/a"}]}`
	if status, doc := serveBindRemap(t, opts, "/libpod/containers/create", body); status != http.StatusBadRequest || doc != nil {
		t.Fatalf("traversal: status = %d, want 400", status)
	}
	opts = bindRemapOptions(mutationSurfaceLibpodContainerCreate, []string{"/srv/other"})
	body = `{"image":"alpine:3.21","systemd":"false","mounts":[{"type":"bind","source":"/builds/a","destination":"/a"}]}`
	if status, _ := serveBindRemap(t, opts, "/libpod/containers/create", body); status != http.StatusForbidden {
		t.Fatalf("allowlist: status = %d, want 403", status)
	}
}

func TestBindRemapSurfaceIsolation(t *testing.T) {
	// A container_create rule never touches libpod bodies and vice versa.
	opts := bindRemapOptions(mutationSurfaceContainerCreate, []string{"/builds"})
	body := `{"image":"alpine:3.21","systemd":"false","mounts":[{"type":"bind","source":"/builds/a","destination":"/a"}]}`
	status, doc := serveBindRemap(t, opts, "/libpod/containers/create", body)
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", status)
	}
	if doc["mounts"].([]any)[0].(map[string]any)["source"] != "/builds/a" {
		t.Fatalf("libpod body rewritten by container_create rule: %#v", doc["mounts"])
	}
}

func TestRemapBindSourceEngineKindString(t *testing.T) {
	if got := mutationRuleRemapBindSource.String(); got != "remap_bind_source" {
		t.Fatalf("String() = %q", got)
	}
}

const libpodOverlayBase = `{"image":"alpine:3.21","systemd":"false",`

func TestBindRemapLibpodOverlayVolumes(t *testing.T) {
	opts := bindRemapOptions(mutationSurfaceLibpodContainerCreate, []string{"/srv/runner/builds"})
	body := libpodOverlayBase + `"overlay_volumes":[{"source":"/builds/lower","destination":"/o","options":["upperdir=/builds/up","workdir=/builds/work","private"]}],"volumes":[{"Name":"v","Dest":"/v","Options":["O","upperdir=/builds/vup","workdir=/builds/vwork"]}]}`
	status, doc := serveBindRemap(t, opts, "/libpod/containers/create", body)
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", status)
	}
	ov := doc["overlay_volumes"].([]any)[0].(map[string]any)
	if ov["source"] != "/srv/runner/builds/lower" {
		t.Fatalf("overlay source = %v", ov["source"])
	}
	want := []any{"upperdir=/srv/runner/builds/up", "workdir=/srv/runner/builds/work", "private"}
	for i, w := range want {
		if ov["options"].([]any)[i] != w {
			t.Fatalf("overlay options = %#v", ov["options"])
		}
	}
	vol := doc["volumes"].([]any)[0].(map[string]any)
	if vol["Options"].([]any)[1] != "upperdir=/srv/runner/builds/vup" || vol["Options"].([]any)[2] != "workdir=/srv/runner/builds/vwork" {
		t.Fatalf("volume options = %#v", vol["Options"])
	}
}

func TestBindRemapLibpodOverlayBypassesDenied(t *testing.T) {
	opts := bindRemapOptions(mutationSurfaceLibpodContainerCreate, []string{"/srv/runner/builds"})
	denied400 := map[string]string{
		"source traversal":      `"overlay_volumes":[{"source":"/builds/../../etc","destination":"/o"}]`,
		"upperdir traversal":    `"overlay_volumes":[{"source":"/builds/l","destination":"/o","options":["upperdir=/builds/../../etc"]}]`,
		"workdir traversal":     `"overlay_volumes":[{"source":"/builds/l","destination":"/o","options":["workdir=/builds/x/../../../etc"]}]`,
		"volume upper traverse": `"volumes":[{"Name":"v","Dest":"/v","Options":["O","upperdir=/builds/../etc"]}]`,
		"control char":          "\"overlay_volumes\":[{\"source\":\"/builds/a\\u0001\",\"destination\":\"/o\"}]",
		"non-string option":     `"overlay_volumes":[{"source":"/builds/l","destination":"/o","options":[1]}]`,
		"non-string source":     `"overlay_volumes":[{"source":1,"destination":"/o"}]`,
	}
	for name, frag := range denied400 {
		if status, doc := serveBindRemap(t, opts, "/libpod/containers/create", libpodOverlayBase+frag+"}"); status != http.StatusBadRequest || doc != nil {
			t.Errorf("%s: status = %d, want 400", name, status)
		}
	}
	// Not rewritten, so the allowlist (which holds only the host path) refuses
	// them as written.
	denied403 := map[string]string{
		"prefix confusion source":  `"overlay_volumes":[{"source":"/builds2/x","destination":"/o"}]`,
		"prefix confusion upper":   `"overlay_volumes":[{"source":"/builds/l","destination":"/o","options":["upperdir=/builds2/up"]}]`,
		"unmapped upper":           `"overlay_volumes":[{"source":"/builds/l","destination":"/o","options":["upperdir=/etc"]}]`,
		"unmapped work":            `"overlay_volumes":[{"source":"/builds/l","destination":"/o","options":["workdir=/var/lib"]}]`,
		"prefix-named option":      `"overlay_volumes":[{"source":"/builds/l","destination":"/o","options":["upperdirX=/etc"]}]`,
		"unmapped source":          `"overlay_volumes":[{"source":"/","destination":"/o"}]`,
		"relative upper":           `"overlay_volumes":[{"source":"/builds/l","destination":"/o","options":["upperdir=up"]}]`,
		"volume unmapped upper":    `"volumes":[{"Name":"v","Dest":"/v","Options":["O","upperdir=/etc"]}]`,
		"comma smuggled in upper":  `"overlay_volumes":[{"source":"/builds/l","destination":"/o","options":["upperdir=/builds/a,lowerdir=/etc"]}]`,
		"backslash in source":      `"overlay_volumes":[{"source":"/builds/a\\b","destination":"/o"}]`,
		"rewritten but not listed": `"overlay_volumes":[{"source":"/builds/l","destination":"/o"}]`,
	}
	for name, frag := range denied403 {
		o := opts
		if name == "rewritten but not listed" {
			o = bindRemapOptions(mutationSurfaceLibpodContainerCreate, []string{"/srv/other"})
		}
		if status, _ := serveBindRemap(t, o, "/libpod/containers/create", libpodOverlayBase+frag+"}"); status != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", name, status)
		}
	}
}

func TestBindRemapLibpodOverlayLeavesRootfsAndDriverOptions(t *testing.T) {
	opts := bindRemapOptions(mutationSurfaceLibpodContainerCreate, []string{"/builds", "/srv/runner/builds"})
	body := libpodOverlayBase + `"rootfs":"/builds/root","volumes":[{"Name":"v","Dest":"/v","Options":["volume-opt=device=/builds/d"]}]}`
	status, doc := serveBindRemap(t, opts, "/libpod/containers/create", body)
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", status)
	}
	if doc["rootfs"] != "/builds/root" {
		t.Fatalf("rootfs rewritten: %v", doc["rootfs"])
	}
	if got := doc["volumes"].([]any)[0].(map[string]any)["Options"].([]any)[0]; got != "volume-opt=device=/builds/d" {
		t.Fatalf("driver option rewritten: %v", got)
	}
}

func TestBindRemapContainerCreateSurfaceIgnoresOverlayVolumes(t *testing.T) {
	opts := bindRemapOptions(mutationSurfaceContainerCreate, []string{"/builds"})
	body := libpodOverlayBase + `"overlay_volumes":[{"source":"/builds/l","destination":"/o"}]}`
	status, doc := serveBindRemap(t, opts, "/libpod/containers/create", body)
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", status)
	}
	if doc["overlay_volumes"].([]any)[0].(map[string]any)["source"] != "/builds/l" {
		t.Fatalf("overlay source rewritten by container_create rule: %#v", doc["overlay_volumes"])
	}
}
