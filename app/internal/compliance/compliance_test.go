package compliance

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

const cisPresetPath = "../../configs/cis-docker-benchmark.yaml"

func loadPreset(t *testing.T) (*config.Config, []byte) {
	t.Helper()
	cfg, data, err := config.LoadWithData(cisPresetPath)
	if err != nil {
		t.Fatalf("LoadWithData(%s): %v", cisPresetPath, err)
	}
	if len(data) == 0 {
		t.Fatalf("preset %s is empty", cisPresetPath)
	}
	return cfg, data
}

func statuses(r Report) map[string]Status {
	m := make(map[string]Status, len(r.Controls))
	for _, c := range r.Controls {
		m[c.ID] = c.Status
	}
	return m
}

func control(t *testing.T, r Report, id string) ControlResult {
	t.Helper()
	for _, c := range r.Controls {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("control %s not in report", id)
	return ControlResult{}
}

func TestCISPresetEnforcedControlsAreSatisfied(t *testing.T) {
	cfg, data := loadPreset(t)
	r := Generate(cfg, data)
	for _, c := range r.Controls {
		if c.Category != CategoryEnforced {
			continue
		}
		// 5.31 depends on how workloads are deployed, which no config can show.
		if c.ID == "5.31" {
			continue
		}
		if c.Status != StatusConfigured && c.Status != StatusAlwaysOn {
			t.Errorf("preset control %s status = %s, want configured or always_on", c.ID, c.Status)
		}
	}
	got := statuses(r)
	for id, want := range map[string]Status{
		"5.20": StatusAlwaysOn, "5.24": StatusAlwaysOn, "5.31": StatusNeedsEvidence,
		"7.x": StatusConfigured, "5.22/5.23": StatusConfigured,
		// The preset ships image_trust off and a default TCP listener with no mTLS.
		"4.5": StatusNotConfigured, "2.6": StatusNotConfigured,
		"1.x": StatusOutsideScope, "6.x": StatusOutsideScope,
	} {
		if got[id] != want {
			t.Errorf("preset %s = %s, want %s", id, got[id], want)
		}
	}
}

func TestDefaultsStatuses(t *testing.T) {
	cfg := config.Defaults()
	got := statuses(Generate(&cfg, nil))
	want := map[string]Status{
		"5.3": StatusNotConfigured, "5.4": StatusConfigured, "5.5": StatusConfigured,
		"5.9": StatusConfigured, "5.10": StatusNotConfigured, "5.11": StatusNotConfigured,
		"5.12": StatusNotConfigured, "5.15": StatusConfigured, "5.16": StatusConfigured,
		"5.17": StatusConfigured, "5.20": StatusAlwaysOn, "5.21": StatusNotConfigured,
		"5.22": StatusConfigured, "5.23": StatusConfigured, "5.24": StatusAlwaysOn,
		"5.25": StatusNotConfigured, "5.28": StatusNotConfigured, "5.30": StatusConfigured,
		"5.31": StatusNeedsEvidence,
		"2.6":  StatusNotConfigured, "4.5": StatusNotConfigured, "5.22/5.23": StatusConfigured,
		"7.x": StatusConfigured,
		"1.x": StatusOutsideScope, "2.x": StatusOutsideScope, "3.x": StatusOutsideScope,
		"4.x": StatusOutsideScope, "5.x": StatusOutsideScope, "6.x": StatusOutsideScope,
	}
	if len(got) != len(want) {
		t.Errorf("got %d controls, want %d", len(got), len(want))
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("Defaults() %s = %s, want %s", id, got[id], w)
		}
	}
}

func TestScopeSemantics(t *testing.T) {
	relaxedPriv := func(c *config.Config) {
		body := c.RequestBody
		body.ContainerCreate.AllowPrivileged = true
		c.Clients.Profiles = append(c.Clients.Profiles, config.ClientProfileConfig{Name: "p", RequestBody: body})
	}
	tests := []struct {
		name   string
		mutate func(*config.Config)
		want   map[string]Status
	}{
		{"profile relaxes allow_privileged", relaxedPriv, map[string]Status{"5.4": StatusPartial, "5.3": StatusConfigured}},
		{"profile with no request_body runs zero-valued policy", func(c *config.Config) {
			c.Clients.Profiles = append(c.Clients.Profiles, config.ClientProfileConfig{Name: "p"})
		}, map[string]Status{"5.4": StatusConfigured, "5.10": StatusPartial, "5.3": StatusPartial}},
		{"warn-mode profile does not enforce", func(c *config.Config) {
			c.Clients.Profiles = append(c.Clients.Profiles, config.ClientProfileConfig{Name: "p", Mode: "warn", RequestBody: c.RequestBody})
		}, map[string]Status{"5.4": StatusPartial, "5.10": StatusPartial}},
		{"global relaxed and profile strict is partial", func(c *config.Config) {
			strict := c.RequestBody
			c.RequestBody.ContainerCreate.AllowPrivileged = true
			c.Clients.Profiles = append(c.Clients.Profiles, config.ClientProfileConfig{Name: "p", RequestBody: strict})
		}, map[string]Status{"5.4": StatusPartial}},
		{"every scope relaxed is not_configured", func(c *config.Config) {
			relaxedPriv(c)
			c.RequestBody.ContainerCreate.AllowPrivileged = true
		}, map[string]Status{"5.4": StatusNotConfigured}},
		{"blind writes leave the mapped knobs alone", func(c *config.Config) {
			c.InsecureAllowBodyBlindWrites = true
		}, map[string]Status{
			"5.3": StatusConfigured, "5.4": StatusConfigured, "5.5": StatusConfigured,
			"5.10": StatusConfigured, "5.21": StatusConfigured, "5.25": StatusConfigured,
			"5.22": StatusConfigured, "5.23": StatusConfigured, "5.22/5.23": StatusConfigured,
			"5.20": StatusAlwaysOn, "5.24": StatusAlwaysOn, "5.31": StatusNeedsEvidence,
			"7.x": StatusConfigured,
		}},
		{"blind writes do not excuse a relaxed privileged exec", func(c *config.Config) {
			c.InsecureAllowBodyBlindWrites = true
			c.RequestBody.Exec.AllowPrivileged = true
		}, map[string]Status{"5.22": StatusNotConfigured, "5.23": StatusConfigured, "5.22/5.23": StatusNotConfigured}},
		{"cpu hard limit satisfies 5.11", func(c *config.Config) {
			c.RequestBody.ContainerCreate.RequireCPULimit = false
			c.RequestBody.ContainerCreate.RequireCPULimitHard = true
		}, map[string]Status{"5.11": StatusConfigured}},
		{"image trust enforce", func(c *config.Config) {
			c.RequestBody.ContainerCreate.ImageTrust.Mode = "enforce"
		}, map[string]Status{"4.5": StatusConfigured}},
		{"libpod privileged create breaks 5.4", func(c *config.Config) {
			c.RequestBody.LibpodContainerCreate.AllowPrivileged = true
		}, map[string]Status{"5.4": StatusNotConfigured}},
		{"libpod trust alone does not satisfy 4.5", func(c *config.Config) {
			c.RequestBody.LibpodContainerCreate.ImageTrust.Mode = "enforce"
		}, map[string]Status{"4.5": StatusNotConfigured}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, data := loadPreset(t)
			tt.mutate(cfg)
			got := statuses(Generate(cfg, data))
			for id, want := range tt.want {
				if got[id] != want {
					t.Errorf("%s = %s, want %s", id, got[id], want)
				}
			}
		})
	}
}

func TestBlindWritesAnnotatesOnlyExecControls(t *testing.T) {
	cfg, data := loadPreset(t)
	cfg.InsecureAllowBodyBlindWrites = true
	r := Generate(cfg, data)
	flagEvidence := func(c ControlResult) bool {
		for _, e := range c.Evidence {
			if e.Path == "insecure_allow_body_blind_writes" && e.Observed == "true" {
				return true
			}
		}
		return false
	}
	affected := map[string]bool{"5.22": true, "5.23": true, "5.22/5.23": true}
	for _, c := range r.Controls {
		if got := flagEvidence(c); got != affected[c.ID] {
			t.Errorf("%s: blind-write flag evidence = %v, want %v", c.ID, got, affected[c.ID])
		}
		if affected[c.ID] && !strings.Contains(strings.Join(c.Notes, " "), "insecure_allow_body_blind_writes") {
			t.Errorf("%s: notes = %v, want the flag named", c.ID, c.Notes)
		}
	}
	if len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "insecure_allow_body_blind_writes") {
		t.Fatalf("report notes = %v, want one note naming the flag", r.Notes)
	}
}

func TestPolicyBundleNote(t *testing.T) {
	cfg, data := loadPreset(t)
	if r := Generate(cfg, data); len(r.Notes) != 0 {
		t.Fatalf("notes without a policy bundle = %v", r.Notes)
	}
	cfg.PolicyBundle.Enabled = true
	r := Generate(cfg, data)
	if len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "signed-policy startup requirements") {
		t.Fatalf("notes = %v", r.Notes)
	}
	for name, s := range renderAll(t, r) {
		if !strings.Contains(s, "signed-policy startup requirements") {
			t.Errorf("%s output is missing the policy bundle note", name)
		}
	}
}

func TestStructuralControlsFollowRolloutMode(t *testing.T) {
	tests := []struct {
		name     string
		profiles []config.ClientProfileConfig
		want     Status
	}{
		{"no profiles", nil, StatusAlwaysOn},
		{"enforce profile", []config.ClientProfileConfig{{Name: "p", Mode: "enforce"}}, StatusAlwaysOn},
		{"default mode profile", []config.ClientProfileConfig{{Name: "p"}}, StatusAlwaysOn},
		{"warn profile", []config.ClientProfileConfig{{Name: "p", Mode: "warn"}}, StatusPartial},
		{"audit profile", []config.ClientProfileConfig{{Name: "p", Mode: "audit"}}, StatusPartial},
		{"enforce and audit profiles", []config.ClientProfileConfig{{Name: "a"}, {Name: "b", Mode: "audit"}}, StatusPartial},
	}
	for _, id := range []string{"5.20", "5.24"} {
		for _, tt := range tests {
			t.Run(id+" "+tt.name, func(t *testing.T) {
				cfg, data := loadPreset(t)
				cfg.Clients.Profiles = tt.profiles
				c := control(t, Generate(cfg, data), id)
				if c.Status != tt.want {
					t.Fatalf("status = %s, want %s", c.Status, tt.want)
				}
				if tt.want == StatusPartial {
					joined := strings.Join(c.Notes, " ")
					if !strings.Contains(joined, "forwards the request") {
						t.Errorf("notes = %v, want the forwarding note", c.Notes)
					}
					if len(c.Evidence) != 1 || c.Evidence[0].Path != "clients.profiles[0].mode" && c.Evidence[0].Path != "clients.profiles[1].mode" {
						t.Errorf("evidence = %+v, want the profile mode", c.Evidence)
					}
				}
			})
		}
	}
}

func TestDockerSocketNeedsEvidence(t *testing.T) {
	tests := []struct {
		name  string
		binds []string
		want  string
	}{
		{"none", nil, "false"},
		{"unrelated path", []string{"/srv/data"}, "false"},
		{"docker socket", []string{"/var/run/docker.sock"}, "true"},
		{"run docker socket", []string{"/run/docker.sock"}, "true"},
		{"podman socket", []string{"/run/podman/podman.sock"}, "true"},
		{"parent directory", []string{"/var/run"}, "true"},
		{"parent directory trailing slash", []string{"/run/"}, "true"},
		{"root", []string{"/"}, "true"},
		{"other sock path", []string{"/opt/custom/engine.sock"}, "true"},
		{"sibling prefix is not a parent", []string{"/var/runner"}, "false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, data := loadPreset(t)
			cfg.RequestBody.ContainerCreate.AllowedBindMounts = tt.binds
			c := control(t, Generate(cfg, data), "5.31")
			if c.Status != StatusNeedsEvidence {
				t.Fatalf("status = %s, want needs_evidence", c.Status)
			}
			if len(c.Evidence) != 1 || c.Evidence[0].Observed != tt.want {
				t.Fatalf("evidence = %+v, want observed %s", c.Evidence, tt.want)
			}
			if got := strings.Contains(strings.Join(c.Notes, " "), "covers a Docker or Podman socket"); got != (tt.want == "true") {
				t.Errorf("socket note present = %v for observed %s", got, tt.want)
			}
		})
	}

	t.Run("profile bind is checked too", func(t *testing.T) {
		cfg, data := loadPreset(t)
		body := cfg.RequestBody
		body.ContainerCreate.AllowedBindMounts = []string{"/var/run/docker.sock"}
		cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "p", RequestBody: body}}
		c := control(t, Generate(cfg, data), "5.31")
		if len(c.Evidence) != 2 || c.Evidence[0].Observed != "false" || c.Evidence[1].Observed != "true" {
			t.Fatalf("evidence = %+v", c.Evidence)
		}
	})
}

func TestCPUEvidenceStatesTheAlternative(t *testing.T) {
	cfg, data := loadPreset(t)
	c := control(t, Generate(cfg, data), "5.11")
	if len(c.Evidence) != 2 {
		t.Fatalf("evidence = %+v, want two rows", c.Evidence)
	}
	for _, e := range c.Evidence {
		if !strings.Contains(e.Expected, "require_cpu_limit or require_cpu_limit_hard") {
			t.Errorf("expected = %q, want the OR stated", e.Expected)
		}
	}
	if c.Evidence[0].Observed != "true" || c.Evidence[1].Observed != "false" {
		t.Errorf("observed = %q, %q", c.Evidence[0].Observed, c.Evidence[1].Observed)
	}
}

func TestPartialEvidencePathsUseProfileIndex(t *testing.T) {
	cfg, data := loadPreset(t)
	body := cfg.RequestBody
	body.ContainerCreate.AllowPrivileged = true
	cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "p", RequestBody: body}}
	c := control(t, Generate(cfg, data), "5.4")
	var paths []string
	for _, e := range c.Evidence {
		paths = append(paths, e.Path)
	}
	want := []string{
		"request_body.container_create.allow_privileged",
		"request_body.libpod_container_create.allow_privileged",
		"clients.profiles[0].request_body.container_create.allow_privileged",
		"clients.profiles[0].request_body.libpod_container_create.allow_privileged",
	}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	if c.Evidence[2].Observed != "true" || c.Evidence[0].Observed != "false" {
		t.Fatalf("evidence = %+v", c.Evidence)
	}
}

func TestTLSListeners(t *testing.T) {
	tcp := func(ca string) config.ListenConfig {
		return config.ListenConfig{Address: "0.0.0.0:2376", TLS: config.ListenTLSConfig{ClientCAFile: ca}}
	}
	tests := []struct {
		name       string
		listen     config.ListenConfig
		listeners  []config.ListenerConfig
		want       Status
		wantNote   string
		wantEvPath string
	}{
		{"unix only", config.ListenConfig{Socket: "/run/s.sock"}, nil, StatusConfigured, "no TCP listeners", ""},
		{"legacy tcp without CA", tcp(""), nil, StatusNotConfigured, "", "listen.tls.client_ca_file"},
		{"legacy tcp with CA", tcp("/x/ca.pem"), nil, StatusConfigured, "", "listen.tls.client_ca_file"},
		{"socket wins over address", config.ListenConfig{Socket: "/run/s.sock", Address: "0.0.0.0:1"}, nil, StatusConfigured, "no TCP listeners", ""},
		{"mixed listeners", config.ListenConfig{}, []config.ListenerConfig{
			{Name: "a", ListenConfig: tcp("/x/ca.pem")},
			{Name: "b", ListenConfig: tcp("")},
			{Name: "c", ListenConfig: config.ListenConfig{Socket: "/run/s.sock"}},
		}, StatusPartial, "", "listeners[1].tls.client_ca_file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Listen = tt.listen
			cfg.Listeners = tt.listeners
			c := control(t, Generate(&cfg, nil), "2.6")
			if c.Status != tt.want {
				t.Fatalf("status = %s, want %s", c.Status, tt.want)
			}
			if tt.wantNote != "" && !strings.Contains(strings.Join(c.Notes, " "), tt.wantNote) {
				t.Errorf("notes = %v, want %q", c.Notes, tt.wantNote)
			}
			if tt.wantEvPath != "" {
				found := false
				for _, e := range c.Evidence {
					found = found || e.Path == tt.wantEvPath
				}
				if !found {
					t.Errorf("evidence = %+v, want path %s", c.Evidence, tt.wantEvPath)
				}
			}
		})
	}
}

func TestSwarmRules(t *testing.T) {
	allow := func(path string) config.RuleConfig {
		return config.RuleConfig{Match: config.MatchConfig{Method: "*", Path: path}, Action: "allow"}
	}
	denyAll := config.RuleConfig{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"}
	tests := []struct {
		name  string
		rules []config.RuleConfig
		prof  []config.ClientProfileConfig
		want  Status
	}{
		{"no rules default-denies", nil, nil, StatusConfigured},
		{"containers only", []config.RuleConfig{allow("/containers/**"), denyAll}, nil, StatusConfigured},
		{"services allowed", []config.RuleConfig{allow("/services/**"), denyAll}, nil, StatusNotConfigured},
		{"get-only secrets allowed", []config.RuleConfig{{Match: config.MatchConfig{Method: "GET", Path: "/secrets"}, Action: "allow"}, denyAll}, nil, StatusNotConfigured},
		{"allow everything", []config.RuleConfig{allow("/**")}, nil, StatusNotConfigured},
		{"global allows, profile denies", []config.RuleConfig{allow("/swarm/**")},
			[]config.ClientProfileConfig{{Name: "p", Rules: []config.RuleConfig{denyAll}}}, StatusPartial},
		{"profile allows nodes", []config.RuleConfig{denyAll},
			[]config.ClientProfileConfig{{Name: "p", Rules: []config.RuleConfig{allow("/nodes/**")}}}, StatusPartial},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Rules = tt.rules
			cfg.Clients.Profiles = tt.prof
			if got := control(t, Generate(&cfg, nil), "7.x").Status; got != tt.want {
				t.Fatalf("7.x = %s, want %s", got, tt.want)
			}
		})
	}
}

const sentinel = "SENTINEL-SECRET"

func sensitiveConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Upstream.Socket = "/" + sentinel + "/docker.sock"
	cfg.Listen = config.ListenConfig{
		Address: "0.0.0.0:2376",
		TLS: config.ListenTLSConfig{
			CertFile:     "/" + sentinel + "/cert.pem",
			KeyFile:      "/" + sentinel + "/key.pem",
			ClientCAFile: "/" + sentinel + "/ca.pem",
			CommonNames:  []string{sentinel + "-cn"},
		},
	}
	cfg.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "GET", Path: "/" + sentinel}, Action: "allow", Reason: sentinel}}
	cc := &cfg.RequestBody.ContainerCreate
	cc.AllowedBindMounts = []string{"/" + sentinel + "/data", sentinel, "/" + sentinel + "/x.sock"}
	cc.AllowedDevices = []string{"/dev/" + sentinel}
	cc.AllowedCapabilities = []string{sentinel}
	cc.RequiredLabels = []string{"owner=" + sentinel}
	cc.AllowedImages = []string{"registry/" + sentinel + ":1"}
	cc.ImageTrust.Mode = "enforce"
	cc.ImageTrust.AllowedSigningKeys = []config.SigningKeyConfig{{PEM: "-----BEGIN " + sentinel + "-----"}}
	cc.ImageTrust.AllowedKeyless = []config.KeylessConfig{{Issuer: "https://" + sentinel, SubjectPattern: sentinel}}
	cfg.RequestBody.Exec.AllowedCommands = [][]string{{sentinel}}
	cfg.Clients.ContainerLabels.LabelPrefix = sentinel
	cfg.Ownership.Owner = sentinel
	cfg.Clients.Profiles = []config.ClientProfileConfig{{
		Name:     sentinel + "-profile",
		Mode:     sentinel + "-mode",
		Response: config.ClientProfileResponseConfig{VisibleResourceLabels: []string{"team=" + sentinel}, NamePatterns: []string{sentinel}},
		RequestBody: config.RequestBodyConfig{ContainerCreate: config.ContainerCreateRequestBodyConfig{
			AllowedBindMounts: []string{"/" + sentinel},
			ImageTrust:        config.ImageTrustConfig{Mode: sentinel},
		}},
		Rules: []config.RuleConfig{{Match: config.MatchConfig{Method: "GET", Path: "/" + sentinel}, Action: "allow"}},
	}}
	return &cfg
}

func renderAll(t *testing.T, r Report) map[string]string {
	t.Helper()
	out := map[string]string{}
	for name, fn := range map[string]func(*bytes.Buffer) error{
		"json":     func(b *bytes.Buffer) error { return WriteJSON(b, r) },
		"markdown": func(b *bytes.Buffer) error { return WriteMarkdown(b, r) },
		"text":     func(b *bytes.Buffer) error { return WriteText(b, r) },
	} {
		var b bytes.Buffer
		if err := fn(&b); err != nil {
			t.Fatalf("%s render: %v", name, err)
		}
		out[name] = b.String()
	}
	return out
}

func TestOutputNeverContainsConfigValues(t *testing.T) {
	r := Generate(sensitiveConfig(), []byte("config bytes "+sentinel))
	for name, s := range renderAll(t, r) {
		if strings.Contains(s, sentinel) {
			t.Errorf("%s output leaks the sentinel", name)
		}
		if strings.Contains(strings.ToLower(s), "sentinel") {
			t.Errorf("%s output leaks part of the sentinel", name)
		}
	}
	// The sentinel config still produces real verdicts, so the check above is
	// not passing on an empty report.
	if got := control(t, r, "5.5").Status; got != StatusNotConfigured {
		t.Errorf("5.5 = %s, want not_configured", got)
	}
	ev := control(t, r, "5.5").Evidence
	if len(ev) == 0 || ev[0].Observed != "3 entries" {
		t.Errorf("5.5 evidence = %+v, want a length-only observation", ev)
	}
}

func TestOutputIsDeterministic(t *testing.T) {
	// Same effective config from YAML with keys in different orders.
	a := "request_body:\n  container_create:\n    allow_privileged: false\n    require_memory_limit: true\n    require_cpu_limit: true\n  exec:\n    allow_root_user: false\nlog:\n  level: info\n"
	b := "log:\n  level: info\nrequest_body:\n  exec:\n    allow_root_user: false\n  container_create:\n    require_cpu_limit: true\n    require_memory_limit: true\n    allow_privileged: false\n"
	dir := t.TempDir()
	load := func(name, y string) *config.Config {
		p := dir + "/" + name
		if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(p)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	cfgA, cfgB := load("a.yaml", a), load("b.yaml", b)
	fixed := []byte("same bytes")
	first := renderAll(t, Generate(cfgA, fixed))
	for i := 0; i < 3; i++ {
		again := renderAll(t, Generate(cfgA, fixed))
		other := renderAll(t, Generate(cfgB, fixed))
		for name := range first {
			if first[name] != again[name] {
				t.Errorf("%s output differs across runs", name)
			}
			if first[name] != other[name] {
				t.Errorf("%s output differs for reordered YAML keys", name)
			}
		}
	}
}

func TestReportShape(t *testing.T) {
	cfg, data := loadPreset(t)
	r := Generate(cfg, data)
	if r.Benchmark != "CIS Docker Benchmark v1.6.0" || r.Disclaimer != Disclaimer || len(r.ConfigSHA256) != 64 {
		t.Fatalf("header = %+v", r)
	}
	sum := r.Summary
	if sum.Total != len(r.Controls) || sum.Total != sum.Configured+sum.NotConfigured+sum.Partial+sum.AlwaysOn+sum.NeedsEvidence+sum.OutsideScope {
		t.Fatalf("summary does not add up: %+v", sum)
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("json does not parse: %v", err)
	}
	if len(back.Controls) != len(r.Controls) {
		t.Fatalf("round trip lost controls")
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"evidence": []`)) {
		t.Errorf("empty evidence should render as [], not null")
	}
	md := renderAll(t, r)["markdown"]
	for _, want := range []string{"| Control | Title | Category | Status |", Disclaimer, "## Summary"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(md), Disclaimer) {
		t.Errorf("markdown should end with the disclaimer")
	}
}

func TestOutsideScopeRowsHaveReasonAndNoEvaluator(t *testing.T) {
	for _, c := range controls {
		if c.Category == CategoryOutsideScope {
			if c.Evaluate != nil || c.Reason == "" {
				t.Errorf("%s: outside_scope needs a reason and no evaluator", c.ID)
			}
		} else if c.Evaluate == nil {
			t.Errorf("%s: %s control needs an evaluator", c.ID, c.Category)
		}
	}
}

// docIDs pulls the bold first-column control IDs from the rows under the
// "## <heading prefix>" section of the CIS docs page.
func docIDs(t *testing.T, doc, headingPrefix string) []string {
	t.Helper()
	var ids []string
	in := false
	row := regexp.MustCompile(`^\| \*\*([^*]+)\*\* \|`)
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "## ") {
			in = strings.HasPrefix(line, "## "+headingPrefix)
			continue
		}
		if !in {
			continue
		}
		if m := row.FindStringSubmatch(line); m != nil {
			id := strings.Fields(m[1])[0]
			ids = append(ids, strings.TrimSuffix(id, ","))
		}
	}
	return ids
}

func TestControlTableMatchesDocs(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/content/docs/cis-docker-benchmark.mdx")
	if err != nil {
		t.Fatalf("read docs page: %v", err)
	}
	doc := string(raw)
	for cat, heading := range map[Category]string{
		CategoryEnforced:     "What sockguard enforces",
		CategoryInfluenced:   "Beyond Section 5",
		CategoryOutsideScope: "What sockguard cannot enforce",
	} {
		want := docIDs(t, doc, heading)
		if len(want) == 0 {
			t.Fatalf("no rows found under %q; the docs table format changed", heading)
		}
		var got []string
		for _, c := range controls {
			if c.Category == cat {
				got = append(got, c.ID)
			}
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s IDs drifted from docs\n go:   %v\n docs: %v", cat, got, want)
		}
	}
}
