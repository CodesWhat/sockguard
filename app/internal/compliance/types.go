// Package compliance turns a Sockguard configuration into a CIS Docker
// Benchmark configuration report. It reads configuration only: it never
// contacts a daemon, and its output carries booleans, enum modes and list
// lengths, never list contents, file paths, keys, names or label values.
package compliance

// Benchmark names the benchmark release the control table mirrors.
const Benchmark = "CIS Docker Benchmark v1.6.0"

// Disclaimer is printed verbatim on every report.
const Disclaimer = "This report describes Sockguard configuration only. It is not a CIS certification and does not prove runtime enforcement; controls outside the Docker API request path need separate evidence."

// Category says how Sockguard relates to a control.
type Category string

const (
	CategoryEnforced     Category = "enforced"
	CategoryInfluenced   Category = "influenced"
	CategoryOutsideScope Category = "outside_scope"
)

// Status is the configuration verdict for one control.
type Status string

const (
	StatusConfigured    Status = "configured"
	StatusNotConfigured Status = "not_configured"
	StatusPartial       Status = "partial"
	StatusAlwaysOn      Status = "always_on"
	// StatusNeedsEvidence marks a control Sockguard cannot verify from its own
	// config: it depends on how workloads are deployed.
	StatusNeedsEvidence Status = "needs_evidence"
	StatusOutsideScope  Status = "outside_scope"
)

// Evidence is one observed configuration fact. Path is a mapstructure-style
// dotted config path (profiles are addressed by index, never by name).
// Observed never holds a secret or free-form value: booleans, enum modes and
// list lengths only.
type Evidence struct {
	Path     string `json:"path"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
}

// ControlResult is the verdict for one control. Evaluators fill Status,
// Evidence and Notes; Generate stamps ID, Title and Category.
type ControlResult struct {
	ID       string     `json:"id"`
	Title    string     `json:"title"`
	Category Category   `json:"category"`
	Status   Status     `json:"status"`
	Evidence []Evidence `json:"evidence"`
	Notes    []string   `json:"notes"`
}

// Summary counts controls per status.
type Summary struct {
	Total         int `json:"total"`
	Configured    int `json:"configured"`
	NotConfigured int `json:"not_configured"`
	Partial       int `json:"partial"`
	AlwaysOn      int `json:"always_on"`
	NeedsEvidence int `json:"needs_evidence"`
	OutsideScope  int `json:"outside_scope"`
}

// Report is the full, deterministic report. It carries no timestamps,
// hostnames or paths.
type Report struct {
	Benchmark        string          `json:"benchmark"`
	SockguardVersion string          `json:"sockguard_version"`
	ConfigSHA256     string          `json:"config_sha256"`
	Disclaimer       string          `json:"disclaimer"`
	Summary          Summary         `json:"summary"`
	Notes            []string        `json:"notes"`
	Controls         []ControlResult `json:"controls"`
}
