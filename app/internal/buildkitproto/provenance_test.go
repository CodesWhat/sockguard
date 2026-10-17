package buildkitproto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vendoredFile mirrors one row of PROVENANCE.md's table. sha256 is computed
// against the file exactly as committed under proto/ — see that document
// for the corresponding upstream source URL/tag and (for files marked
// "full" there) the upstream sha256 to diff a fresh fetch against. tag and
// curationPrefix duplicate two more of that row's columns (Upstream tag,
// Curation) so TestProvenanceMarkdownMatchesVendoredManifest can catch
// PROVENANCE.md drifting out of sync with this manifest, not just the
// manifest drifting out of sync with the files on disk (that's
// TestVendoredProtoIntegrity's job, above).
type vendoredFile struct {
	path           string // relative to this package's proto/ directory
	tag            string // PROVENANCE.md's "Upstream tag" column, backtick-quoted part only
	curationPrefix string // PROVENANCE.md's "Curation" column must start with this
	sha256         string // PROVENANCE.md's "Vendored sha256" column
}

// vendoredManifest is the committed descriptor/provenance manifest this
// test's TestVendoredProtoIntegrity diffs the on-disk proto/ tree against.
// Any hand-edit to a vendored .proto file that isn't accompanied by an
// update here (and to PROVENANCE.md) fails this test — see #185 phase 1's
// "compatibility is keyed to the committed manifest, never a client version
// string" posture, applied to the vendoring step itself.
var vendoredManifest = []vendoredFile{
	{path: "github.com/moby/buildkit/frontend/gateway/pb/gateway.proto", tag: "v0.32.0", curationPrefix: "full", sha256: "7647f50267550b2d615176e990b1ac7b86294b5f5ad0d0ca07723d309dfaec47"},
	{path: "github.com/moby/buildkit/api/types/worker.proto", tag: "v0.32.0", curationPrefix: "full", sha256: "0ec05fcaf0bd7fbba8db269b774b82a7f9a6d1193e43335a84e3a07ef4758c16"},
	{path: "github.com/moby/buildkit/util/apicaps/pb/caps.proto", tag: "v0.32.0", curationPrefix: "full", sha256: "4f997c43584a2d903b44d0c00e37582e9a63f569a781ed920f9937d177d17c88"},
	{path: "google/rpc/status.proto", tag: "a68d4433fa8f0cf72710a60cc09dec096db0fcee", curationPrefix: "full", sha256: "f5bfd262e6705c7ae73f32e0ad8ee20ce8c0a2578df8c4f76ebf76b572f295ed"},
	{
		path:           "github.com/moby/buildkit/api/services/control/control.proto",
		tag:            "v0.32.0",
		curationPrefix: "trimmed",
		sha256:         "377961906c8fc7fa832f70f01bf182e2bfe2262491e357b0eebf18143f54215b",
	},
	{
		path:           "github.com/moby/buildkit/solver/pb/ops.proto",
		tag:            "v0.32.0",
		curationPrefix: "full",
		sha256:         "78b13c6ea45c9b65fd2336a38780c9a470db4dcccc01822f4066376bb1660cd6",
	},
	{
		path:           "github.com/moby/buildkit/sourcepolicy/pb/policy.proto",
		tag:            "v0.32.0",
		curationPrefix: "full",
		sha256:         "6e61e45167caf341ac82268327a9bd5d98195ee97700bb58fde190be1b65cdea",
	},
	{
		path:           "github.com/moby/buildkit/session/auth/auth.proto",
		tag:            "v0.32.0",
		curationPrefix: "full",
		sha256:         "86ef8731042a1122b6e58e7426f52a6601e46dcf8e58d86c383d82d5743a5d96",
	},
	{
		path:           "github.com/moby/buildkit/session/secrets/secrets.proto",
		tag:            "v0.32.0",
		curationPrefix: "full",
		sha256:         "982d29ddd33f1d38a9e88abe95fc97c405f2901cccda74475fa571a6c85043b0",
	},
	{
		path:           "github.com/moby/buildkit/session/sshforward/ssh.proto",
		tag:            "v0.32.0",
		curationPrefix: "full",
		sha256:         "19a2083f9398b67a3b15f40d42b0a13042932f7ea3742034554a8128a876faa9",
	},
	{
		path:           "github.com/moby/buildkit/session/filesync/filesync.proto",
		tag:            "v0.32.0",
		curationPrefix: "full",
		sha256:         "5e76333ee49cd23972ca023fb970e69d6849c0f086ca06244fdf40beecbf956f",
	},
	{
		path:           "github.com/moby/buildkit/session/upload/upload.proto",
		tag:            "v0.32.0",
		curationPrefix: "full",
		sha256:         "319603d177706969e788a119710613bf365ffb904d5d062c578b7a83275bbde6",
	},
	{
		path:           "github.com/tonistiigi/fsutil/types/wire.proto",
		tag:            "v0.32.0",
		curationPrefix: "trimmed, dep dropped",
		sha256:         "35be3cfcd50159b49f17200dc980e7cb4e8d548521cb53b78aa1d96983faafaf",
	},
	{
		path:           "github.com/tonistiigi/fsutil/types/stat.proto",
		tag:            "v0.32.0",
		curationPrefix: "trimmed, dep dropped",
		sha256:         "6e1e24a1fe1cc74755d51f9c9f602ec7ac2f8a3e178e0ecc90e5e3e3b1e841f5",
	},
	{
		path:           "grpc/health/v1/health.proto",
		tag:            "v1.71.0",
		curationPrefix: "full",
		sha256:         "9fc6091c04f6e02485cf3bf9eee14f0e62be3484fbf90c0a253b2a3dffbb4bcc",
	},
}

// TestVendoredProtoIntegrity is #185 phase 1's provenance golden test: every
// vendored .proto file under proto/ must exactly match the sha256 recorded
// in vendoredManifest (and PROVENANCE.md), and every .proto file under
// proto/ must be listed in the manifest — in either direction, drift means
// someone edited a vendored schema (or added/removed one) without updating
// the provenance record reviewers rely on for compatibility bumps.
func TestVendoredProtoIntegrity(t *testing.T) {
	seen := make(map[string]bool, len(vendoredManifest))

	for _, vf := range vendoredManifest {
		seen[vf.path] = true
		data, err := os.ReadFile(filepath.Join("proto", vf.path))
		if err != nil {
			t.Errorf("manifest entry %q: %v", vf.path, err)
			continue
		}
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if got != vf.sha256 {
			t.Errorf("proto/%s: sha256 = %s, manifest says %s — vendored file changed without a provenance update (see PROVENANCE.md)", vf.path, got, vf.sha256)
		}
	}

	err := filepath.WalkDir("proto", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".proto" {
			return nil
		}
		rel, relErr := filepath.Rel("proto", path)
		if relErr != nil {
			return relErr
		}
		if !seen[rel] {
			t.Errorf("proto/%s exists on disk but is not listed in vendoredManifest (update this test and PROVENANCE.md)", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk proto/: %v", err)
	}
}

// provenanceRow is one parsed data row of PROVENANCE.md's "Vendored files"
// table (the seven-column table under the "## Vendored files" heading).
type provenanceRow struct {
	path           string // "Vendored path" column, backtick-quoted part
	tag            string // "Upstream tag" column, backtick-quoted part only (drops any trailing parenthetical like fsutiltypes' "(buildkit's vendored copy)")
	curation       string // "Curation" column, verbatim (plain text, not backtick-quoted)
	vendoredSHA256 string // "Vendored sha256" column, backtick-quoted part
}

// extractBacktick returns the text between the first pair of backticks in
// cell, or cell trimmed of surrounding whitespace if it has no backtick pair
// at all (used for PROVENANCE.md's plain-text Curation column).
func extractBacktick(cell string) string {
	start := strings.Index(cell, "`")
	if start < 0 {
		return strings.TrimSpace(cell)
	}
	rest := cell[start+1:]
	end := strings.Index(rest, "`")
	if end < 0 {
		return strings.TrimSpace(cell)
	}
	return rest[:end]
}

// parseProvenanceMarkdownTable extracts every data row of PROVENANCE.md's
// "Vendored files" table. It locates the table by its header cell text
// ("Vendored path (under...") rather than a fixed line number, so unrelated
// edits earlier in the document don't break parsing, and stops at the first
// line that isn't a table row (a blank line always follows the table in
// PROVENANCE.md today).
func parseProvenanceMarkdownTable(md string) ([]provenanceRow, error) {
	lines := strings.Split(md, "\n")

	headerIdx := -1
	for i, line := range lines {
		if strings.Contains(line, "Vendored path (under") {
			headerIdx = i
			break
		}
	}
	if headerIdx < 0 {
		return nil, fmt.Errorf("could not find the vendored-files table header (looking for a line containing %q)", "Vendored path (under")
	}
	if headerIdx+1 >= len(lines) || !strings.HasPrefix(strings.TrimSpace(lines[headerIdx+1]), "|---") {
		return nil, fmt.Errorf("expected a markdown table separator row (|---|...) immediately after the header at line %d", headerIdx+1)
	}

	const wantColumns = 7 // Vendored path, Go package, Upstream source, Upstream tag, Curation, Upstream sha256, Vendored sha256
	var rows []provenanceRow
	for i := headerIdx + 2; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "|") {
			break
		}
		cells := strings.Split(line, "|")
		// Splitting "|c1|...|c7|" on "|" yields a leading and trailing empty
		// element plus the wantColumns data cells in between.
		if len(cells) < wantColumns+2 {
			return nil, fmt.Errorf("table row has %d columns, want %d: %q", len(cells)-2, wantColumns, line)
		}
		rows = append(rows, provenanceRow{
			path:           extractBacktick(cells[1]),
			tag:            extractBacktick(cells[4]),
			curation:       strings.TrimSpace(cells[5]),
			vendoredSHA256: extractBacktick(cells[7]),
		})
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("parsed zero data rows from PROVENANCE.md's vendored-files table")
	}
	return rows, nil
}

// TestProvenanceMarkdownMatchesVendoredManifest is CodeRabbit's
// round-1-review fix: TestVendoredProtoIntegrity above only ever compared
// vendoredManifest against the files on disk, so PROVENANCE.md itself could
// drift — a hand-edit to the table (or a missed update after changing
// vendoredManifest) stayed invisible to CI as long as nobody also touched a
// .proto file. This test closes that gap by parsing PROVENANCE.md's table
// directly and cross-checking every row against vendoredManifest in both
// directions: path, pinned upstream tag, curation (full/trimmed) status, and
// vendored sha256 must all agree, and neither side may have an entry the
// other lacks.
func TestProvenanceMarkdownMatchesVendoredManifest(t *testing.T) {
	data, err := os.ReadFile("PROVENANCE.md")
	if err != nil {
		t.Fatalf("reading PROVENANCE.md: %v", err)
	}
	rows, err := parseProvenanceMarkdownTable(string(data))
	if err != nil {
		t.Fatalf("parsing PROVENANCE.md's vendored-files table: %v", err)
	}

	manifestByPath := make(map[string]vendoredFile, len(vendoredManifest))
	for _, vf := range vendoredManifest {
		manifestByPath[vf.path] = vf
	}

	seenPaths := make(map[string]bool, len(rows))
	for _, row := range rows {
		seenPaths[row.path] = true

		vf, ok := manifestByPath[row.path]
		if !ok {
			t.Errorf("PROVENANCE.md row %q has no matching entry in vendoredManifest (provenance_test.go) — the table drifted ahead of the Go manifest", row.path)
			continue
		}
		if row.tag != vf.tag {
			t.Errorf("PROVENANCE.md row %q: Upstream tag column = %q, vendoredManifest.tag = %q", row.path, row.tag, vf.tag)
		}
		if !strings.HasPrefix(row.curation, vf.curationPrefix) {
			t.Errorf("PROVENANCE.md row %q: Curation column = %q, vendoredManifest.curationPrefix = %q (column must start with this)", row.path, row.curation, vf.curationPrefix)
		}
		if row.vendoredSHA256 != vf.sha256 {
			t.Errorf("PROVENANCE.md row %q: Vendored sha256 column = %s, vendoredManifest.sha256 = %s", row.path, row.vendoredSHA256, vf.sha256)
		}
	}

	for path := range manifestByPath {
		if !seenPaths[path] {
			t.Errorf("vendoredManifest entry %q has no matching row in PROVENANCE.md's table — the Go manifest drifted ahead of the doc", path)
		}
	}
}
