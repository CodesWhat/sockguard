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
	{
		path:           "github.com/moby/buildkit/api/services/control/control.proto",
		tag:            "v0.32.0",
		curationPrefix: "trimmed",
		sha256:         "07dd7f821f3384a164a1d835caf321e60c577e1ad55aa9c0ffa6a62c63161d4d",
	},
	{
		path:           "github.com/moby/buildkit/solver/pb/ops.proto",
		tag:            "v0.32.0",
		curationPrefix: "full",
		sha256:         "a39200ece5949279660da29dc632fc55f684862eb8014cdacaac373127b6445b",
	},
	{
		path:           "github.com/moby/buildkit/sourcepolicy/pb/policy.proto",
		tag:            "v0.32.0",
		curationPrefix: "full",
		sha256:         "8437741bd7dd5dffc154f71017b5608eea96e5f2f4b2f404ede55e736bffbe0b",
	},
	{
		path:           "github.com/moby/buildkit/session/auth/auth.proto",
		tag:            "v0.32.0",
		curationPrefix: "full",
		sha256:         "04fa85bbe7a9dc954d6de7751033efdbb6064211cd8ec12b58b591e1ed5a28b8",
	},
	{
		path:           "github.com/moby/buildkit/session/secrets/secrets.proto",
		tag:            "v0.32.0",
		curationPrefix: "full",
		sha256:         "bb85e36142c2ac0a581288a17f5c8f8f154f476bf1c40695423a68bb3489d6d4",
	},
	{
		path:           "github.com/moby/buildkit/session/sshforward/ssh.proto",
		tag:            "v0.32.0",
		curationPrefix: "full",
		sha256:         "841df4c28324beee9d98aff5132418302583ac5179d87ff264a705da6a0124ca",
	},
	{
		path:           "github.com/moby/buildkit/session/filesync/filesync.proto",
		tag:            "v0.32.0",
		curationPrefix: "full",
		sha256:         "1e35063b1644dab951f7f1bbb38b4da76ffa219418e4c4a63a41a46b1a9e3d1e",
	},
	{
		path:           "github.com/moby/buildkit/session/upload/upload.proto",
		tag:            "v0.32.0",
		curationPrefix: "full",
		sha256:         "261fd48c87585a6473b8929ee05a28e08f526d60acba4fc4c1382612121a7318",
	},
	{
		path:           "github.com/tonistiigi/fsutil/types/wire.proto",
		tag:            "v0.32.0",
		curationPrefix: "trimmed, dep dropped",
		sha256:         "2c3557f086e5d0d07cb85fc2794a8d432967cc3079d43a8ea3a86dcb203afa10",
	},
	{
		path:           "github.com/tonistiigi/fsutil/types/stat.proto",
		tag:            "v0.32.0",
		curationPrefix: "trimmed, dep dropped",
		sha256:         "bf0ff711be60836c7e3f4b30945ecf768621241f2748af11a42b99a6b35e358c",
	},
	{
		path:           "grpc/health/v1/health.proto",
		tag:            "v1.71.0",
		curationPrefix: "full",
		sha256:         "38da70e7115c9e195947d433db862deefdd76085891197d630fe72b5cc210d75",
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
