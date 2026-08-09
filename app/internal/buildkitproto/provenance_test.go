package buildkitproto

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// vendoredFile mirrors one row of PROVENANCE.md's table. sha256 is computed
// against the file exactly as committed under proto/ — see that document
// for the corresponding upstream source URL/tag and (for files marked
// "full" there) the upstream sha256 to diff a fresh fetch against.
type vendoredFile struct {
	path   string // relative to this package's proto/ directory
	sha256 string
}

// vendoredManifest is the committed descriptor/provenance manifest this
// test's TestVendoredProtoIntegrity diffs the on-disk proto/ tree against.
// Any hand-edit to a vendored .proto file that isn't accompanied by an
// update here (and to PROVENANCE.md) fails this test — see #185 phase 1's
// "compatibility is keyed to the committed manifest, never a client version
// string" posture, applied to the vendoring step itself.
var vendoredManifest = []vendoredFile{
	{
		path:   "github.com/moby/buildkit/api/services/control/control.proto",
		sha256: "07dd7f821f3384a164a1d835caf321e60c577e1ad55aa9c0ffa6a62c63161d4d",
	},
	{
		path:   "github.com/moby/buildkit/solver/pb/ops.proto",
		sha256: "a39200ece5949279660da29dc632fc55f684862eb8014cdacaac373127b6445b",
	},
	{
		path:   "github.com/moby/buildkit/sourcepolicy/pb/policy.proto",
		sha256: "8437741bd7dd5dffc154f71017b5608eea96e5f2f4b2f404ede55e736bffbe0b",
	},
	{
		path:   "github.com/moby/buildkit/session/auth/auth.proto",
		sha256: "04fa85bbe7a9dc954d6de7751033efdbb6064211cd8ec12b58b591e1ed5a28b8",
	},
	{
		path:   "github.com/moby/buildkit/session/secrets/secrets.proto",
		sha256: "bb85e36142c2ac0a581288a17f5c8f8f154f476bf1c40695423a68bb3489d6d4",
	},
	{
		path:   "github.com/moby/buildkit/session/sshforward/ssh.proto",
		sha256: "841df4c28324beee9d98aff5132418302583ac5179d87ff264a705da6a0124ca",
	},
	{
		path:   "github.com/moby/buildkit/session/filesync/filesync.proto",
		sha256: "1e35063b1644dab951f7f1bbb38b4da76ffa219418e4c4a63a41a46b1a9e3d1e",
	},
	{
		path:   "github.com/moby/buildkit/session/upload/upload.proto",
		sha256: "261fd48c87585a6473b8929ee05a28e08f526d60acba4fc4c1382612121a7318",
	},
	{
		path:   "github.com/tonistiigi/fsutil/types/wire.proto",
		sha256: "2c3557f086e5d0d07cb85fc2794a8d432967cc3079d43a8ea3a86dcb203afa10",
	},
	{
		path:   "github.com/tonistiigi/fsutil/types/stat.proto",
		sha256: "bf0ff711be60836c7e3f4b30945ecf768621241f2748af11a42b99a6b35e358c",
	},
	{
		path:   "grpc/health/v1/health.proto",
		sha256: "38da70e7115c9e195947d433db862deefdd76085891197d630fe72b5cc210d75",
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
