package tlsbootstrap

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func opts(dir string, clients ...string) Options {
	return Options{Dir: dir, ServerNames: []string{"sockguard.internal", "127.0.0.1"}, Clients: clients}
}

func loadCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(data)
	if b == nil {
		t.Fatalf("%s: no PEM", path)
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func readAll(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		m[e.Name()] = string(b)
	}
	return m
}

func TestBootstrapChainAndIdentity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	res, err := Bootstrap(opts(dir, "portainer", "ci"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.CreatedCA || res.Server != ActionCreated {
		t.Fatalf("result = %+v", res)
	}
	ca := loadCert(t, filepath.Join(dir, CAFileName))
	if !ca.IsCA || ca.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatal("CA is not an ECDSA CA")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	srv := loadCert(t, filepath.Join(dir, ServerCertFileName))
	if _, err := srv.Verify(x509.VerifyOptions{Roots: pool, DNSName: "sockguard.internal", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("server dns: %v", err)
	}
	if _, err := srv.Verify(x509.VerifyOptions{Roots: pool, DNSName: "127.0.0.1", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("server ip: %v", err)
	}
	for _, name := range []string{"portainer", "ci"} {
		c := loadCert(t, filepath.Join(dir, ClientCertFileName(name)))
		if c.Subject.CommonName != name || len(c.DNSNames) != 1 || c.DNSNames[0] != name {
			t.Errorf("%s identity: CN=%q DNS=%v", name, c.Subject.CommonName, c.DNSNames)
		}
		if _, err := c.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Errorf("%s verify: %v", name, err)
		}
		if _, err := c.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
			t.Errorf("%s client cert verifies for server auth", name)
		}
	}
}

func TestBootstrapPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	dir := filepath.Join(t.TempDir(), "a", "pki")
	if _, err := Bootstrap(opts(dir, "x")); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(dir)
	if info.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %o", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 8-2 { // ca, ca-key, server, server-key, client, client-key
		t.Errorf("files = %d", len(entries))
	}
	for _, e := range entries {
		fi, _ := e.Info()
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o", e.Name(), fi.Mode().Perm())
		}
	}
}

func TestBootstrapRefusesLooseExistingDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Bootstrap(opts(dir, "x"))
	if err == nil || !strings.Contains(err.Error(), "looser than 0700") {
		t.Fatalf("err = %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("wrote into loose dir: %v", entries)
	}
	info, _ := os.Stat(dir)
	if info.Mode().Perm() != 0o755 {
		t.Error("loose dir was chmod-ed")
	}
}

func TestBootstrapRefusesSymlinkAndFile(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "real"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "link")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := Bootstrap(opts(filepath.Join(base, "link"), "x")); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("symlink err = %v", err)
	}
	f := filepath.Join(base, "file")
	_ = os.WriteFile(f, nil, 0o600)
	if _, err := Bootstrap(opts(f, "x")); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("file err = %v", err)
	}
}

func TestBootstrapIdempotentRerunAndAddClient(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	if _, err := Bootstrap(opts(dir, "a")); err != nil {
		t.Fatal(err)
	}
	before := readAll(t, dir)

	res, err := Bootstrap(opts(dir, "a"))
	if err != nil {
		t.Fatal(err)
	}
	if res.CreatedCA || res.Server != ActionReused || res.Clients["a"] != ActionReused || len(res.CreatedFiles) != 0 {
		t.Fatalf("rerun result = %+v", res)
	}
	if after := readAll(t, dir); !equalMaps(before, after) {
		t.Fatal("rerun changed files")
	}

	res, err = Bootstrap(opts(dir, "a", "b"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Clients["a"] != ActionReused || res.Clients["b"] != ActionCreated {
		t.Fatalf("add result = %+v", res.Clients)
	}
	after := readAll(t, dir)
	for name, content := range before {
		if after[name] != content {
			t.Errorf("%s changed when adding a client", name)
		}
	}
	if after[ClientCertFileName("b")] == "" || after[ClientKeyFileName("b")] == "" {
		t.Error("client b files missing")
	}
	ca := loadCert(t, filepath.Join(dir, CAFileName))
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := loadCert(t, filepath.Join(dir, ClientCertFileName("b"))).Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("client b under original CA: %v", err)
	}
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestBootstrapForceReissuesLeavesKeepsCA(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	if _, err := Bootstrap(opts(dir, "a", "b")); err != nil {
		t.Fatal(err)
	}
	before := readAll(t, dir)

	o := opts(dir, "a")
	o.Force = true
	res, err := Bootstrap(o)
	if err != nil {
		t.Fatal(err)
	}
	if res.CreatedCA || res.Server != ActionReissued || res.Clients["a"] != ActionReissued {
		t.Fatalf("force result = %+v", res)
	}
	after := readAll(t, dir)
	for _, name := range []string{CAFileName, CAKeyFileName, ClientCertFileName("b"), ClientKeyFileName("b")} {
		if before[name] != after[name] {
			t.Errorf("%s changed under --force", name)
		}
	}
	for _, name := range []string{ServerCertFileName, ServerKeyFileName, ClientCertFileName("a"), ClientKeyFileName("a")} {
		if before[name] == after[name] {
			t.Errorf("%s not reissued", name)
		}
	}
	for name := range after {
		if strings.Contains(name, "bootstrap") {
			t.Errorf("leftover %s", name)
		}
	}
}

func TestBootstrapWithoutForceRefusesStaleLeaf(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	if _, err := Bootstrap(opts(dir, "a")); err != nil {
		t.Fatal(err)
	}
	before := readAll(t, dir)

	o := opts(dir, "a")
	o.ServerNames = []string{"sockguard.internal", "127.0.0.1", "other.example"}
	if _, err := Bootstrap(o); err == nil || !strings.Contains(err.Error(), "other.example") || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("err = %v", err)
	}
	if !equalMaps(before, readAll(t, dir)) {
		t.Error("refused run changed files")
	}

	// A leaf from a different CA is refused as well.
	other := filepath.Join(t.TempDir(), "other")
	if _, err := Bootstrap(opts(other, "a")); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{ClientCertFileName("a"), ClientKeyFileName("a")} {
		b, _ := os.ReadFile(filepath.Join(other, n))
		_ = os.WriteFile(filepath.Join(dir, n), b, 0o600)
	}
	if _, err := Bootstrap(opts(dir, "a")); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("foreign leaf err = %v", err)
	}
}

func TestBootstrapExpiringLeafNeedsForce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	if _, err := Bootstrap(opts(dir, "a")); err != nil {
		t.Fatal(err)
	}
	real := now
	now = func() time.Time { return real().Add(340 * 24 * time.Hour) }
	defer func() { now = real }()
	if _, err := Bootstrap(opts(dir, "a")); err == nil || !strings.Contains(err.Error(), "expires") {
		t.Fatalf("err = %v", err)
	}
}

func TestBootstrapHalfCAFails(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	if _, err := Bootstrap(opts(dir, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, CAKeyFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := Bootstrap(opts(dir, "a")); err == nil || !strings.Contains(err.Error(), "must exist together") {
		t.Fatalf("err = %v", err)
	}
}

func TestBootstrapFailureMidWayLeavesNothing(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "pki")
	real := writeStep
	calls := 0
	writeStep = func(f *os.File, data []byte) error {
		calls++
		if calls == 5 {
			return errors.New("disk full")
		}
		return real(f, data)
	}
	defer func() { writeStep = real }()

	if _, err := Bootstrap(opts(dir, "a")); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		entries, _ := os.ReadDir(dir)
		t.Fatalf("dir left behind: %v %v", err, entries)
	}
}

func TestBootstrapFailureOnExistingDirLeavesItUntouched(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	if _, err := Bootstrap(opts(dir, "a")); err != nil {
		t.Fatal(err)
	}
	before := readAll(t, dir)

	real := writeStep
	calls := 0
	writeStep = func(f *os.File, data []byte) error {
		calls++
		if calls == 3 {
			return errors.New("disk full")
		}
		return real(f, data)
	}
	defer func() { writeStep = real }()

	o := opts(dir, "a", "b", "c")
	if _, err := Bootstrap(o); err == nil {
		t.Fatal("expected failure")
	}
	if after := readAll(t, dir); !equalMaps(before, after) {
		t.Errorf("files changed after failed run: before %d after %d", len(before), len(after))
	}

	// Same through a failed replace under --force.
	calls = 0
	o = opts(dir, "a")
	o.Force = true
	if _, err := Bootstrap(o); err == nil {
		t.Fatal("expected failure")
	}
	if after := readAll(t, dir); !equalMaps(before, after) {
		t.Errorf("force failure changed files")
	}
}

func TestBootstrapInputValidation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	cases := map[string]Options{
		"no dir":       {ServerNames: []string{"a"}, Clients: []string{"c"}},
		"no server":    {Dir: dir, Clients: []string{"c"}},
		"no client":    {Dir: dir, ServerNames: []string{"a"}},
		"bad client":   {Dir: dir, ServerNames: []string{"a"}, Clients: []string{"Bad_Name"}},
		"path client":  {Dir: dir, ServerNames: []string{"a"}, Clients: []string{"../x"}},
		"bad server":   {Dir: dir, ServerNames: []string{"not a host"}, Clients: []string{"c"}},
		"empty server": {Dir: dir, ServerNames: []string{" "}, Clients: []string{"c"}},
	}
	for name, o := range cases {
		if _, err := Bootstrap(o); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("validation failure created the dir")
	}
}
