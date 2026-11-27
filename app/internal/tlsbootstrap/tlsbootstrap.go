// Package tlsbootstrap provisions the certificate material for sockguard's
// mutual-TLS listener: one CA, one server certificate and one client
// certificate per named client. It is stdlib-only and never runs on the
// request path.
//
// The identity binding is fixed: each client certificate carries the client
// name as its Subject CommonName and as its only DNS SAN, so
// clients.client_certificate_profiles can select it with common_names (or
// dns_names) and the selected profile's ownership.owner scopes its resources.
package tlsbootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	CAFileName         = "ca.pem"
	CAKeyFileName      = "ca-key.pem"
	ServerCertFileName = "server-cert.pem"
	ServerKeyFileName  = "server-key.pem"

	caValidity   = 10 * 365 * 24 * time.Hour
	leafValidity = 365 * 24 * time.Hour
	// renewWindow is how close to expiry an existing certificate may be
	// before a rerun refuses to reuse it.
	renewWindow = 30 * 24 * time.Hour
	clockSkew   = time.Hour

	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600
)

var clientNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$`)

// ClientCertFileName returns the certificate file name for a client.
func ClientCertFileName(name string) string { return "client-" + name + ".pem" }

// ClientKeyFileName returns the private key file name for a client.
func ClientKeyFileName(name string) string { return "client-" + name + "-key.pem" }

// Options selects what Bootstrap provisions.
type Options struct {
	Dir         string
	ServerNames []string
	Clients     []string
	Force       bool
}

// Result lists what a run did, for reporting.
type Result struct {
	Dir          string
	CreatedCA    bool
	Server       Action
	Clients      map[string]Action
	ClientNames  []string
	ServerNames  []string
	CAFile       string
	ServerCert   string
	ServerKey    string
	ClientFiles  map[string][2]string
	CreatedFiles []string
}

// Action says what happened to one certificate.
type Action string

const (
	ActionCreated  Action = "created"
	ActionReused   Action = "reused"
	ActionReissued Action = "reissued"
)

// hooks swapped by tests.
var (
	now       = time.Now
	writeStep = func(f *os.File, data []byte) error { _, err := f.Write(data); return err }
)

type file struct {
	name string
	data []byte
}

// Bootstrap provisions Dir. It generates everything in memory first, stages
// every file as a temp file in Dir, and only then renames them into place, so
// a failure leaves the directory as it was found.
func Bootstrap(opts Options) (*Result, error) {
	if opts.Dir == "" {
		return nil, errors.New("--dir is required")
	}
	if len(opts.ServerNames) == 0 {
		return nil, errors.New("at least one --server-name is required")
	}
	if len(opts.Clients) == 0 {
		return nil, errors.New("at least one --client is required")
	}
	serverNames, dnsNames, ips, err := normalizeServerNames(opts.ServerNames)
	if err != nil {
		return nil, err
	}
	clients, err := normalizeClients(opts.Clients)
	if err != nil {
		return nil, err
	}
	dir, err := filepath.Abs(opts.Dir)
	if err != nil {
		return nil, fmt.Errorf("resolve --dir: %w", err)
	}
	created, err := prepareDir(dir)
	if err != nil {
		return nil, err
	}

	res := &Result{
		Dir: dir, Clients: map[string]Action{}, ClientFiles: map[string][2]string{},
		ClientNames: clients, ServerNames: serverNames,
		CAFile: filepath.Join(dir, CAFileName), ServerCert: filepath.Join(dir, ServerCertFileName),
		ServerKey: filepath.Join(dir, ServerKeyFileName),
	}
	var out []file

	ca, caFiles, createdCA, err := loadOrCreateCA(dir)
	if err != nil {
		return nil, cleanupDir(dir, created, err)
	}
	res.CreatedCA = createdCA
	out = append(out, caFiles...)

	serverFiles, serverAction, err := ensureLeaf(dir, ca, leafSpec{
		certName: ServerCertFileName, keyName: ServerKeyFileName,
		commonName: serverNames[0], dns: dnsNames, ips: ips, usage: x509.ExtKeyUsageServerAuth,
		label: "server certificate",
	}, opts.Force)
	if err != nil {
		return nil, cleanupDir(dir, created, err)
	}
	res.Server = serverAction
	out = append(out, serverFiles...)

	for _, name := range clients {
		if err := refuseExistingFileNameCollision(dir, name); err != nil {
			return nil, cleanupDir(dir, created, err)
		}
		files, action, err := ensureLeaf(dir, ca, leafSpec{
			certName: ClientCertFileName(name), keyName: ClientKeyFileName(name),
			commonName: name, dns: []string{name}, usage: x509.ExtKeyUsageClientAuth,
			label: fmt.Sprintf("client %q certificate", name),
		}, opts.Force)
		if err != nil {
			return nil, cleanupDir(dir, created, err)
		}
		res.Clients[name] = action
		res.ClientFiles[name] = [2]string{filepath.Join(dir, ClientCertFileName(name)), filepath.Join(dir, ClientKeyFileName(name))}
		out = append(out, files...)
	}

	if err := commit(dir, out); err != nil {
		return nil, cleanupDir(dir, created, err)
	}
	for _, f := range out {
		res.CreatedFiles = append(res.CreatedFiles, filepath.Join(dir, f.name))
	}
	return res, nil
}

func cleanupDir(dir string, created bool, cause error) error {
	if created {
		_ = os.Remove(dir) // only succeeds when empty
	}
	return cause
}

func normalizeServerNames(in []string) (all, dns []string, ips []net.IP, err error) {
	seen := map[string]bool{}
	for _, raw := range in {
		n := strings.TrimSpace(raw)
		if n == "" {
			return nil, nil, nil, errors.New("--server-name must not be empty")
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		} else if validHostname(n) {
			dns = append(dns, n)
		} else {
			return nil, nil, nil, fmt.Errorf("--server-name %q is neither an IP address nor a valid DNS name", n)
		}
		all = append(all, n)
	}
	return all, dns, ips, nil
}

func validHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func normalizeClients(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, n := range in {
		if !clientNamePattern.MatchString(n) {
			return nil, fmt.Errorf("--client %q is invalid: use lowercase letters, digits, '.' and '-' (1 to 63 characters, starting and ending alphanumeric)", n)
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	if err := rejectFileNameCollisions(out); err != nil {
		return nil, err
	}
	return out, nil
}

// rejectFileNameCollisions refuses client names whose derived files land on
// the same path. Client X's key file (client-X-key.pem) is the certificate
// file of client "X-key", so provisioning both would overwrite X's private key
// with the other client's certificate and report success for both. names is
// sorted, so the message is deterministic.
func rejectFileNameCollisions(names []string) error {
	owner := make(map[string]string, 2*len(names))
	for _, n := range names {
		for _, f := range []string{ClientCertFileName(n), ClientKeyFileName(n)} {
			if other, ok := owner[f]; ok && other != n {
				return fmt.Errorf("--client %q and --client %q collide: both would write %s; rename one of them", other, n, f)
			}
			owner[f] = n
		}
	}
	return nil
}

// refuseExistingFileNameCollision is the cross-run half of
// rejectFileNameCollisions: a client whose certificate file is the private key
// file of an already provisioned client, or whose key file is the certificate
// file of one, is refused. --force does not override it, since reissuing would
// destroy the other client's key or certificate.
func refuseExistingFileNameCollision(dir, name string) error {
	if base, ok := strings.CutSuffix(name, "-key"); ok && base != "" {
		exists, err := fileExists(filepath.Join(dir, ClientCertFileName(base)))
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("client %q: %s is the private key file of existing client %q; choose another name", name, ClientCertFileName(name), base)
		}
	}
	exists, err := fileExists(filepath.Join(dir, ClientKeyFileName(name+"-key")))
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("client %q: %s is the certificate file of existing client %q; choose another name", name, ClientKeyFileName(name), name+"-key")
	}
	return nil
}

func fileExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("check %s: %w", path, err)
	}
}

// prepareDir creates dir with mode 0700, or checks an existing one. An
// existing directory that group or others can reach is refused rather than
// silently chmod-ed: the operator may have put it there for another reason,
// and keys may already have been exposed in it.
func prepareDir(dir string) (created bool, err error) {
	info, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil { // #nosec G301 -- parent of the key directory, not the key directory itself.
			return false, fmt.Errorf("create parent of %s: %w", dir, err)
		}
		if err := os.Mkdir(dir, dirMode); err != nil {
			return false, fmt.Errorf("create %s: %w", dir, err)
		}
		// Mkdir is subject to the umask; make the mode exact.
		if err := os.Chmod(dir, dirMode); err != nil {
			return true, cleanupDir(dir, true, fmt.Errorf("chmod %s: %w", dir, err))
		}
		return true, nil
	case err != nil:
		return false, fmt.Errorf("stat %s: %w", dir, err)
	case info.Mode()&os.ModeSymlink != 0:
		return false, fmt.Errorf("%s is a symlink; point --dir at the real directory", dir)
	case !info.IsDir():
		return false, fmt.Errorf("%s exists and is not a directory", dir)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return false, fmt.Errorf("%s has mode %04o, looser than 0700; run chmod 700 on it (or use a new directory) and rerun", dir, info.Mode().Perm())
	}
	return false, nil
}

type issued struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func randSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func loadOrCreateCA(dir string) (*issued, []file, bool, error) {
	certPath, keyPath := filepath.Join(dir, CAFileName), filepath.Join(dir, CAKeyFileName)
	certData, certErr := os.ReadFile(certPath) // #nosec G304 -- fixed file name under the operator-chosen directory.
	keyData, keyErr := os.ReadFile(keyPath)    // #nosec G304 -- same.
	switch {
	case certErr == nil && keyErr == nil:
		ca, err := parsePair(certData, keyData)
		if err != nil {
			return nil, nil, false, fmt.Errorf("existing CA in %s is unusable: %w", dir, err)
		}
		if !ca.cert.IsCA {
			return nil, nil, false, fmt.Errorf("existing %s is not a CA certificate", CAFileName)
		}
		if !now().Before(ca.cert.NotAfter.Add(-renewWindow)) {
			return nil, nil, false, fmt.Errorf("existing CA expires %s; rotate it by moving %s and %s aside, which reissues every certificate", ca.cert.NotAfter.Format(time.DateOnly), CAFileName, CAKeyFileName)
		}
		return ca, nil, false, nil
	case errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist):
	case certErr == nil || keyErr == nil:
		return nil, nil, false, fmt.Errorf("%s and %s must exist together; found only one in %s", CAFileName, CAKeyFileName, dir)
	default:
		return nil, nil, false, fmt.Errorf("read CA: %w", errors.Join(certErr, keyErr))
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, false, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, nil, false, err
	}
	t := now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "sockguard mTLS CA", Organization: []string{"sockguard"}},
		NotBefore:             t.Add(-clockSkew),
		NotAfter:              t.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, false, fmt.Errorf("create CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, false, err
	}
	files, err := encodePair(CAFileName, CAKeyFileName, der, key)
	if err != nil {
		return nil, nil, false, err
	}
	return &issued{cert, key}, files, true, nil
}

type leafSpec struct {
	certName, keyName, commonName, label string
	dns                                  []string
	ips                                  []net.IP
	usage                                x509.ExtKeyUsage
}

// ensureLeaf reuses a valid existing leaf, issues a new one when none exists,
// and refuses to touch a stale or mismatched one without force.
func ensureLeaf(dir string, ca *issued, spec leafSpec, force bool) ([]file, Action, error) {
	certPath, keyPath := filepath.Join(dir, spec.certName), filepath.Join(dir, spec.keyName)
	certData, certErr := os.ReadFile(certPath) // #nosec G304 -- fixed names under the operator-chosen directory.
	keyData, keyErr := os.ReadFile(keyPath)    // #nosec G304 -- same.
	exists := certErr == nil || keyErr == nil
	if exists && !force {
		if certErr != nil || keyErr != nil {
			return nil, "", fmt.Errorf("%s: %s and %s must exist together; found only one (use --force to reissue)", spec.label, spec.certName, spec.keyName)
		}
		if problem := checkLeaf(certData, keyData, ca, spec); problem != "" {
			return nil, "", fmt.Errorf("existing %s (%s) %s; use --force to reissue it", spec.label, spec.certName, problem)
		}
		return nil, ActionReused, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate %s key: %w", spec.label, err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, "", err
	}
	t := now()
	notAfter := t.Add(leafValidity)
	if notAfter.After(ca.cert.NotAfter) {
		notAfter = ca.cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: spec.commonName},
		DNSNames:              spec.dns,
		IPAddresses:           spec.ips,
		NotBefore:             t.Add(-clockSkew),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{spec.usage},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, "", fmt.Errorf("create %s: %w", spec.label, err)
	}
	files, err := encodePair(spec.certName, spec.keyName, der, key)
	if err != nil {
		return nil, "", err
	}
	if exists {
		return files, ActionReissued, nil
	}
	return files, ActionCreated, nil
}

// checkLeaf returns a short reason the existing pair can't be reused, or "".
func checkLeaf(certData, keyData []byte, ca *issued, spec leafSpec) string {
	pair, err := parsePair(certData, keyData)
	if err != nil {
		return "is unreadable or its key does not match (" + err.Error() + ")"
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	if _, err := pair.cert.Verify(x509.VerifyOptions{
		Roots: pool, KeyUsages: []x509.ExtKeyUsage{spec.usage}, CurrentTime: now(),
	}); err != nil {
		return "does not verify against the CA in this directory (" + err.Error() + ")"
	}
	if !now().Before(pair.cert.NotAfter.Add(-renewWindow)) {
		return "expires " + pair.cert.NotAfter.Format(time.DateOnly)
	}
	if pair.cert.Subject.CommonName != spec.commonName {
		return fmt.Sprintf("has CommonName %q, want %q", pair.cert.Subject.CommonName, spec.commonName)
	}
	have := map[string]bool{}
	for _, d := range pair.cert.DNSNames {
		have[d] = true
	}
	for _, d := range spec.dns {
		if !have[d] {
			return fmt.Sprintf("does not cover DNS name %q", d)
		}
	}
	for _, ip := range spec.ips {
		ok := false
		for _, h := range pair.cert.IPAddresses {
			ok = ok || h.Equal(ip)
		}
		if !ok {
			return fmt.Sprintf("does not cover IP %s", ip)
		}
	}
	return ""
}

func parsePair(certPEM, keyPEM []byte) (*issued, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, errors.New("no CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("no private key PEM block")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("private key does not match certificate")
	}
	return &issued{cert, key}, nil
}

func encodePair(certName, keyName string, der []byte, key *ecdsa.PrivateKey) ([]file, error) {
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	return []file{
		{certName, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})},
		{keyName, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})},
	}, nil
}

// commit stages every file as a 0600 temp file, then renames them into place.
// Files being replaced are first moved aside and restored if anything fails.
func commit(dir string, files []file) error {
	if len(files) == 0 {
		return nil
	}
	// Two entries on one path would stage both and let the later rename
	// overwrite the earlier one while reporting success for each.
	seenNames := make(map[string]struct{}, len(files))
	for _, f := range files {
		if _, dup := seenNames[f.name]; dup {
			return fmt.Errorf("internal error: duplicate output file %s", f.name)
		}
		seenNames[f.name] = struct{}{}
	}
	type staged struct{ tmp, final, backup string }
	var steps []staged
	var renamed []staged
	cleanup := func() {
		for _, s := range steps {
			_ = os.Remove(s.tmp)
		}
	}
	rollback := func() {
		for i := len(renamed) - 1; i >= 0; i-- {
			s := renamed[i]
			_ = os.Remove(s.final)
			if s.backup != "" {
				_ = os.Rename(s.backup, s.final)
			}
		}
		cleanup()
	}

	for _, f := range files {
		tmp, err := os.CreateTemp(dir, ".bootstrap-*.tmp")
		if err != nil {
			cleanup()
			return fmt.Errorf("stage %s: %w", f.name, err)
		}
		s := staged{tmp: tmp.Name(), final: filepath.Join(dir, f.name)}
		steps = append(steps, s)
		if err := tmp.Chmod(fileMode); err != nil {
			_ = tmp.Close()
			cleanup()
			return fmt.Errorf("stage %s: %w", f.name, err)
		}
		if err := writeStep(tmp, f.data); err != nil {
			_ = tmp.Close()
			cleanup()
			return fmt.Errorf("write %s: %w", f.name, err)
		}
		if err := tmp.Sync(); err != nil {
			_ = tmp.Close()
			cleanup()
			return fmt.Errorf("sync %s: %w", f.name, err)
		}
		if err := tmp.Close(); err != nil {
			cleanup()
			return fmt.Errorf("close %s: %w", f.name, err)
		}
	}

	var backups []string
	for i := range steps {
		s := &steps[i]
		if _, err := os.Lstat(s.final); err == nil {
			s.backup = s.final + ".bootstrap-old"
			if err := os.Rename(s.final, s.backup); err != nil {
				rollback()
				return fmt.Errorf("replace %s: %w", filepath.Base(s.final), err)
			}
			backups = append(backups, s.backup)
			renamed = append(renamed, *s)
		}
		if err := os.Rename(s.tmp, s.final); err != nil {
			rollback()
			return fmt.Errorf("install %s: %w", filepath.Base(s.final), err)
		}
		if s.backup == "" {
			renamed = append(renamed, *s)
		} else {
			renamed[len(renamed)-1] = *s
		}
	}
	for _, b := range backups {
		_ = os.Remove(b)
	}
	return nil
}
