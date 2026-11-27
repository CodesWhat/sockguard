// Package podmanspec holds the test helpers that derive a Podman request-body
// field set from Podman's own Go source: fetch a file at a ref, parse its
// struct declarations with go/ast, and flatten the embedded structs the way
// encoding/json does. The libpod drift tests in internal/filter and
// internal/ownership share it.
package podmanspec

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// RefEnvVar names the containers/podman ref (a tag such as v6.2.0, or main) the
// upstream drift tests fetch. Unset, those tests skip and the suite stays
// offline.
const RefEnvVar = "SOCKGUARD_TEST_PODMAN_UPSTREAM_REF"

// FetchTimeout bounds one upstream drift test's network work.
const FetchTimeout = 90 * time.Second

// maxSourceBytes bounds one fetched file. Podman's containers.go is the
// largest of them at well under a megabyte.
const maxSourceBytes = 4 << 20

// UpstreamRef returns the ref named by RefEnvVar, or "" when it is unset.
func UpstreamRef() string {
	return strings.TrimSpace(os.Getenv(RefEnvVar))
}

// FetchSource downloads one file from raw.githubusercontent.com.
func FetchSource(ctx context.Context, t *testing.T, repo, ref, path string) []byte {
	t.Helper()

	url := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s", repo, ref, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request for %s: %v", url, err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %s (a moved or renamed file is itself upstream drift; confirm the path before editing this test)", url, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSourceBytes))
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	if len(body) == 0 {
		t.Fatalf("GET %s returned an empty body", url)
	}
	return body
}

// ParseStructs indexes every struct type declared in one Go source file by its
// name. The file is parsed, not type-checked, so it needs none of the packages
// it imports.
func ParseStructs(t *testing.T, src []byte) map[string]*ast.StructType {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "upstream.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse upstream source: %v", err)
	}

	structs := map[string]*ast.StructType{}
	for _, decl := range file.Decls {
		generic, ok := decl.(*ast.GenDecl)
		if !ok || generic.Tok != token.TYPE {
			continue
		}
		for _, spec := range generic.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			if structType, ok := typeSpec.Type.(*ast.StructType); ok {
				structs[typeSpec.Name.Name] = structType
			}
		}
	}
	return structs
}

// FlattenRootFields collects the wire keys a struct contributes to the JSON
// object root, following encoding/json's rules: an anonymous field with no
// json name is flattened into the parent, a named field uses its json name
// or, with no tag, its Go name, and `json:"-"` contributes nothing. Two fields
// resolving to the same key collapse into one entry, which is what happens on
// the wire too.
//
// An embedded type that is not in owners fails the test when it is exported:
// the upstream layout changed and the caller's file list needs extending. An
// unexported one contributes nothing, because encoding/json only promotes
// exported fields and an unexported helper type (Podman's cacheLibImage) holds
// none.
func FlattenRootFields(t *testing.T, typeName string, owners map[string]*ast.StructType, visiting map[string]bool, out map[string]struct{}) {
	t.Helper()

	declared, ok := owners[typeName]
	if !ok {
		t.Fatalf("an embedded struct names %s, which is not one of the upstream files this test fetches; Podman has restructured the request body and this test needs its file list extended before the snapshot can be trusted", typeName)
	}
	if visiting[typeName] {
		t.Fatalf("embedded type cycle through %s", typeName)
	}
	visiting[typeName] = true
	defer delete(visiting, typeName)

	for _, field := range declared.Fields.List {
		name, skip := jsonFieldName(field.Tag)
		if skip {
			continue
		}

		if len(field.Names) == 0 {
			if name != "" {
				// A named embedded field nests rather than flattens.
				out[name] = struct{}{}
				continue
			}
			embedded := embeddedTypeName(field.Type)
			if embedded == "" {
				t.Fatalf("cannot resolve the type of an embedded field in %s", typeName)
			}
			if _, known := owners[embedded]; !known && !ast.IsExported(embedded) {
				continue
			}
			FlattenRootFields(t, embedded, owners, visiting, out)
			continue
		}

		for _, ident := range field.Names {
			if !ident.IsExported() {
				continue
			}
			key := name
			if key == "" {
				key = ident.Name
			}
			out[key] = struct{}{}
		}
	}
}

func jsonFieldName(tag *ast.BasicLit) (string, bool) {
	if tag == nil {
		return "", false
	}
	unquoted, err := strconv.Unquote(tag.Value)
	if err != nil {
		return "", false
	}
	value, ok := reflect.StructTag(unquoted).Lookup("json")
	if !ok {
		return "", false
	}
	if value == "-" {
		return "", true
	}
	name, _, _ := strings.Cut(value, ",")
	return name, false
}

func embeddedTypeName(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	case *ast.StarExpr:
		return embeddedTypeName(typed.X)
	}
	return ""
}

// RuntimeSpecVersion reads the runtime-spec version out of Podman's go.mod, so
// the OCI half of a field set is checked at the version Podman actually
// builds against rather than one the test guesses. It refuses a go.mod that
// names the module at two versions, which is what a replace directive would
// look like here.
func RuntimeSpecVersion(t *testing.T, gomod []byte) string {
	t.Helper()

	const module = "github.com/opencontainers/runtime-spec"
	version := ""
	for _, line := range strings.Split(string(gomod), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != module || !strings.HasPrefix(fields[1], "v") {
			continue
		}
		if version != "" && version != fields[1] {
			t.Fatalf("podman go.mod names %s at both %s and %s; resolve which one the build uses before trusting the OCI field set", module, version, fields[1])
		}
		version = fields[1]
	}
	if version == "" {
		t.Fatalf("podman go.mod does not require %s", module)
	}
	return version
}

// SetDifference returns the values of from that are not in remove.
func SetDifference(from, remove []string) []string {
	var diff []string
	for _, value := range from {
		if !slices.Contains(remove, value) {
			diff = append(diff, value)
		}
	}
	return diff
}

// JoinOrNone joins values with commas, or says "(none)".
func JoinOrNone(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, ", ")
}

// FormatRootFields renders a sorted field list as the root_fields entry of a
// snapshot file, ready to paste.
func FormatRootFields(fields []string) string {
	quoted := make([]string, 0, len(fields))
	for _, field := range fields {
		quoted = append(quoted, "    "+strconv.Quote(field))
	}
	return "  \"root_fields\": [\n" + strings.Join(quoted, ",\n") + "\n  ]"
}

// DiffSorted compares a derived field set with a recorded one and reports
// whether they match, plus the sorted derived list and what moved each way.
func DiffSorted(derived map[string]struct{}, recorded []string) (upstream, added, removed []string, equal bool) {
	upstream = make([]string, 0, len(derived))
	for field := range derived {
		upstream = append(upstream, field)
	}
	slices.Sort(upstream)

	sortedRecorded := slices.Clone(recorded)
	slices.Sort(sortedRecorded)
	if slices.Equal(upstream, sortedRecorded) {
		return upstream, nil, nil, true
	}
	return upstream, SetDifference(upstream, sortedRecorded), SetDifference(sortedRecorded, upstream), false
}
