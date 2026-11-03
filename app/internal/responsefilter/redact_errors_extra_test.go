package responsefilter

import (
	"strings"
	"testing"
)

func TestTrailingJSONError(t *testing.T) {
	t.Parallel()
	body := []byte(`{"a":1}  x`)
	if err := trailingJSONError(body, 7); err == nil || !strings.Contains(err.Error(), "'x'") {
		t.Fatalf("trailing garbage err = %v, want an invalid character error", err)
	}
	if err := trailingJSONError([]byte("{}\n\t\r "), 2); err != nil {
		t.Fatalf("trailing whitespace err = %v, want nil", err)
	}
	if err := trailingJSONError(body, -1); err != nil {
		t.Fatalf("negative offset err = %v, want nil", err)
	}
	if err := trailingJSONError(body, int64(len(body))+1); err != nil {
		t.Fatalf("offset past the end err = %v, want nil", err)
	}
}

func TestRedactNestedValueIfPresentShapes(t *testing.T) {
	t.Parallel()
	payload := map[string]any{"Config": map[string]any{"Secrets": []any{"s"}}}
	if err := redactNestedValueIfPresent(payload, "Config", "Secrets", []any{}); err != nil {
		t.Fatalf("err = %v", err)
	}
	if got := payload["Config"].(map[string]any)["Secrets"].([]any); len(got) != 0 {
		t.Fatalf("Secrets = %v, want emptied", got)
	}
	// An absent field is not added.
	payload = map[string]any{"Config": map[string]any{}}
	if err := redactNestedValueIfPresent(payload, "Config", "Secrets", []any{}); err != nil {
		t.Fatalf("err = %v", err)
	}
	if _, added := payload["Config"].(map[string]any)["Secrets"]; added {
		t.Fatal("a field the daemon never sent was added")
	}
	for _, p := range []map[string]any{{}, {"Config": nil}} {
		if err := redactNestedValueIfPresent(p, "Config", "Secrets", []any{}); err != nil {
			t.Fatalf("absent/null object err = %v", err)
		}
	}
	if err := redactNestedValueIfPresent(map[string]any{"Config": "oops"}, "Config", "Secrets", []any{}); err == nil {
		t.Fatal("a non-object Config must error")
	}
}

func TestRedactBindMountObjectsShapes(t *testing.T) {
	t.Parallel()
	payload := map[string]any{"Mounts": []any{
		map[string]any{"Type": "bind", "Source": "/etc"},
		map[string]any{"Type": "volume", "Source": "data"},
		map[string]any{"Source": "/no/type"},
	}}
	if err := redactBindMountObjects(payload, "Mounts"); err != nil {
		t.Fatalf("err = %v", err)
	}
	mounts := payload["Mounts"].([]any)
	if mounts[0].(map[string]any)["Source"] == "/etc" || mounts[2].(map[string]any)["Source"] == "/no/type" {
		t.Fatal("bind or untyped mount source was not redacted")
	}
	if mounts[1].(map[string]any)["Source"] != "data" {
		t.Fatal("a volume name must be left alone")
	}
	if err := redactBindMountObjects(map[string]any{}, "Mounts"); err != nil {
		t.Fatalf("absent Mounts err = %v", err)
	}
	if err := redactBindMountObjects(map[string]any{"Mounts": "x"}, "Mounts"); err == nil {
		t.Fatal("non-array Mounts must error")
	}
	if err := redactBindMountObjects(map[string]any{"Mounts": []any{"x"}}, "Mounts"); err == nil {
		t.Fatal("non-object mount entry must error")
	}
}

func TestRedactFieldAnyShapeKinds(t *testing.T) {
	t.Parallel()
	payload := map[string]any{"a": "text", "b": []any{1}, "c": map[string]any{"k": 1}, "d": 5.0, "e": nil}
	for _, k := range []string{"a", "b", "c", "d", "e", "missing"} {
		redactFieldAnyShape(payload, k)
	}
	if payload["a"] == "text" {
		t.Fatal("string was not redacted")
	}
	if len(payload["b"].([]any)) != 0 || len(payload["c"].(map[string]any)) != 0 {
		t.Fatal("array/object were not emptied")
	}
	if payload["d"] != 5.0 {
		t.Fatal("numbers are left as they are")
	}
}
