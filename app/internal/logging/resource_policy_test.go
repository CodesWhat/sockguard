package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"sync"
	"testing"
)

func TestResourcePolicyAccessLogFieldsForEveryEvaluatedResult(t *testing.T) {
	results := []struct {
		result    string
		violation string
	}{
		{result: "allow"},
		{result: "deny", violation: "memory"},
		{result: "would_deny", violation: "hard_cpu"},
		{result: "invalid"},
		{result: "lookup_failed"},
		{result: "state_changed"},
	}

	for _, tt := range results {
		t.Run(tt.result, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, nil))
			handler := AccessLogMiddleware(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				meta := MetaFromResponseWriter(w)
				if meta == nil {
					t.Fatal("request meta is nil")
				}
				meta.NormPath = "/containers/redacted/update"
				meta.ResourcePolicy = GetResourcePolicyMeta()
				*meta.ResourcePolicy = ResourcePolicyMeta{
					Evaluated:    true,
					Kind:         "container",
					Operation:    "update",
					StateSource:  "effective_state",
					Requirements: "memory,hard_cpu,pids",
					Result:       tt.result,
					Violation:    tt.violation,
					StateLookup:  true,
				}
				w.WriteHeader(http.StatusOK)
			}))

			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/containers/redacted/update", nil))

			var record map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record); err != nil {
				t.Fatalf("decode access log: %v\n%s", err, buf.String())
			}
			want := map[string]any{
				"resource_policy_evaluated":    true,
				"resource_policy_kind":         "container",
				"resource_policy_operation":    "update",
				"resource_policy_source":       "effective_state",
				"resource_policy_requirements": "memory,hard_cpu,pids",
				"resource_policy_result":       tt.result,
				"resource_policy_state_lookup": true,
			}
			for key, wantValue := range want {
				if got := record[key]; got != wantValue {
					t.Errorf("%s = %#v, want %#v; record=%#v", key, got, wantValue, record)
				}
			}
			if tt.violation == "" {
				if _, found := record["resource_policy_violation"]; found {
					t.Fatalf("resource_policy_violation unexpectedly present: %#v", record)
				}
			} else if got := record["resource_policy_violation"]; got != tt.violation {
				t.Fatalf("resource_policy_violation = %#v, want %q", got, tt.violation)
			}
		})
	}
}

func TestResourcePolicyAccessAndAuditFieldsAbsentWhenNotEvaluated(t *testing.T) {
	t.Run("access", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buf, nil))
		handler := AccessLogMiddleware(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			meta := MetaFromResponseWriter(w)
			meta.NormPath = "/_ping"
			w.WriteHeader(http.StatusOK)
		}))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/_ping", nil))

		var record map[string]any
		if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record); err != nil {
			t.Fatalf("decode access log: %v", err)
		}
		for key := range record {
			if len(key) >= len("resource_policy_") && key[:len("resource_policy_")] == "resource_policy_" {
				t.Fatalf("unexpected resource policy field %q in %#v", key, record)
			}
		}
	})

	t.Run("audit", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewAuditLogger(&buf)
		handler := AuditLogMiddleware(logger, AuditOptions{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/_ping", nil))
		if err := logger.Close(); err != nil {
			t.Fatalf("close audit logger: %v", err)
		}

		var event map[string]any
		if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &event); err != nil {
			t.Fatalf("decode audit event: %v", err)
		}
		if _, found := event["resource_policy"]; found {
			t.Fatalf("resource_policy unexpectedly present: %#v", event)
		}
	})
}

func TestResourcePolicyAuditFieldForEveryEvaluatedResult(t *testing.T) {
	for _, result := range []string{"allow", "deny", "would_deny", "invalid", "lookup_failed", "state_changed"} {
		t.Run(result, func(t *testing.T) {
			var buf bytes.Buffer
			logger := NewAuditLogger(&buf)
			handler := AuditLogMiddleware(logger, AuditOptions{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				meta := MetaFromResponseWriter(w)
				meta.ResourcePolicy = GetResourcePolicyMeta()
				*meta.ResourcePolicy = ResourcePolicyMeta{
					Evaluated:    true,
					Kind:         "service",
					Operation:    "manual_rollback",
					StateSource:  "previous_spec",
					Requirements: "hard_cpu",
					Result:       result,
					StateLookup:  true,
				}
				w.WriteHeader(http.StatusOK)
			}))
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/services/redacted/update", nil))
			if err := logger.Close(); err != nil {
				t.Fatalf("close audit logger: %v", err)
			}

			var event struct {
				ResourcePolicy *auditResourcePolicyContext `json:"resource_policy"`
			}
			if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &event); err != nil {
				t.Fatalf("decode audit event: %v", err)
			}
			if event.ResourcePolicy == nil || event.ResourcePolicy.Result != result {
				t.Fatalf("resource_policy = %#v, want result %q", event.ResourcePolicy, result)
			}
		})
	}
}

func TestResourcePolicyMetaPoolZeroesBeforeReuse(t *testing.T) {
	meta := GetResourcePolicyMeta()
	*meta = ResourcePolicyMeta{
		Evaluated:    true,
		Kind:         "service",
		Operation:    "manual_rollback",
		StateSource:  "previous_spec",
		Requirements: "hard_cpu",
		Result:       "deny",
		Violation:    "cpu",
		StateLookup:  true,
	}
	putResourcePolicyMeta(meta)

	if *meta != (ResourcePolicyMeta{}) {
		t.Fatalf("returned pooled metadata was not zeroed: %#v", *meta)
	}
	reused := GetResourcePolicyMeta()
	if *reused != (ResourcePolicyMeta{}) {
		t.Fatalf("metadata obtained for reuse was not zeroed: %#v", *reused)
	}
	putResourcePolicyMeta(reused)
}

// TestGetResourcePolicyMetaFallsBackWhenPoolReturnsWrongType mirrors
// TestGetMutationRecordFallsBackWhenPoolReturnsWrongType's pattern: drain
// the pool's per-P private slots, then poison both New and the shared list
// with a non-*ResourcePolicyMeta value, forcing GetResourcePolicyMeta's
// type assertion at resource_policy.go:55 to fail and exercising the
// defensive nil-fallback branch at line 56 -- otherwise unreachable, since
// New always returns *ResourcePolicyMeta.
func TestGetResourcePolicyMetaFallsBackWhenPoolReturnsWrongType(t *testing.T) {
	for i := 0; i < 2*runtime.GOMAXPROCS(0)+4; i++ {
		resourcePolicyMetaPool.Get()
	}

	wrong := new(int)
	originalNew := resourcePolicyMetaPool.New
	resourcePolicyMetaPool.New = func() any { return wrong }
	t.Cleanup(func() {
		resourcePolicyMetaPool.New = originalNew
	})
	resourcePolicyMetaPool.Put(wrong)

	meta := GetResourcePolicyMeta()
	if meta == nil {
		t.Fatal("GetResourcePolicyMeta() = nil, want a usable fallback value")
	}
	if *meta != (ResourcePolicyMeta{}) {
		t.Fatalf("fallback meta = %#v, want zero value", *meta)
	}
}

func TestAuditResourcePolicyDeepCopySurvivesConcurrentPoolReuse(t *testing.T) {
	meta := GetResourcePolicyMeta()
	*meta = ResourcePolicyMeta{
		Evaluated:    true,
		Kind:         "service",
		Operation:    "automatic_rollback",
		StateSource:  "current_spec",
		Requirements: "cpu,hard_cpu",
		Result:       "allow",
		StateLookup:  true,
	}

	auditCopy := auditResourcePolicyContextFrom(meta)
	if auditCopy == nil {
		t.Fatal("audit copy is nil")
	}
	putResourcePolicyMeta(meta)

	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				reused := GetResourcePolicyMeta()
				reused.Evaluated = true
				reused.Kind = "container"
				reused.Operation = "update"
				reused.StateSource = "effective_state"
				reused.Requirements = "memory"
				reused.Result = "deny"
				reused.Violation = "memory"
				reused.StateLookup = worker%2 == 0
				runtime.Gosched()
				putResourcePolicyMeta(reused)
			}
		}(worker)
	}
	wg.Wait()

	want := auditResourcePolicyContext{
		Kind:         "service",
		Operation:    "automatic_rollback",
		StateSource:  "current_spec",
		Requirements: "cpu,hard_cpu",
		Result:       "allow",
		StateLookup:  true,
	}
	if *auditCopy != want {
		t.Fatalf("audit copy changed during pooled reuse: got %#v want %#v", *auditCopy, want)
	}
}

func TestAuditResourcePolicyContextContainsOnlyBoundedClassifications(t *testing.T) {
	copy := auditResourcePolicyContextFrom(&ResourcePolicyMeta{
		Evaluated:    true,
		Kind:         "container",
		Operation:    "update",
		StateSource:  "effective_state",
		Requirements: "memory",
		Result:       "deny",
		Violation:    "memory",
		StateLookup:  true,
	})
	if copy == nil {
		t.Fatal("audit copy is nil")
	}
	wantSourceFields := []string{"Evaluated", "Kind", "Operation", "StateSource", "Requirements", "Result", "Violation", "StateLookup"}
	gotSourceFields := make([]string, 0, reflect.TypeOf(ResourcePolicyMeta{}).NumField())
	for i := 0; i < reflect.TypeOf(ResourcePolicyMeta{}).NumField(); i++ {
		gotSourceFields = append(gotSourceFields, reflect.TypeOf(ResourcePolicyMeta{}).Field(i).Name)
	}
	if !reflect.DeepEqual(gotSourceFields, wantSourceFields) {
		t.Fatalf("ResourcePolicyMeta fields = %v, want bounded classification fields %v", gotSourceFields, wantSourceFields)
	}
	wantAuditFields := []string{"Kind", "Operation", "StateSource", "Requirements", "Result", "Violation", "StateLookup"}
	gotAuditFields := make([]string, 0, reflect.TypeOf(*copy).NumField())
	for i := 0; i < reflect.TypeOf(*copy).NumField(); i++ {
		gotAuditFields = append(gotAuditFields, reflect.TypeOf(*copy).Field(i).Name)
	}
	if !reflect.DeepEqual(gotAuditFields, wantAuditFields) {
		t.Fatalf("audit resource-policy fields = %v, want bounded classification fields %v", gotAuditFields, wantAuditFields)
	}
}
