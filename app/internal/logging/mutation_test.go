package logging

import (
	"runtime"
	"testing"
)

func TestMutationRecordPoolZeroesAllFields(t *testing.T) {
	rec := GetMutationRecord()
	rec.Rules = append(rec.Rules, MutationRuleOutcome{ID: "secret-rule", Type: "remap_image", Mode: "warn", Outcome: "failed"})
	rec.ActualChanged = true
	rec.HasWarnEvaluation = true
	PutMutationRecord(rec)

	reused := GetMutationRecord()
	t.Cleanup(func() { PutMutationRecord(reused) })
	if len(reused.Rules) != 0 || reused.ActualChanged || reused.HasWarnEvaluation {
		t.Fatalf("reused MutationRecord = %#v, want fully zeroed pooled record", reused)
	}
}

func TestAuditMutationRecordIsDeepCopyOfPooledRecord(t *testing.T) {
	rec := &MutationRecord{
		Rules: []MutationRuleOutcome{
			{ID: "rule-a", Type: "inject_labels", Mode: "enforce", Outcome: "applied"},
			{ID: "rule-b", Type: "remap_image", Mode: "audit", Outcome: "would_noop"},
		},
		ActualChanged: true,
	}
	audit := newAuditMutationRecord(rec)
	if audit == nil {
		t.Fatal("newAuditMutationRecord() = nil, want record")
	}

	rec.Rules[0].ID = "reused-secret"
	rec.Rules[1].Outcome = "failed"
	rec.Rules = rec.Rules[:0]
	rec.ActualChanged = false

	if len(audit.Rules) != 2 {
		t.Fatalf("audit rules length = %d, want 2", len(audit.Rules))
	}
	if audit.Rules[0].ID != "rule-a" || audit.Rules[1].Outcome != "would_noop" || !audit.ActualChanged {
		t.Fatalf("audit mutation record changed with pooled source: %#v", audit)
	}
}

func TestAuditMutationRecordOmitsNilAndEmptyRecords(t *testing.T) {
	if got := newAuditMutationRecord(nil); got != nil {
		t.Fatalf("newAuditMutationRecord(nil) = %#v, want nil", got)
	}
	if got := newAuditMutationRecord(&MutationRecord{}); got != nil {
		t.Fatalf("newAuditMutationRecord(empty) = %#v, want nil", got)
	}
}

func TestGetMutationRecordFallsBackWhenPoolReturnsWrongType(t *testing.T) {
	// Mirrors TestRequestMetaPoolFallbackWhenPoolReturnsWrongType's pattern
	// for requestMetaPool: override New too (not just Put a wrong-typed
	// value), since sync.Pool.Get() may satisfy the call from an internal
	// victim cache rather than the value most recently Put, and New is what
	// actually runs when the pool has nothing else to offer. Together these
	// force mutationRecordPool.Get()'s type assertion to fail, exercising
	// GetMutationRecord's defensive nil-fallback branch — otherwise
	// unreachable, since New always returns *MutationRecord.
	//
	// Drain first: an earlier test's PutMutationRecord may have already left
	// a real *MutationRecord sitting in this P's private pool slot, which
	// Get() would return ahead of the poisoned value below (Put appends to
	// the shared list, not private, when private is already occupied).
	for i := 0; i < 2*runtime.GOMAXPROCS(0)+4; i++ {
		mutationRecordPool.Get()
	}

	wrong := new(int)
	originalNew := mutationRecordPool.New
	mutationRecordPool.New = func() any { return wrong }
	t.Cleanup(func() {
		mutationRecordPool.New = originalNew
	})
	mutationRecordPool.Put(wrong)

	rec := GetMutationRecord()
	if rec == nil {
		t.Fatal("GetMutationRecord() = nil, want a usable fallback record")
	}
	if len(rec.Rules) != 0 || rec.ActualChanged || rec.HasWarnEvaluation {
		t.Fatalf("fallback record = %#v, want zero value", rec)
	}
}
