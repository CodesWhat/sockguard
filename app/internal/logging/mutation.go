package logging

import "sync"

// mutation.go holds the logging-side record of one request's admission-
// mutation trace (#151). It intentionally duplicates the tiny outcome
// vocabulary filter's mutation engine also defines internally, rather than
// importing internal/filter here: the dependency between the two packages
// runs filter -> logging (filter already imports logging for RequestMeta),
// so logging cannot import filter back without a cycle. filter's
// recordMutationOutcome (internal/filter/mutation.go) is the only writer of
// these values.

// MutationRuleOutcome is one compiled admission-mutation rule's outcome for
// a single request.
type MutationRuleOutcome struct {
	// ID is the rule's configured id.
	ID string
	// Type is "inject_labels" or "remap_image".
	Type string
	// Mode is "enforce", "warn", or "audit".
	Mode string
	// Outcome is one of "applied", "noop", "would_apply", "would_noop", or
	// "failed".
	Outcome string
}

// MutationRecord is the pooled per-request admission-mutation trace attached
// to RequestMeta.Mutation. It is populated only when at least one mutation
// rule matched the request's surface; a request with no configured mutation
// rules for its surface never gets one attached.
type MutationRecord struct {
	Rules []MutationRuleOutcome
	// ActualChanged reports whether an enforce-mode rule actually rewrote
	// the committed request body.
	ActualChanged bool
	// HasWarnEvaluation reports whether at least one warn-mode rule was
	// evaluated against the shadow document, regardless of its outcome —
	// used to elevate the access log line to WARN even when the request
	// itself was allowed.
	HasWarnEvaluation bool
}

var mutationRecordPool = sync.Pool{
	New: func() any {
		return &MutationRecord{}
	},
}

// GetMutationRecord returns a pooled, zeroed MutationRecord.
func GetMutationRecord() *MutationRecord {
	rec, _ := mutationRecordPool.Get().(*MutationRecord)
	if rec == nil {
		return &MutationRecord{}
	}
	return rec
}

// PutMutationRecord returns rec to the pool after zeroing its fields,
// matching putRequestMeta's pattern for the RequestMeta it hangs off of.
func PutMutationRecord(rec *MutationRecord) {
	if rec == nil {
		return
	}
	rec.Rules = rec.Rules[:0]
	rec.ActualChanged = false
	rec.HasWarnEvaluation = false
	mutationRecordPool.Put(rec)
}
