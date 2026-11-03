package filter

import "errors"

type requestRejectionError struct {
	status int
	reason string
	// reasonCode overrides requestRejectionReasonCode's status-derived
	// default when non-empty. Existing callers (e.g. the container-create/
	// service 413 body-too-large paths) leave this unset and keep exactly
	// today's status-derived code; the mutation engine sets it explicitly so
	// its four reason codes are distinguishable from the generic
	// request_body_* vocabulary even where the HTTP status overlaps (e.g.
	// mutation_request_too_large vs request_body_too_large, both 413).
	reasonCode string
	// hard marks a refusal that warn and audit rollout modes must not turn
	// into a pass-through, because forwarding the request would skip a
	// mandatory rewrite (an enforce-mode admission mutation).
	hard bool
}

func (e *requestRejectionError) Error() string {
	return e.reason
}

func newRequestRejectionError(status int, reason string) error {
	return &requestRejectionError{status: status, reason: reason}
}

// newRequestRejectionErrorWithCode is newRequestRejectionError plus an
// explicit reason code, for callers whose denial reason isn't adequately
// described by requestRejectionReasonCode's status-only mapping.
func newRequestRejectionErrorWithCode(status int, reasonCode, reason string) error {
	return &requestRejectionError{status: status, reason: reason, reasonCode: reasonCode}
}

// asHardRequestRejection returns err as a hard rejection when it is a
// requestRejectionError, and err unchanged otherwise.
func asHardRequestRejection(err error) error {
	rejection, ok := requestRejectionFromError(err)
	if !ok {
		return err
	}
	rejection.hard = true
	return &rejection
}

func requestRejectionFromError(err error) (requestRejectionError, bool) {
	var target *requestRejectionError
	if !errors.As(err, &target) {
		return requestRejectionError{}, false
	}
	return *target, true
}
