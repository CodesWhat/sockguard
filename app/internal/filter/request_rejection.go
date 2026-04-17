package filter

import "errors"

type requestRejectionError struct {
	status int
	reason string
}

func (e *requestRejectionError) Error() string {
	return e.reason
}

func newRequestRejectionError(status int, reason string) error {
	return &requestRejectionError{status: status, reason: reason}
}

func requestRejectionFromError(err error) (requestRejectionError, bool) {
	var target *requestRejectionError
	if !errors.As(err, &target) {
		return requestRejectionError{}, false
	}
	return *target, true
}
