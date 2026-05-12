// Package testhelp provides shared test utilities for the sockguard internal packages.
package testhelp

import (
	"testing"
	"time"
)

// Eventually polls ok every 10 ms until it returns true or a 2-second deadline
// elapses. It calls t.Fatal if the condition is not met in time.
func Eventually(t *testing.T, ok func() bool) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ok() {
		return
	}
	t.Fatal("condition was not met before timeout")
}
