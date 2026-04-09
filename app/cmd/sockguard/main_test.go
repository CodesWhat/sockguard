package main

import (
	"errors"
	"testing"
)

func TestMainSuccess(t *testing.T) {
	originalExecute := execute
	originalExit := exitProcess
	t.Cleanup(func() {
		execute = originalExecute
		exitProcess = originalExit
	})

	called := false
	execute = func() error {
		called = true
		return nil
	}
	exitProcess = func(code int) {
		t.Fatalf("exitProcess(%d) should not be called", code)
	}

	main()

	if !called {
		t.Fatal("expected execute to be called")
	}
}

func TestMainFailureExits(t *testing.T) {
	originalExecute := execute
	originalExit := exitProcess
	t.Cleanup(func() {
		execute = originalExecute
		exitProcess = originalExit
	})

	execute = func() error { return errors.New("boom") }

	var exitCode int
	exitProcess = func(code int) {
		exitCode = code
	}

	main()

	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
}
