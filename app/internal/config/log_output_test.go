package config

import (
	"reflect"
	"runtime"
	"testing"

	"github.com/codeswhat/sockguard/internal/logging"
)

func TestValidateLogOutputUsesLoggingValidateOutput(t *testing.T) {
	got := runtime.FuncForPC(reflect.ValueOf(validateLogOutput).Pointer()).Name()
	want := runtime.FuncForPC(reflect.ValueOf(logging.ValidateOutput).Pointer()).Name()

	if got != want {
		t.Fatalf("validateLogOutput = %s, want %s", got, want)
	}
}
