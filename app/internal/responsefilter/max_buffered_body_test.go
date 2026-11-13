package responsefilter

import (
	"errors"
	"io"
	"strings"
	"testing"

	requestfilter "github.com/codeswhat/sockguard/v3/app/internal/filter"
)

// These tests move the process-wide limit, so they stay serial and restore it.
func setLimitForTest(t *testing.T, n int64) {
	t.Helper()
	requestfilter.SetResponseBodyLimit(n)
	t.Cleanup(func() { requestfilter.SetResponseBodyLimit(0) })
}

func TestMaxBufferedBodyRejectsListOverConfiguredLimit(t *testing.T) {
	setLimitForTest(t, 1024)
	f := New(Options{RedactMountPaths: true})

	item := `{"Id":"abc","Names":["/c"],"Image":"alpine"}`
	body := "[" + strings.Repeat(item+",", 40) + item + "]"
	resp := newResponseForTest(t, "GET", "/v1.53/containers/json", body)

	err := f.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseTooLarge) || !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("ModifyResponse() error = %v, want ErrResponseTooLarge inside ErrResponseRejected", err)
	}
	if !strings.Contains(err.Error(), "response body exceeds 1024 bytes") {
		t.Fatalf("error %q should state the configured limit", err)
	}
}

func TestMaxBufferedBodyRejectsInspectOverConfiguredLimit(t *testing.T) {
	setLimitForTest(t, 1024)
	f := New(Options{RedactContainerEnv: true})
	body := `{"Config":{"Env":["` + strings.Repeat("A", 2048) + `"]}}`
	resp := newResponseForTest(t, "GET", "/v1.53/containers/abc123/json", body)
	if err := f.ModifyResponse(resp); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("ModifyResponse() error = %v, want ErrResponseTooLarge", err)
	}
}

func TestMaxBufferedBodyRaisedLimitAdmitsLargeList(t *testing.T) {
	setLimitForTest(t, 32<<20)
	f := New(Options{RedactMountPaths: true})

	// A list past the 8MiB default that the raised limit must now pass.
	item := `{"Id":"abc","Names":["/c"],"Image":"alpine","Labels":{"k":"` + strings.Repeat("v", 200) + `"}}`
	count := (requestfilter.MaxResponseBodyBytes / len(item)) + 1000
	body := "[" + strings.Repeat(item+",", count) + item + "]"
	if len(body) <= requestfilter.MaxResponseBodyBytes {
		t.Fatalf("test body is only %d bytes, want over the 8MiB default", len(body))
	}
	resp := newResponseForTest(t, "GET", "/v1.53/containers/json", body)
	if err := f.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse() with 32MiB limit: %v", err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("read filtered body: %v", err)
	}
}
