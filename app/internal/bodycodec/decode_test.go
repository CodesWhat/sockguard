package bodycodec

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// fuzzDecodeLimit bounds both the compressed input and the decoded output in
// the fuzz target below. It is far under the callers' 8 MiB so an expanding
// archive trips the cap in a single cheap iteration.
const fuzzDecodeLimit = 1 << 16

func gzipBytes(t *testing.T, body string) []byte {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(body)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func headerWithCoding(values ...string) http.Header {
	header := http.Header{}
	for _, value := range values {
		header.Add("Content-Encoding", value)
	}
	return header
}

// TestBytesDecodesGzip is the whole point: a caller holding a buffered
// compressed body gets the plaintext the policy walks.
func TestBytesDecodesGzip(t *testing.T) {
	t.Parallel()

	const plain = `[{"Names":["/web"],"Image":"nginx"}]`
	for _, coding := range []string{"gzip", "x-gzip", "GZIP", " gzip "} {
		t.Run(coding, func(t *testing.T) {
			t.Parallel()

			got, err := Bytes(headerWithCoding(coding), gzipBytes(t, plain), 1<<20)
			if err != nil {
				t.Fatalf("Bytes() error = %v, want nil", err)
			}
			if string(got) != plain {
				t.Fatalf("Bytes() = %q, want %q", got, plain)
			}
		})
	}
}

// TestBytesReturnsIdentityBodyUncopied pins the hot path. A real daemon never
// compresses, so the common case has to cost a header lookup and no copy.
func TestBytesReturnsIdentityBodyUncopied(t *testing.T) {
	t.Parallel()

	body := []byte(`[{"Names":["/web"]}]`)
	for _, header := range []http.Header{http.Header{}, headerWithCoding("identity"), headerWithCoding("IDENTITY"), headerWithCoding("")} {
		got, err := Bytes(header, body, 1<<20)
		if err != nil {
			t.Fatalf("Bytes(%v) error = %v, want nil", header, err)
		}
		if len(got) != len(body) || &got[0] != &body[0] {
			t.Fatalf("Bytes(%v) copied the identity body, want the caller's own slice back", header)
		}
	}
}

// TestBytesAllocatesNothingOnTheIdentityPath is the hot-path guard. Every
// filtered list response runs through Bytes, and a real daemon answers
// identity, so the pass-through has to allocate nothing at all. Building the
// bytes.Reader before the coding was checked put one 48-byte wrapper on every
// one of those responses for a value nothing on that path reads.
func TestBytesAllocatesNothingOnTheIdentityPath(t *testing.T) {
	body := []byte(`[{"Names":["/web"],"Image":"nginx"}]`)
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	header.Set("ETag", `"upstream"`)

	allocs := testing.AllocsPerRun(200, func() {
		if _, err := Bytes(header, body, 1<<20); err != nil {
			t.Fatalf("Bytes() error = %v, want nil", err)
		}
	})
	if allocs != 0 {
		t.Fatalf("Bytes() on the identity path allocated %v times, want 0", allocs)
	}
}

// TestBytesRejectsUnsupportedCoding keeps the fail-closed direction for the
// codings this package cannot decode, and pins that the refusal names the one
// it refused so an operator reading the log knows what the upstream sent.
func TestBytesRejectsUnsupportedCoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{name: "brotli", values: []string{"br"}, want: `"br"`},
		{name: "zstd", values: []string{"zstd"}, want: `"zstd"`},
		{name: "deflate", values: []string{"deflate"}, want: `"deflate"`},
		{name: "double gzip in one value", values: []string{"gzip, gzip"}, want: `"gzip, gzip"`},
		{name: "double gzip in two header lines", values: []string{"gzip", "gzip"}, want: `"gzip, gzip"`},
		{name: "gzip then identity", values: []string{"gzip", "identity"}, want: `"gzip, identity"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := Bytes(headerWithCoding(tt.values...), []byte("whatever"), 1<<20)
			if err == nil {
				t.Fatalf("Bytes() error = nil, want the coding refused")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want it to name the coding %s", err, tt.want)
			}
		})
	}
}

// TestBytesRejectsMalformedAndTruncatedGzip covers the header that claims gzip
// over bytes that are not one, and the stream that stops mid-way.
func TestBytesRejectsMalformedAndTruncatedGzip(t *testing.T) {
	t.Parallel()

	full := gzipBytes(t, `[{"Names":["/web"],"Image":"nginx"}]`)
	tests := []struct {
		name string
		body []byte
	}{
		{name: "not gzip at all", body: []byte(`[{"Names":["/web"]}]`)},
		{name: "empty body", body: nil},
		{name: "header only", body: full[:6]},
		{name: "truncated stream", body: full[:len(full)-4]},
		{name: "gzip magic then garbage", body: append([]byte{0x1f, 0x8b}, []byte("garbage")...)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := Bytes(headerWithCoding("gzip"), tt.body, 1<<20); err == nil {
				t.Fatalf("Bytes() error = nil, want the body refused")
			}
		})
	}
}

// TestBytesEnforcesDecodedSizeLimit is the gzip-bomb guard. The compressed
// bytes are well under the cap, so only the decoded size can trip it, and the
// refusal has to be ErrTooLarge rather than a generic decode failure because
// the callers map it to their own response-too-large verdict.
func TestBytesEnforcesDecodedSizeLimit(t *testing.T) {
	t.Parallel()

	const limit = 4096
	raw := gzipBytes(t, strings.Repeat("a", limit+1))
	if int64(len(raw)) > limit {
		t.Fatalf("compressed payload is %d bytes, want it under the cap so only the decoded size can trip it", len(raw))
	}

	if _, err := Bytes(headerWithCoding("gzip"), raw, limit); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Bytes() error = %v, want ErrTooLarge", err)
	}

	// A body of exactly the limit is kept: the cap is inclusive, the same way
	// the callers' own MaxResponseBodyBytes checks are.
	exact := gzipBytes(t, strings.Repeat("a", limit))
	got, err := Bytes(headerWithCoding("gzip"), exact, limit)
	if err != nil {
		t.Fatalf("Bytes() at exactly the limit error = %v, want nil", err)
	}
	if len(got) != limit {
		t.Fatalf("Bytes() decoded %d bytes, want %d", len(got), limit)
	}
}

// TestReaderMatchesBytes pins that the streaming entry point the response
// filter uses and the buffered one the two middlewares use decode the same
// input to the same output. They are one rule at two shapes, and a drift
// between them is what this package exists to prevent.
func TestReaderMatchesBytes(t *testing.T) {
	t.Parallel()

	const plain = `{"Id":"abc123"}`
	tests := []struct {
		name   string
		coding string
		body   []byte
	}{
		{name: "identity", coding: "", body: []byte(plain)},
		{name: "explicit identity", coding: "identity", body: []byte(plain)},
		{name: "gzip", coding: "gzip", body: gzipBytes(t, plain)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			header := headerWithCoding()
			if tt.coding != "" {
				header = headerWithCoding(tt.coding)
			}

			reader, err := Reader(header, bytes.NewReader(tt.body), 1<<20)
			if err != nil {
				t.Fatalf("Reader() error = %v, want nil", err)
			}
			streamed, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			buffered, err := Bytes(header, tt.body, 1<<20)
			if err != nil {
				t.Fatalf("Bytes() error = %v, want nil", err)
			}
			if !bytes.Equal(streamed, buffered) {
				t.Fatalf("Reader() = %q, Bytes() = %q, want them to agree", streamed, buffered)
			}
			if string(buffered) != plain {
				t.Fatalf("decoded = %q, want %q", buffered, plain)
			}
		})
	}
}

// TestReaderRejectsUnsupportedCoding is Reader's half of the fail-closed rule.
func TestReaderRejectsUnsupportedCoding(t *testing.T) {
	t.Parallel()

	if _, err := Reader(headerWithCoding("br"), strings.NewReader("whatever"), 1<<20); err == nil {
		t.Fatalf("Reader() error = nil, want the coding refused")
	}
}

// FuzzDecodeResponseBody drives an adversarial Content-Encoding header and an
// adversarial body through both entry points.
//
// Two invariants. An accepted body never exceeds the caller's limit, which is
// what keeps a compressed archive from becoming an unbounded buffer in a
// middleware that has already checked the raw size. And an accepted body is
// exactly what compress/gzip produces for the same input — an independent
// oracle rather than the decode under test — so a body that is silently
// truncated or half-decoded shows up as a failure instead of as a policy
// decision made over bytes nobody read. The seeds carry the truncated stream
// that motivated the second one.
func FuzzDecodeResponseBody(f *testing.F) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(`[{"Names":["/web"],"Image":"nginx"}]`)); err != nil {
		f.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		f.Fatalf("gzip close: %v", err)
	}
	full := buf.Bytes()

	f.Add("gzip", full)
	f.Add("gzip", full[:len(full)-4])             // truncated stream
	f.Add("gzip", full[:6])                       // header only
	f.Add("gzip", append([]byte(nil), full...))   // whole stream, distinct slice
	f.Add("gzip", []byte{})                       // empty body under a gzip claim
	f.Add("gzip", []byte(`[{"Names":["/web"]}]`)) // claims gzip, is not
	f.Add("x-gzip", full)
	f.Add("gzip, gzip", full)
	f.Add("GZIP", full)
	f.Add(" gzip ", full)
	f.Add("identity", []byte(`[{"Names":["/web"]}]`))
	f.Add("", []byte(`[{"Names":["/web"]}]`))
	f.Add("br", full)
	f.Add("deflate", full)

	f.Fuzz(func(t *testing.T, coding string, body []byte) {
		if len(body) > fuzzDecodeLimit {
			body = body[:fuzzDecodeLimit]
		}
		header := http.Header{"Content-Encoding": []string{coding}}

		got, err := Bytes(header, body, fuzzDecodeLimit)
		if err != nil {
			return
		}
		if int64(len(got)) > fuzzDecodeLimit {
			t.Fatalf("Bytes accepted %d bytes past the %d limit: coding=%q", len(got), fuzzDecodeLimit, coding)
		}

		want, oracleErr := gunzipOracle(coding, body, fuzzDecodeLimit)
		if oracleErr != nil {
			t.Fatalf("Bytes accepted a body the oracle refused (%v): coding=%q body=%q", oracleErr, coding, body)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("Bytes = %q, oracle = %q: coding=%q", got, want, coding)
		}

		reader, err := Reader(header, bytes.NewReader(body), fuzzDecodeLimit)
		if err != nil {
			t.Fatalf("Bytes accepted a body Reader refused (%v): coding=%q", err, coding)
		}
		streamed, err := io.ReadAll(io.LimitReader(reader, fuzzDecodeLimit+1))
		if err != nil {
			t.Fatalf("Bytes accepted a body Reader could not read (%v): coding=%q", err, coding)
		}
		if !bytes.Equal(got, streamed) {
			t.Fatalf("Bytes = %q, Reader = %q: coding=%q", got, streamed, coding)
		}
	})
}

// gunzipOracle decodes coding/body with compress/gzip directly, deliberately
// not through the code under test, so the fuzz invariant has a witness that
// shares none of its logic.
func gunzipOracle(coding string, body []byte, limit int64) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(coding)) {
	case "", "identity":
		return body, nil
	case "gzip", "x-gzip":
		gzr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		decoded, err := io.ReadAll(io.LimitReader(gzr, limit+1))
		if err != nil {
			return nil, err
		}
		if int64(len(decoded)) > limit {
			return nil, errors.New("oracle: decoded body exceeds the limit")
		}
		return decoded, nil
	default:
		return nil, errors.New("oracle: unsupported coding " + coding)
	}
}
