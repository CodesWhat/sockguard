package filter

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestImageLoadGzipBombExceedingDecompressedLimitIsDenied builds a gzip stream
// whose decompressed content exceeds maxImageLoadDecompressedBytes and asserts
// that the inspector returns a denial reason (not a hard error) matching
// errImageLoadDecompressedTooLarge.
//
// The bomb is produced by streaming zeros into a gzip writer through a pipe so
// that the full decompressed payload is never resident in memory — only the
// (small) compressed bytes are buffered.
func TestImageLoadGzipBombExceedingDecompressedLimitIsDenied(t *testing.T) {
	// We need to produce a gzip-wrapped tar that, when decompressed, exceeds
	// maxImageLoadDecompressedBytes (2 GiB). Writing real 2 GiB of zeros would
	// be impractical in a test; instead we produce a well-compressed tar stream
	// that expands past the limit. Because compress/gzip at default level
	// compresses a stream of zeros by ~1000:1 or better, writing
	// (maxImageLoadDecompressedBytes + 1) zeros produces a gzip blob that is a
	// few MiB — safe for a unit test. We stream via pipe to avoid a 2 GiB
	// allocation.
	const decompressedTarget = maxImageLoadDecompressedBytes + 1 // one byte past the limit

	pr, pw := io.Pipe()

	// goroutine: write a tar whose content is decompressedTarget zero bytes,
	// gzip-compressed, into the pipe.
	go func() {
		gzw := gzip.NewWriter(pw)
		tw := tar.NewWriter(gzw)

		// Single large regular-file entry filled with zeros.
		hdr := &tar.Header{
			Name:     "bigfile",
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     int64(decompressedTarget),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = pw.CloseWithError(err)
			return
		}

		// Stream zeros in chunks — never allocate the full payload.
		const chunkSize = 1 << 20 // 1 MiB
		chunk := make([]byte, chunkSize)
		remaining := int64(decompressedTarget)
		for remaining > 0 {
			n := int64(chunkSize)
			if remaining < n {
				n = remaining
			}
			if _, err := tw.Write(chunk[:n]); err != nil {
				_ = pw.CloseWithError(err)
				return
			}
			remaining -= n
		}

		if err := tw.Close(); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if err := gzw.Close(); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()

	// Collect the compressed output into a buffer that we can replay as an
	// http.Request body. The compressed size should be small (~a few MiB at
	// most for an all-zeros payload).
	var compressed bytes.Buffer
	if _, err := io.Copy(&compressed, pr); err != nil {
		t.Fatalf("compress bomb payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/images/load", bytes.NewReader(compressed.Bytes()))
	reason, err := newImageLoadPolicy(ImageLoadOptions{
		AllowAllRegistries: true,
		AllowUntagged:      true,
	}).inspect(nil, req, "/images/load")

	if err != nil {
		t.Fatalf("inspect() returned error = %v; want nil error with a denial reason", err)
	}
	if reason == "" {
		t.Fatal("inspect() returned empty reason; want gzip-bomb denial")
	}

	const wantPrefix = "image load denied: decompressed image archive exceeds"
	if len(reason) < len(wantPrefix) || reason[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("inspect() reason = %q; want prefix %q", reason, wantPrefix)
	}
}
