package filter

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// Go's tar writer does not emit sparse members. Build a GNU PAX member
// containing one physical byte at offset zero and a logical trailing hole.
func imageLoadSparseMember(t *testing.T, name, version string, size int64) []byte {
	t.Helper()
	fields := [][2]string{{"GNU.sparse.name", name}, {"GNU.sparse.realsize", strconv.FormatInt(size, 10)}}
	content := []byte{'x'}
	if version == "0.1" {
		fields = append(fields, [2]string{"GNU.sparse.major", "0"}, [2]string{"GNU.sparse.minor", "1"}, [2]string{"GNU.sparse.numblocks", "1"}, [2]string{"GNU.sparse.map", "0,1"})
	} else {
		fields = append(fields, [2]string{"GNU.sparse.major", "1"}, [2]string{"GNU.sparse.minor", "0"})
		content = make([]byte, 513)
		copy(content, "1\n0\n1\n")
		content[512] = 'x'
	}
	var pax strings.Builder
	for _, field := range fields {
		value := field[0] + "=" + field[1] + "\n"
		length := len(value) + 2
		for {
			record := strconv.Itoa(length) + " " + value
			if len(record) == length {
				pax.WriteString(record)
				break
			}
			length = len(record)
		}
	}
	extension := mustContainerArchiveTar(t, containerArchiveTestEntry{name: "PaxHeaders/sparse", body: pax.String()})
	extension = extension[:len(extension)-1024]
	extension[156] = tar.TypeXHeader
	for i := 148; i < 156; i++ {
		extension[i] = ' '
	}
	sum := 0
	for _, b := range extension[:512] {
		sum += int(b)
	}
	copy(extension[148:156], fmt.Sprintf("%06o\x00 ", sum))
	member := mustContainerArchiveTar(t, containerArchiveTestEntry{name: "sparse", body: string(content)})
	return append(extension, member[:len(member)-1024]...)
}

func TestImageLoadSparseLogicalBudget(t *testing.T) {
	const limit int64 = 32 << 10
	original := maxImageLoadDecompressedBytes
	maxImageLoadDecompressedBytes = limit
	t.Cleanup(func() { maxImageLoadDecompressedBytes = original })
	for _, version := range []string{"0.1", "1.0"} {
		for _, compressed := range []bool{false, true} {
			for _, sizes := range [][]int64{{limit + 1}, {20 << 10, 20 << 10}} {
				t.Run(fmt.Sprintf("%s/gzip=%v/sizes=%v", version, compressed, sizes), func(t *testing.T) {
					var payload []byte
					for i, size := range sizes {
						payload = append(payload, imageLoadSparseMember(t, fmt.Sprintf("blobs/sha256/%064x", i), version, size)...)
					}
					payload = append(payload, make([]byte, 1024)...)
					if int64(len(payload)) >= limit {
						t.Fatal("physical tar exceeds test limit")
					}
					if compressed {
						payload = mustGzip(t, payload)
					}
					req := httptest.NewRequest(http.MethodPost, "/images/load", bytes.NewReader(payload))
					reason, err := newImageLoadPolicy(ImageLoadOptions{AllowAllRegistries: true, AllowUntagged: true}).inspect(nil, req, "/images/load")
					t.Cleanup(func() {
						if req.Body != nil {
							_ = req.Body.Close()
						}
					})
					want := fmt.Sprintf("image load denied: decompressed image archive exceeds %d byte limit", limit)
					if err != nil || reason != want {
						t.Fatalf("inspect = (%q,%v), want (%q,nil)", reason, err, want)
					}
				})
			}
		}
	}
}

type imageLoadUnreadableBlob struct{ t *testing.T }

func (r imageLoadUnreadableBlob) Read([]byte) (int, error) {
	r.t.Error("over-budget blob was read")
	return 0, io.ErrUnexpectedEOF
}

func TestImageLoadLogicalBlobPreflight(t *testing.T) {
	const limit int64 = 16
	original := maxImageLoadDecompressedBytes
	maxImageLoadDecompressedBytes = limit
	t.Cleanup(func() { maxImageLoadDecompressedBytes = original })
	for _, size := range []int64{-1, limit + 1, math.MaxInt64} {
		t.Run(strconv.FormatInt(size, 10), func(t *testing.T) {
			var controls imageLoadArchiveControlFiles
			err := defaultIODeps().recordImageLoadOCIBlob(&controls, "blobs/sha256/"+strings.Repeat("0", 64), &tar.Header{Typeflag: tar.TypeReg, Size: size}, imageLoadUnreadableBlob{t})
			if !errors.Is(err, errImageLoadDecompressedTooLarge) {
				t.Fatalf("error = %v, want logical size denial", err)
			}
		})
	}
	var controls imageLoadArchiveControlFiles
	for i, size := range []int64{7, 9, 1, math.MaxInt64} {
		reader := io.Reader(imageLoadUnreadableBlob{t})
		if i < 2 {
			reader = bytes.NewReader(make([]byte, size))
		}
		err := defaultIODeps().recordImageLoadOCIBlob(&controls, fmt.Sprintf("blobs/sha256/%064x", i), &tar.Header{Typeflag: tar.TypeReg, Size: size}, reader)
		if i < 2 && err != nil {
			t.Fatalf("exact boundary rejected: %v", err)
		}
		if i >= 2 && !errors.Is(err, errImageLoadDecompressedTooLarge) {
			t.Fatalf("aggregate limit-plus-one error = %v", err)
		}
	}
}

func TestImageLoadSparseCompatibility(t *testing.T) {
	const limit int64 = 32 << 10
	original := maxImageLoadDecompressedBytes
	maxImageLoadDecompressedBytes = limit
	t.Cleanup(func() { maxImageLoadDecompressedBytes = original })
	for _, version := range []string{"0.1", "1.0"} {
		for _, compressed := range []bool{false, true} {
			for _, format := range []string{"oci", "docker"} {
				t.Run(fmt.Sprintf("%s/gzip=%v/%s", version, compressed, format), func(t *testing.T) {
					var payload []byte
					if format == "oci" {
						layer := make([]byte, 4096)
						layer[0] = 'x'
						entries := mustOCIImageLoadEntriesWithPayloads(t, "registry.example.com/acme/app:latest", []byte(`{"architecture":"amd64","os":"linux"}`), layer)
						for _, entry := range entries {
							if entry.body == string(layer) {
								payload = append(payload, imageLoadSparseMember(t, entry.name, version, int64(len(layer)))...)
							} else {
								raw := mustContainerArchiveTar(t, entry)
								payload = append(payload, raw[:len(raw)-1024]...)
							}
						}
					} else {
						raw := mustContainerArchiveTar(t, daemonValidDockerImageLoadEntries(t, "registry.example.com/acme/app:latest")...)
						payload = append(payload, raw[:len(raw)-1024]...)
						payload = append(payload, imageLoadSparseMember(t, "unrelated/layer.tar", version, math.MaxInt64)...)
					}
					payload = append(payload, make([]byte, 1024)...)
					if compressed {
						payload = mustGzip(t, payload)
					}
					req := httptest.NewRequest(http.MethodPost, "/images/load", bytes.NewReader(payload))
					reason, err := newImageLoadPolicy(ImageLoadOptions{AllowAllRegistries: true}).inspect(nil, req, "/images/load")
					t.Cleanup(func() {
						if req.Body != nil {
							_ = req.Body.Close()
						}
					})
					if err != nil || reason != "" {
						t.Fatalf("valid sparse archive rejected: (%q,%v)", reason, err)
					}
					body, err := io.ReadAll(req.Body)
					if err != nil || !bytes.Equal(body, payload) {
						t.Fatalf("archive body changed: %v", err)
					}
				})
			}
		}
	}
}
