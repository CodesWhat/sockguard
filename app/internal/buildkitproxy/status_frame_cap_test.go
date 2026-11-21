package buildkitproxy

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/buildkitproto/control"
)

const (
	controlServiceName = "moby.buildkit.v1.Control"
	statusRPCName      = "Status"
)

// statusStreamBody builds a server-streaming response of count frames, each
// carrying payloadLen bytes.
func statusStreamBody(count, payloadLen int) []byte {
	var out bytes.Buffer
	payload := bytes.Repeat([]byte{'x'}, payloadLen)
	for range count {
		out.Write(grpcFrame(payload))
	}
	return out.Bytes()
}

func TestRelayGRPCFramesPerMessageCap(t *testing.T) {
	t.Parallel()

	t.Run("many frames exceeding the cap in aggregate relay verbatim", func(t *testing.T) {
		t.Parallel()
		body := statusStreamBody(50, 100) // 5000 payload bytes, cap 128 per frame
		var dst bytes.Buffer
		if err := relayGRPCFramesPerMessageCap(&dst, bytes.NewReader(body), 128); err != nil {
			t.Fatalf("relay error = %v, want nil", err)
		}
		if !bytes.Equal(dst.Bytes(), body) {
			t.Fatal("relayed bytes differ from the source stream")
		}
	})

	t.Run("a frame of exactly the cap is admitted", func(t *testing.T) {
		t.Parallel()
		body := statusStreamBody(1, 128)
		var dst bytes.Buffer
		if err := relayGRPCFramesPerMessageCap(&dst, bytes.NewReader(body), 128); err != nil {
			t.Fatalf("relay error = %v, want nil", err)
		}
	})

	t.Run("an oversized frame fails before any of it is forwarded", func(t *testing.T) {
		t.Parallel()
		body := append(statusStreamBody(2, 10), statusStreamBody(1, 129)...)
		var dst bytes.Buffer
		err := relayGRPCFramesPerMessageCap(&dst, bytes.NewReader(body), 128)
		if !errors.Is(err, errMessageTooLarge) {
			t.Fatalf("relay error = %v, want errMessageTooLarge", err)
		}
		if want := 2 * (grpcMessageHeaderLen + 10); dst.Len() != want {
			t.Fatalf("forwarded %d bytes, want only the %d bytes of the two good frames", dst.Len(), want)
		}
	})

	t.Run("a truncated header is a protocol error", func(t *testing.T) {
		t.Parallel()
		body := append(statusStreamBody(1, 4), 0, 0, 0)
		err := relayGRPCFramesPerMessageCap(io.Discard, bytes.NewReader(body), 128)
		if !errors.Is(err, errStreamFrameProtocolError) {
			t.Fatalf("relay error = %v, want errStreamFrameProtocolError", err)
		}
	})

	t.Run("a truncated payload is a protocol error", func(t *testing.T) {
		t.Parallel()
		body := statusStreamBody(1, 40)
		err := relayGRPCFramesPerMessageCap(io.Discard, bytes.NewReader(body[:len(body)-7]), 128)
		if !errors.Is(err, errStreamFrameProtocolError) {
			t.Fatalf("relay error = %v, want errStreamFrameProtocolError", err)
		}
	})

	t.Run("an empty stream is a clean end", func(t *testing.T) {
		t.Parallel()
		if err := relayGRPCFramesPerMessageCap(io.Discard, strings.NewReader(""), 128); err != nil {
			t.Fatalf("relay error = %v, want nil", err)
		}
	})

	t.Run("a zero-length frame is relayed", func(t *testing.T) {
		t.Parallel()
		body := statusStreamBody(3, 0)
		var dst bytes.Buffer
		if err := relayGRPCFramesPerMessageCap(&dst, bytes.NewReader(body), 128); err != nil || !bytes.Equal(dst.Bytes(), body) {
			t.Fatalf("relay = %v, equal = %v", err, bytes.Equal(dst.Bytes(), body))
		}
	})

	t.Run("a disabled cap admits any length", func(t *testing.T) {
		t.Parallel()
		body := statusStreamBody(1, 5000)
		if err := relayGRPCFramesPerMessageCap(io.Discard, bytes.NewReader(body), 0); err != nil {
			t.Fatalf("relay error = %v, want nil", err)
		}
	})

	t.Run("a write failure is returned as is", func(t *testing.T) {
		t.Parallel()
		want := errors.New("client went away")
		err := relayGRPCFramesPerMessageCap(failingWriter{want}, bytes.NewReader(statusStreamBody(1, 4)), 128)
		if !errors.Is(err, want) {
			t.Fatalf("relay error = %v, want the write error", err)
		}
	})
}

type failingWriter struct{ err error }

func (f failingWriter) Write([]byte) (int, error) { return 0, f.err }

func statusBridge(t *testing.T, body []byte, maxMessage int64) (*bridge, *fakeClientLeg) {
	t.Helper()
	leg := &fakeClientLeg{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/grpc"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}}
	b := newUnitTestBridge(t, leg)
	b.limits.MaxMessageBytes = maxMessage
	return b, leg
}

func forwardStatus(b *bridge) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/"+controlServiceName+"/"+statusRPCName, strings.NewReader(""))
	b.forwardWithBody(rec, req, controlServiceName, statusRPCName, req.Body)
	return rec
}

// Status messages carry build logs for as long as a build runs, so a long
// build must not be cut when its cumulative output crosses the size cap.
func TestForwardWithBodyStatusAllowsAggregateAboveTheMessageCap(t *testing.T) {
	body := statusStreamBody(40, 100) // 4000 payload bytes against a 256-byte cap
	b, _ := statusBridge(t, body, 256)

	rec := forwardStatus(b)

	if !bytes.Equal(rec.Body.Bytes(), body) {
		t.Fatalf("relayed %d bytes, want the whole %d-byte stream", rec.Body.Len(), len(body))
	}
	if got := rec.Result().Trailer.Get("Grpc-Status"); got != "" {
		t.Fatalf("Grpc-Status trailer = %q, want none on a clean stream", got)
	}
}

func TestForwardWithBodyStatusOversizedFrameIsResourceExhausted(t *testing.T) {
	body := append(statusStreamBody(3, 10), statusStreamBody(1, 300)...)
	b, _ := statusBridge(t, body, 256)

	rec := forwardStatus(b)

	if want := 3 * (grpcMessageHeaderLen + 10); rec.Body.Len() != want {
		t.Fatalf("relayed %d bytes, want %d (the frames before the oversized one)", rec.Body.Len(), want)
	}
	if got := rec.Header().Get(http.TrailerPrefix + "Grpc-Status"); got != "8" {
		t.Fatalf("Grpc-Status trailer = %q, want 8 (RESOURCE_EXHAUSTED)", got)
	}
}

func TestForwardWithBodyStatusTruncatedFrameEndsOnlyThatStream(t *testing.T) {
	body := statusStreamBody(2, 20)
	b, _ := statusBridge(t, body[:len(body)-5], 256)

	rec := forwardStatus(b)

	if got := rec.Header().Get(http.TrailerPrefix + "Grpc-Status"); got != "13" {
		t.Fatalf("Grpc-Status trailer = %q, want 13 (INTERNAL)", got)
	}
	// The tunnel survives: a following stream on the same bridge still relays.
	b.clientLeg.(*fakeClientLeg).resp.Body = io.NopCloser(bytes.NewReader(statusStreamBody(1, 8)))
	next := forwardStatus(b)
	if next.Body.Len() != grpcMessageHeaderLen+8 || next.Header().Get(http.TrailerPrefix+"Grpc-Status") != "" {
		t.Fatalf("next stream after a truncated one: %d bytes, status %q", next.Body.Len(), next.Header().Get(http.TrailerPrefix+"Grpc-Status"))
	}
}

// Every RPC other than Control/Status keeps the cumulative cap.
func TestForwardWithBodyOtherRPCsKeepCumulativeCap(t *testing.T) {
	body := statusStreamBody(40, 100)
	for _, tc := range []struct{ service, method string }{
		{controlServiceName, "ListWorkers"},
		{controlServiceName, "DiskUsage"},
		{"moby.filesync.v1.FileSync", "DiffCopy"},
	} {
		b, _ := statusBridge(t, body, 256)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/"+tc.service+"/"+tc.method, strings.NewReader(""))
		b.forwardWithBody(rec, req, tc.service, tc.method, req.Body)
		if got := rec.Header().Get(http.TrailerPrefix + "Grpc-Status"); got != "8" {
			t.Errorf("%s/%s: Grpc-Status trailer = %q, want 8 under the cumulative cap", tc.service, tc.method, got)
		}
	}
}

// End to end over the real h2 legs: a Status stream whose total output is many
// times the message cap reaches the client intact, and an unrelated stream on
// the same tunnel keeps working afterward.
func TestBridgeStatusStreamSurvivesAggregateAboveTheMessageCap(t *testing.T) {
	const (
		solvePath  = "/moby.buildkit.v1.Control/Solve"
		statusPath = "/moby.buildkit.v1.Control/Status"
	)
	stream := statusStreamBody(60, 100)
	daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		if strings.HasSuffix(r.URL.Path, "/Status") {
			_, _ = w.Write(stream)
		}
	})
	limits := DefaultLimits()
	limits.MaxMessageBytes = 512
	tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, limits, daemon)

	solve, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, solvePath, &control.SolveRequest{Ref: "owned-ref", Session: testBuildkitSessionID}))
	if err != nil {
		t.Fatalf("Solve RoundTrip: %v", err)
	}
	_, _ = io.Copy(io.Discard, solve.Body)
	_ = solve.Body.Close()

	status, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, statusPath, &control.StatusRequest{Ref: "owned-ref"}))
	if err != nil {
		t.Fatalf("Status RoundTrip: %v", err)
	}
	got, err := io.ReadAll(status.Body)
	_ = status.Body.Close()
	if err != nil {
		t.Fatalf("reading Status stream: %v", err)
	}
	if !bytes.Equal(got, stream) {
		t.Fatalf("Status stream relayed %d bytes, want %d", len(got), len(stream))
	}

	again, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, statusPath, &control.StatusRequest{Ref: "owned-ref"}))
	if err != nil {
		t.Fatalf("second Status RoundTrip: %v", err)
	}
	if got, _ := io.ReadAll(again.Body); !bytes.Equal(got, stream) {
		t.Fatalf("second Status stream relayed %d bytes, want %d", len(got), len(stream))
	}
	_ = again.Body.Close()
}
