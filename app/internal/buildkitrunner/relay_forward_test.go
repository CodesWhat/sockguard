package buildkitrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/gateway"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/pb"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/proto"
)

func relayTestClient(t *testing.T, handler http.HandlerFunc) *http2.ClientConn {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	config := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	config.NextProtos = []string{"h2"}
	conn, err := tls.Dial("tcp", server.Listener.Addr().String(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	client, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

type relayReportWriter func([]byte) (int, error)

func (f relayReportWriter) Write(p []byte) (int, error) { return f(p) }

func TestRelayForwardsOriginalFramesAfterReport(t *testing.T) {
	raw, err := proto.Marshal(&pb.Op{Op: &pb.Op_Source{Source: &pb.SourceOp{Identifier: "inert:reviewed"}}})
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, 0xf8, 0x07, 0x01)
	payload, err := proto.Marshal(&gateway.SolveRequest{Definition: &pb.Definition{Def: [][]byte{raw}}})
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, 0xf8, 0x07, 0x02)
	requestFrame := frameMessage(payload)
	responseFrame := frameMessage([]byte{0xf8, 0x07, 0x03})
	reports := make(chan []byte, 1)
	var called atomic.Bool
	client := relayTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		select {
		case record := <-reports:
			var got operationRecord
			if err := json.Unmarshal(record, &got); err != nil {
				t.Error(err)
			}
			if got.Digest != fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) || !bytes.Equal(got.Encoded, raw) {
				t.Error("upstream received Solve before its original operation was reported")
			}
		default:
			t.Error("Solve reached upstream before operation report completed")
		}
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(got, requestFrame) {
			t.Error("relay rewrote original Solve frame")
		}
		if r.Method != http.MethodPost || r.URL.Path != "/"+gatewayService+"/Solve" || r.URL.RawQuery != "" {
			t.Error("relay changed gateway routing")
		}
		if r.Header.Get(buildHeader) != "trusted-build" || len(r.Header.Values(buildHeader)) != 1 {
			t.Error("caller build identity reached upstream")
		}
		if r.Header.Get("Content-Type") != "application/grpc" || r.Header.Get("Te") != "trailers" {
			t.Error("gateway transport metadata missing")
		}
		for _, name := range []string{"Authorization", "Cookie", "X-Frontend", "Grpc-Timeout", "Grpc-Encoding"} {
			if r.Header.Get(name) != "" {
				t.Errorf("frontend metadata %s reached upstream", name)
			}
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message, Grpc-Status-Details-Bin")
		w.Header().Set("X-Upstream", "private")
		w.WriteHeader(http.StatusOK)
		w.Write(responseFrame)
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("Grpc-Message", "complete%20message")
		w.Header().Set("Grpc-Status-Details-Bin", "ZGV0YWlscw==")
	})
	relay := &gatewayRelay{client: client, build: "trusted-build", report: newOperationReporter(relayReportWriter(func(p []byte) (int, error) {
		reports <- bytes.Clone(p)
		return len(p), nil
	}))}
	req := httptest.NewRequest(http.MethodPost, "/"+gatewayService+"/Solve", bytes.NewReader(requestFrame))
	req.Header[http.CanonicalHeaderKey(buildHeader)] = []string{"forged-build", "another-build"}
	for _, name := range []string{"Authorization", "Cookie", "X-Frontend", "Grpc-Timeout"} {
		req.Header.Set(name, "untrusted")
	}
	req.Header.Set("Grpc-Encoding", "identity")
	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, req)
	result := rec.Result()
	defer result.Body.Close()
	if !called.Load() || !bytes.Equal(rec.Body.Bytes(), responseFrame) {
		t.Fatal("original response frame was not relayed")
	}
	if result.Header.Get("X-Upstream") != "" {
		t.Fatal("private upstream metadata leaked")
	}
	for name, want := range map[string]string{"Grpc-Status": "0", "Grpc-Message": "complete%20message", "Grpc-Status-Details-Bin": "ZGV0YWlscw=="} {
		if got := result.Trailer.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestRelayRejectsInvalidRequestsWithoutUpstream(t *testing.T) {
	cases := []struct {
		name, method, path, encoding string
		body                         []byte
		status                       string
	}{
		{"GET", http.MethodGet, "/" + gatewayService + "/Ping", "", frameMessage(nil), "7"},
		{"query", http.MethodPost, "/" + gatewayService + "/Ping?extra=1", "", frameMessage(nil), "7"},
		{"compression", http.MethodPost, "/" + gatewayService + "/Ping", "gzip", frameMessage(nil), "3"},
		{"framing", http.MethodPost, "/" + gatewayService + "/Ping", "", []byte{0, 0}, "3"},
		{"Solve protobuf", http.MethodPost, "/" + gatewayService + "/Solve", "", frameMessage([]byte{0xff}), "3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relay := &gatewayRelay{report: newOperationReporter(nil)}
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
			req.Header.Set("Grpc-Encoding", tc.encoding)
			rec := httptest.NewRecorder()
			relay.ServeHTTP(rec, req)
			if got := rec.Header().Get("Grpc-Status"); got != tc.status {
				t.Fatalf("status = %q, want %q", got, tc.status)
			}
		})
	}
}

func TestRelayReportFailureStopsForwardingAndStaysFailed(t *testing.T) {
	sentinel := errors.New("report\nfailed%")
	writes := 0
	reporter := newOperationReporter(relayReportWriter(func([]byte) (int, error) { writes++; return 0, sentinel }))
	payload, err := proto.Marshal(&gateway.SolveRequest{Definition: &pb.Definition{Def: [][]byte{{}}}})
	if err != nil {
		t.Fatal(err)
	}
	relay := &gatewayRelay{report: reporter}
	for range 2 {
		rec := httptest.NewRecorder()
		relay.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/"+gatewayService+"/Solve", bytes.NewReader(frameMessage(payload))))
		if rec.Header().Get("Grpc-Status") != "3" || rec.Header().Get("Grpc-Message") != "report%0Afailed%25" {
			t.Fatalf("report failure was not propagated safely: %v", rec.Header())
		}
	}
	if writes != 1 || !errors.Is(reporter.err, sentinel) || len(reporter.seen) != 0 || reporter.bytes != 0 {
		t.Fatal("failed report was retried or counted as delivered")
	}
}

func TestOperationReportLimits(t *testing.T) {
	t.Run("distinct operations", func(t *testing.T) {
		reporter := newOperationReporter(nil)
		for i := 0; i < 4096; i++ {
			raw, err := proto.Marshal(&pb.Op{Op: &pb.Op_Source{Source: &pb.SourceOp{Identifier: fmt.Sprintf("inert:%d", i)}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := reporter.write(&pb.Definition{Def: [][]byte{raw}}); err != nil {
				t.Fatalf("operation %d: %v", i, err)
			}
		}
		if err := reporter.write(&pb.Definition{Def: [][]byte{{}}}); err == nil || err.Error() != "operation report limit exceeded" {
			t.Fatalf("operation beyond cap: %v", err)
		}
	})
	t.Run("cumulative bytes", func(t *testing.T) {
		raw, err := proto.Marshal(&pb.Op{Op: &pb.Op_Source{Source: &pb.SourceOp{Identifier: "inert:boundary"}}})
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		reporter := newOperationReporter(&output)
		// Represent bytes already reported by earlier solves without allocating a 32 MiB fixture.
		reporter.bytes = (32 << 20) - len(raw)
		if err := reporter.write(&pb.Definition{Def: [][]byte{raw}}); err != nil {
			t.Fatalf("exact byte cap: %v", err)
		}
		before := output.Len()
		if err := reporter.write(&pb.Definition{Def: [][]byte{raw}}); err != nil {
			t.Fatalf("duplicate at cap: %v", err)
		}
		if err := reporter.write(&pb.Definition{Def: [][]byte{{0xf8, 0x07, 0x01}}}); err == nil || err.Error() != "operation report limit exceeded" {
			t.Fatalf("bytes beyond cap: %v", err)
		}
		if reporter.bytes != 32<<20 || output.Len() != before {
			t.Fatal("duplicate or excess operation changed report accounting")
		}
	})
}

func TestRelayUpstreamResponseBoundaries(t *testing.T) {
	valid := frameMessage([]byte("inert response"))
	cases := []struct {
		name                        string
		httpStatus                  int
		headerStatus, trailerStatus string
		body                        []byte
		want                        string
		forwarded                   bool
	}{
		{"header status", 200, "0", "", valid, "0", true},
		{"header error without body", 200, "7", "", nil, "7", false},
		{"trailer error without body", 200, "", "7", nil, "7", false},
		{"trailers override headers", 200, "0", "7", valid, "7", true},
		{"HTTP error", 502, "0", "", nil, "14", false},
		{"missing status", 200, "", "", valid, "13", false},
		{"success without message", 200, "0", "", nil, "13", false},
		{"truncated header", 200, "7", "", []byte{0, 0}, "13", false},
		{"truncated payload", 200, "0", "", []byte{0, 0, 0, 0, 2, 1}, "13", false},
		{"compressed frame", 200, "0", "", []byte{1, 0, 0, 0, 0}, "13", false},
		{"multiple frames", 200, "0", "", append(bytes.Clone(valid), valid...), "13", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := relayTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				if tc.headerStatus != "" {
					w.Header().Set("Grpc-Status", tc.headerStatus)
				}
				w.Header().Set("Grpc-Message", "upstream%20message")
				w.Header().Set("Grpc-Status-Details-Bin", "ZGV0YWlscw==")
				if tc.trailerStatus != "" {
					w.Header().Set("Trailer", "Grpc-Status")
				}
				w.WriteHeader(tc.httpStatus)
				w.Write(tc.body)
				if tc.trailerStatus != "" {
					w.Header().Set("Grpc-Status", tc.trailerStatus)
				}
			})
			relay := &gatewayRelay{client: client, report: newOperationReporter(nil)}
			rec := httptest.NewRecorder()
			relay.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/"+gatewayService+"/Ping", bytes.NewReader(frameMessage(nil))))
			result := rec.Result()
			defer result.Body.Close()
			status := result.Trailer.Get("Grpc-Status")
			if status == "" {
				status = result.Header.Get("Grpc-Status")
			}
			if status != tc.want {
				t.Fatalf("status = %q, want %q", status, tc.want)
			}
			if tc.forwarded {
				if !bytes.Equal(rec.Body.Bytes(), tc.body) {
					t.Fatal("response frame changed")
				}
			} else if rec.Body.Len() != 0 {
				t.Fatal("invalid response body was forwarded")
			}
			if tc.want == "7" || tc.forwarded {
				if result.Trailer.Get("Grpc-Message") != "upstream%20message" || result.Trailer.Get("Grpc-Status-Details-Bin") != "ZGV0YWlscw==" {
					t.Fatal("header metadata fallback was lost")
				}
			}
		})
	}
}

type relayFailingResponse struct {
	header http.Header
	writes int
	status int
}

func (w *relayFailingResponse) Header() http.Header  { return w.header }
func (w *relayFailingResponse) WriteHeader(code int) { w.status = code }
func (w *relayFailingResponse) Write([]byte) (int, error) {
	w.writes++
	return 0, errors.New("frontend disconnected")
}

func TestRelayStopsAfterFrontendWriteFailure(t *testing.T) {
	client := relayTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Grpc-Status", "0")
		w.Write(frameMessage(nil))
	})
	relay := &gatewayRelay{client: client, report: newOperationReporter(nil)}
	rec := &relayFailingResponse{header: make(http.Header)}
	relay.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/"+gatewayService+"/Ping", bytes.NewReader(frameMessage(nil))))
	if rec.writes != 1 || rec.status != http.StatusOK || rec.header.Get("Grpc-Status") != "" {
		t.Fatal("failed response write still emitted successful trailers")
	}
}

func TestRelayCancelsUpstreamWithFrontend(t *testing.T) {
	entered := make(chan struct{})
	canceled := make(chan struct{})
	client := relayTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	relay := &gatewayRelay{client: client, report: newOperationReporter(nil)}
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		relay.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/"+gatewayService+"/Ping", bytes.NewReader(frameMessage(nil))).WithContext(ctx))
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream request never arrived")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay ignored frontend cancellation")
	}
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream stream was not canceled")
	}
	if rec.Header().Get("Grpc-Status") != "14" || !strings.Contains(rec.Header().Get("Grpc-Message"), "connection failed") {
		t.Fatal("canceled upstream did not return connection failure")
	}
}
