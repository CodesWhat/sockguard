package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/logging"
	"github.com/codeswhat/sockguard/v3/app/internal/metrics"
)

// hijackTelemetryDaemon answers one request on a unix socket with the given
// head, then writes payload and closes. upgrade picks a 101 head over a
// no-length 200 raw stream.
func hijackTelemetryDaemon(t *testing.T, upgrade bool, payload string) string {
	t.Helper()
	socketPath := tempSocketPath(t, "hijack-telemetry")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		_ = req.Body.Close()
		if upgrade {
			_, _ = io.WriteString(conn, "HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/vnd.docker.raw-stream\r\n\r\n")
		} else {
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.docker.raw-stream\r\n\r\n")
		}
		_, _ = io.WriteString(conn, payload)
	}()
	return socketPath
}

type hijackTelemetry struct {
	access  []map[string]any
	audit   []map[string]any
	metrics string
}

// runHijackTelemetry sends one attach request through metrics, access log,
// audit log and the hijack handler, drains the stream and returns what each
// layer recorded.
func runHijackTelemetry(t *testing.T, upgrade bool) hijackTelemetry {
	t.Helper()
	const payload = "stream-bytes"
	socketPath := hijackTelemetryDaemon(t, upgrade, payload)

	var accessBuf, auditBuf safeBuffer
	accessLogger := slog.New(slog.NewJSONHandler(&accessBuf, nil))
	auditLogger := logging.NewAuditLogger(&auditBuf)
	registry := metrics.NewRegistry()

	hijackLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("next handler should not be called for a hijack endpoint")
	})
	handler := HijackHandler(socketPath, hijackLogger, next)
	handler = PassClientUpgrade(handler)
	// Same order as the serve chain: access log outermost, metrics innermost,
	// so all three read one shared RequestMeta.
	handler = registry.Middleware()(handler)
	handler = logging.AuditLogMiddleware(auditLogger, logging.AuditOptions{})(handler)
	handler = logging.AccessLogMiddleware(accessLogger)(handler)

	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(clientLn) }()
	t.Cleanup(func() { _ = srv.Close() })

	conn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	req := "POST /containers/abc/attach?stream=1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	wantWire := http.StatusOK
	if upgrade {
		wantWire = http.StatusSwitchingProtocols
	}
	if resp.StatusCode != wantWire {
		t.Fatalf("wire status = %d, want %d", resp.StatusCode, wantWire)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil || string(got) != payload {
		t.Fatalf("payload = %q, err = %v", got, err)
	}
	_ = conn.Close()

	// The telemetry is emitted after the handler returns, which follows the
	// relay finishing; wait for the access line.
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(accessBuf.String(), `"status"`) {
		if time.Now().After(deadline) {
			t.Fatal("access log line never appeared")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := auditLogger.Close(); err != nil {
		t.Fatalf("close audit logger: %v", err)
	}

	var out hijackTelemetry
	for _, line := range bytes.Split([]byte(accessBuf.String()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err == nil && m["status"] != nil {
			out.access = append(out.access, m)
		}
	}
	for _, line := range bytes.Split([]byte(auditBuf.String()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err == nil {
			out.audit = append(out.audit, m)
		}
	}
	rec := httptest.NewRecorder()
	registry.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	out.metrics = rec.Body.String()
	return out
}

func statusOf(t *testing.T, events []map[string]any, what string) int {
	t.Helper()
	if len(events) != 1 {
		t.Fatalf("%s: %d events, want 1: %v", what, len(events), events)
	}
	status, ok := events[0]["status"].(float64)
	if !ok {
		t.Fatalf("%s: no numeric status in %v", what, events[0])
	}
	return int(status)
}

func requestsTotalLines(metricsText string) []string {
	var lines []string
	for _, line := range strings.Split(metricsText, "\n") {
		if strings.HasPrefix(line, "sockguard_http_requests_total{") {
			lines = append(lines, line)
		}
	}
	return lines
}

func TestHijackedUpgradeReportsStatus101InAuditAccessAndMetrics(t *testing.T) {
	got := runHijackTelemetry(t, true)

	if s := statusOf(t, got.access, "access log"); s != http.StatusSwitchingProtocols {
		t.Errorf("access log status = %d, want 101", s)
	}
	if s := statusOf(t, got.audit, "audit log"); s != http.StatusSwitchingProtocols {
		t.Errorf("audit log status = %d, want 101", s)
	}
	lines := requestsTotalLines(got.metrics)
	if len(lines) != 1 || !strings.Contains(lines[0], `status="101"`) {
		t.Errorf("metrics request lines = %v, want one with status=\"101\"", lines)
	}
}

func TestHijackedRawStreamKeepsStatus200(t *testing.T) {
	got := runHijackTelemetry(t, false)

	if s := statusOf(t, got.access, "access log"); s != http.StatusOK {
		t.Errorf("access log status = %d, want 200", s)
	}
	if s := statusOf(t, got.audit, "audit log"); s != http.StatusOK {
		t.Errorf("audit log status = %d, want 200", s)
	}
	lines := requestsTotalLines(got.metrics)
	if len(lines) != 1 || !strings.Contains(lines[0], `status="200"`) {
		t.Errorf("metrics request lines = %v, want one with status=\"200\"", lines)
	}
}

// A failed hijack must not claim a successful upgrade.
func TestFailedHijackDoesNotRecordUpgradeStatus(t *testing.T) {
	cases := map[string]http.ResponseWriter{
		"not a hijacker": &loggingTestResponseWriter{meta: &logging.RequestMeta{}},
		"hijack error":   &hijackErrorWriter{err: errors.New("hijack refused")},
	}
	for name, w := range cases {
		t.Run(name, func(t *testing.T) {
			meta := &logging.RequestMeta{}
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			resp := &http.Response{StatusCode: http.StatusSwitchingProtocols, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{}}
			upstream, peer := net.Pipe()
			defer peer.Close()
			_, ok := finalizeHijackUpgrade(w, logger, hijackUpgradeState{meta: meta, resp: resp, upstreamConn: upstream, path: "/containers/abc/attach"})
			if ok {
				t.Fatal("finalizeHijackUpgrade succeeded on a writer that cannot hijack")
			}
			if meta.HijackedStatus != 0 {
				t.Fatalf("HijackedStatus = %d after a failed hijack, want 0", meta.HijackedStatus)
			}
		})
	}
}

func TestRequestMetaHijackedStatusIsClearedOnPoolReuse(t *testing.T) {
	// The pooled meta is zeroed wholesale on return; a leaked status would
	// misreport the next request on that meta.
	meta := &logging.RequestMeta{}
	meta.SetHijackedStatus(http.StatusSwitchingProtocols)
	if got := meta.EffectiveStatus(http.StatusOK); got != http.StatusSwitchingProtocols {
		t.Fatalf("EffectiveStatus = %d, want 101", got)
	}
	*meta = logging.RequestMeta{}
	if got := meta.EffectiveStatus(http.StatusOK); got != http.StatusOK {
		t.Fatalf("EffectiveStatus after reset = %d, want the captured 200", got)
	}
	var nilMeta *logging.RequestMeta
	nilMeta.SetHijackedStatus(101)
	if got := nilMeta.EffectiveStatus(204); got != 204 {
		t.Fatalf("nil meta EffectiveStatus = %d, want 204", got)
	}
	meta.SetHijackedStatus(0)
	meta.SetHijackedStatus(-5)
	if meta.HijackedStatus != 0 {
		t.Fatalf("non-positive codes must be ignored, got %d", meta.HijackedStatus)
	}
}
