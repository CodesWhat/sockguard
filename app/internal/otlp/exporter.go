package otlp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// ScopeName is the instrumentation scope reported on every export.
	ScopeName = "github.com/codeswhat/sockguard"

	maxAttempts          = 3
	maxRetryDelay        = 5 * time.Second
	baseRetryDelay       = 200 * time.Millisecond
	maxResponseBodyBytes = 64 << 10
	warnInterval         = time.Minute
)

// Options configures an Exporter.
type Options struct {
	// Endpoint is the full collector URL including path.
	Endpoint string
	// Headers are added to every export request. Values are secrets and are
	// never logged or returned in errors.
	Headers        map[string]string
	Timeout        time.Duration
	FlushInterval  time.Duration
	QueueSize      int
	BatchSize      int
	ServiceName    string
	ServiceVersion string
	// CAFile adds a PEM bundle to the trusted roots. Empty uses system roots.
	CAFile             string
	InsecureSkipVerify bool
}

// Stats is a point-in-time snapshot of the exporter's counters.
type Stats struct {
	Exported            uint64
	DroppedQueueFull    uint64
	DroppedExportFailed uint64
	DroppedShutdown     uint64
	RequestsSuccess     uint64
	RequestsRetryable   uint64
	RequestsPermanent   uint64
}

// Exporter batches spans and posts them to an OTLP/HTTP collector.
type Exporter struct {
	opts   Options
	client *http.Client

	admissionMu sync.RWMutex
	queue       chan Span
	done        chan struct{} // closed by Close: stop admitting, drain
	finished    chan struct{} // closed when the worker has exited
	closeOnce   sync.Once
	runCtx      context.Context
	cancelRun   context.CancelFunc

	// sleep waits d or until ctx is done. Replaced in tests.
	sleep func(ctx context.Context, d time.Duration) bool

	exported            atomic.Uint64
	droppedQueueFull    atomic.Uint64
	droppedExportFailed atomic.Uint64
	droppedShutdown     atomic.Uint64
	reqSuccess          atomic.Uint64
	reqRetryable        atomic.Uint64
	reqPermanent        atomic.Uint64
	lastWarn            atomic.Int64
}

// New builds an Exporter and starts its worker goroutine. The caller must
// call Close.
func New(opts Options) (*Exporter, error) {
	if opts.QueueSize < 1 || opts.BatchSize < 1 || opts.Timeout <= 0 || opts.FlushInterval <= 0 {
		return nil, errors.New("otlp: queue size, batch size, timeout and flush interval must be positive")
	}
	if u, err := url.Parse(opts.Endpoint); err != nil || u.Host == "" {
		return nil, errors.New("otlp: endpoint must be an absolute URL")
	}
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("otlp: unexpected default transport")
	}
	// The clone keeps the stdlib defaults, including ProxyFromEnvironment:
	// HTTPS_PROXY / NO_PROXY apply to the export request like any other
	// stdlib client.
	transport = transport.Clone()
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: opts.InsecureSkipVerify} // #nosec G402 -- operator opt-in via otlp.tls.insecure_skip_verify, off by default
	if opts.CAFile != "" {
		pem, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, errors.New("otlp: cannot read tls.ca_file")
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("otlp: tls.ca_file contains no PEM certificates")
		}
		tlsCfg.RootCAs = pool
	}
	transport.TLSClientConfig = tlsCfg

	runCtx, cancel := context.WithCancel(context.Background())
	e := &Exporter{
		opts: opts,
		client: &http.Client{
			Transport: transport,
			Timeout:   opts.Timeout,
			// A redirect would replay the export (and its headers) elsewhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		queue:     make(chan Span, opts.QueueSize),
		done:      make(chan struct{}),
		finished:  make(chan struct{}),
		runCtx:    runCtx,
		cancelRun: cancel,
		sleep:     sleepCtx,
	}
	go e.run()
	return e, nil
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// Enqueue offers a span to the exporter. It never blocks: a full queue or a
// closed exporter drops the span and counts it.
func (e *Exporter) Enqueue(s Span) {
	if e == nil {
		return
	}
	e.admissionMu.RLock()
	defer e.admissionMu.RUnlock()
	select {
	case <-e.done:
		e.drop(&e.droppedShutdown, 1, "exporter closed")
		return
	default:
	}
	select {
	case e.queue <- s:
	default:
		e.drop(&e.droppedQueueFull, 1, "queue full")
	}
}

func (e *Exporter) drop(counter *atomic.Uint64, n uint64, reason string) {
	counter.Add(n)
	e.warn("otlp spans dropped", "reason", reason)
}

// warn emits at most one WARN per minute. Attributes must never carry the
// endpoint, headers or raw transport errors.
func (e *Exporter) warn(msg string, args ...any) {
	now := time.Now().UnixNano()
	last := e.lastWarn.Load()
	if now-last < warnInterval.Nanoseconds() || !e.lastWarn.CompareAndSwap(last, now) {
		return
	}
	s := e.Stats()
	args = append(args,
		"dropped_queue_full", s.DroppedQueueFull,
		"dropped_export_failed", s.DroppedExportFailed,
		"dropped_shutdown", s.DroppedShutdown,
	)
	slog.Warn(msg, args...)
}

// Stats returns a snapshot of the exporter counters. Nil-safe.
func (e *Exporter) Stats() Stats {
	if e == nil {
		return Stats{}
	}
	return Stats{
		Exported:            e.exported.Load(),
		DroppedQueueFull:    e.droppedQueueFull.Load(),
		DroppedExportFailed: e.droppedExportFailed.Load(),
		DroppedShutdown:     e.droppedShutdown.Load(),
		RequestsSuccess:     e.reqSuccess.Load(),
		RequestsRetryable:   e.reqRetryable.Load(),
		RequestsPermanent:   e.reqPermanent.Load(),
	}
}

// Close stops admitting spans, flushes what is queued, and returns once the
// worker is done or ctx expires. On expiry in-flight exports are aborted and
// the remaining spans are dropped (counted as shutdown drops) and ctx.Err()
// is returned. Safe to call more than once and on a nil Exporter.
func (e *Exporter) Close(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.closeOnce.Do(func() {
		e.admissionMu.Lock()
		close(e.done)
		e.admissionMu.Unlock()
	})
	var err error
	select {
	case <-e.finished:
	case <-ctx.Done():
		e.cancelRun()
		<-e.finished
		err = ctx.Err()
	}
	e.cancelRun()
	e.client.CloseIdleConnections()
	return err
}

func (e *Exporter) run() {
	defer close(e.finished)
	batch := make([]Span, 0, e.opts.BatchSize)
	timer := time.NewTimer(e.opts.FlushInterval)
	defer timer.Stop()

	flush := func() {
		if len(batch) > 0 {
			e.send(batch)
			batch = batch[:0]
		}
	}
	for {
		select {
		case s := <-e.queue:
			batch = append(batch, s)
			if len(batch) >= e.opts.BatchSize {
				flush()
			}
		case <-timer.C:
			flush()
			timer.Reset(e.opts.FlushInterval)
		case <-e.done:
			// Admission is closed (Enqueue holds the read lock across its
			// send, Close took the write lock), so the queue only shrinks.
			for {
				select {
				case s := <-e.queue:
					batch = append(batch, s)
					if len(batch) >= e.opts.BatchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

// send exports one batch with bounded retries and accounts for the outcome.
func (e *Exporter) send(batch []Span) {
	n := uint64(len(batch))
	if e.runCtx.Err() != nil {
		e.droppedShutdown.Add(n)
		return
	}
	body, err := e.encode(batch)
	if err != nil {
		e.droppedExportFailed.Add(n)
		e.warn("otlp export failed", "reason", "encode")
		return
	}
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		retryable, retryAfter, ok, reason := e.post(body)
		switch {
		case ok:
			e.reqSuccess.Add(1)
			e.exported.Add(n)
			return
		case !retryable:
			e.reqPermanent.Add(1)
			e.droppedExportFailed.Add(n)
			e.warn("otlp export failed", "reason", reason)
			return
		}
		e.reqRetryable.Add(1)
		if e.runCtx.Err() != nil {
			e.droppedShutdown.Add(n)
			return
		}
		if attempt == maxAttempts {
			e.droppedExportFailed.Add(n)
			e.warn("otlp export failed", "reason", reason)
			return
		}
		delay := baseRetryDelay << (attempt - 1)
		if retryAfter > 0 {
			delay = retryAfter
		}
		delay = min(delay, maxRetryDelay)
		if !e.sleep(e.runCtx, delay) {
			e.droppedShutdown.Add(n)
			return
		}
	}
}

func (e *Exporter) encode(batch []Span) ([]byte, error) {
	spans := make([]jsonSpan, len(batch))
	for i, s := range batch {
		spans[i] = toJSONSpan(s)
	}
	res := []keyValue{toKeyValue(StringAttr("service.name", e.opts.ServiceName))}
	if e.opts.ServiceVersion != "" {
		res = append(res, toKeyValue(StringAttr("service.version", e.opts.ServiceVersion)))
	}
	return json.Marshal(exportRequest{ResourceSpans: []resourceSpans{{
		Resource:   resource{Attributes: res},
		ScopeSpans: []scopeSpans{{Scope: scope{Name: ScopeName}, Spans: spans}},
	}}})
}

// post performs one HTTP attempt. reason is a short classification safe to
// log: it never contains the URL, headers or response body.
func (e *Exporter) post(body []byte) (retryable bool, retryAfter time.Duration, ok bool, reason string) {
	req, err := http.NewRequestWithContext(e.runCtx, http.MethodPost, e.opts.Endpoint, bytes.NewReader(body))
	if err != nil {
		return false, 0, false, "bad request"
	}
	for k, v := range e.opts.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		// url.Error embeds the full URL; report only the cause class.
		var ue *url.Error
		if errors.As(err, &ue) && ue.Timeout() {
			return true, 0, false, "timeout"
		}
		return true, 0, false, "network error"
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBodyBytes))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, 0, true, ""
	case resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode == http.StatusBadGateway,
		resp.StatusCode == http.StatusServiceUnavailable,
		resp.StatusCode == http.StatusGatewayTimeout:
		return true, parseRetryAfter(resp.Header.Get("Retry-After")), false, fmt.Sprintf("http %d", resp.StatusCode)
	default:
		return false, 0, false, fmt.Sprintf("http %d", resp.StatusCode)
	}
}

// parseRetryAfter reads delta-seconds or an HTTP-date; anything else is 0.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs <= 0 {
			return 0
		}
		return min(time.Duration(secs)*time.Second, maxRetryDelay)
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return min(d, maxRetryDelay)
		}
	}
	return 0
}
