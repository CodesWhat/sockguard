// loadgen hammers a unix-socket HTTP endpoint at a configurable
// concurrency for a fixed duration and prints a single-line JSON result
// summarizing p50/p90/p99/max latency, RPS, and error counts. It keeps a
// persistent http.Client per goroutine so we measure steady-state
// performance, not per-request transport setup.
//
// Output is JSON (one line) so the orchestrator can parse it without
// regex'ing columnar text.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type result struct {
	Scenario         string           `json:"scenario"`
	Socket           string           `json:"socket"`
	Method           string           `json:"method"`
	Path             string           `json:"path"`
	Concurrency      int              `json:"concurrency"`
	DurationSeconds  float64          `json:"duration_seconds"`
	TotalRequests    int64            `json:"total_requests"`
	ErrorRequests    int64            `json:"error_requests"`
	ErrorCounts      map[string]int64 `json:"error_counts,omitempty"`
	StatusCodeCounts map[int]int64    `json:"status_code_counts"`
	RPS              float64          `json:"rps"`
	LatencyP50Micros int64            `json:"latency_p50_us"`
	LatencyP90Micros int64            `json:"latency_p90_us"`
	LatencyP99Micros int64            `json:"latency_p99_us"`
	LatencyMaxMicros int64            `json:"latency_max_us"`
	GoroutinesStart  int              `json:"goroutines_start"`
	GoroutinesEnd    int              `json:"goroutines_end"`
}

type benchmarkOptions struct {
	Socket      string
	Method      string
	Path        string
	Concurrency int
	Duration    time.Duration
	Scenario    string
}

func main() {
	var (
		socket      = flag.String("socket", "/tmp/sg-bench-proxy.sock", "unix socket to hit")
		method      = flag.String("method", "GET", "HTTP method")
		path        = flag.String("path", "/_ping", "request path")
		concurrency = flag.Int("concurrency", 50, "concurrent workers")
		duration    = flag.Duration("duration", 20*time.Second, "benchmark duration")
		scenario    = flag.String("scenario", "custom", "label for this run")
	)
	flag.Parse()

	out := runBenchmark(benchmarkOptions{
		Socket:      *socket,
		Method:      *method,
		Path:        *path,
		Concurrency: *concurrency,
		Duration:    *duration,
		Scenario:    *scenario,
	})

	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(out); err != nil {
		log.Fatalf("encode: %v", err)
	}
	fmt.Fprintf(os.Stderr, "%-20s conc=%-3d rps=%.0f p50=%dus p99=%dus max=%dus errs=%d\n",
		*scenario, *concurrency, out.RPS, out.LatencyP50Micros, out.LatencyP99Micros, out.LatencyMaxMicros, out.ErrorRequests)
}

func runBenchmark(opts benchmarkOptions) result {
	runtime.GC()
	goStart := runtime.NumGoroutine()

	stop := make(chan struct{})
	timer := time.NewTimer(opts.Duration)
	defer timer.Stop()
	go func() {
		<-timer.C
		close(stop)
	}()

	// One client per worker, each pinned to the same unix socket.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", opts.Socket)
		},
		MaxIdleConns:        opts.Concurrency * 2,
		MaxIdleConnsPerHost: opts.Concurrency * 2,
		IdleConnTimeout:     90 * time.Second,
	}
	defer transport.CloseIdleConnections()

	var (
		totalReqs atomic.Int64
		totalErrs atomic.Int64
	)
	errorMu := &sync.Mutex{}
	errorCounts := make(map[string]int64)
	statusMu := &sync.Mutex{}
	statusCounts := make(map[int]int64)

	latenciesMu := &sync.Mutex{}
	latencies := make([]int64, 0, 1<<20)

	var wg sync.WaitGroup
	wg.Add(opts.Concurrency)
	started := time.Now()

	for i := 0; i < opts.Concurrency; i++ {
		go func() {
			defer wg.Done()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			for {
				select {
				case <-stop:
					return
				default:
				}
				req, err := http.NewRequest(opts.Method, "http://unix"+opts.Path, nil)
				if err != nil {
					totalErrs.Add(1)
					totalReqs.Add(1)
					errorMu.Lock()
					errorCounts[err.Error()]++
					errorMu.Unlock()
					continue
				}
				t0 := time.Now()
				resp, err := client.Do(req)
				dur := time.Since(t0).Microseconds()
				totalReqs.Add(1)
				if err != nil {
					totalErrs.Add(1)
					errorMu.Lock()
					errorCounts[err.Error()]++
					errorMu.Unlock()
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				statusMu.Lock()
				statusCounts[resp.StatusCode]++
				statusMu.Unlock()
				latenciesMu.Lock()
				latencies = append(latencies, dur)
				latenciesMu.Unlock()
			}
		}()
	}

	wg.Wait()
	elapsed := time.Since(started)

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p := func(q float64) int64 {
		if len(latencies) == 0 {
			return 0
		}
		idx := int(q * float64(len(latencies)))
		if idx >= len(latencies) {
			idx = len(latencies) - 1
		}
		return latencies[idx]
	}
	var max int64
	if len(latencies) > 0 {
		max = latencies[len(latencies)-1]
	}

	runtime.GC()
	goEnd := runtime.NumGoroutine()

	out := result{
		Scenario:         opts.Scenario,
		Socket:           opts.Socket,
		Method:           opts.Method,
		Path:             opts.Path,
		Concurrency:      opts.Concurrency,
		DurationSeconds:  elapsed.Seconds(),
		TotalRequests:    totalReqs.Load(),
		ErrorRequests:    totalErrs.Load(),
		ErrorCounts:      errorCounts,
		StatusCodeCounts: statusCounts,
		RPS:              float64(totalReqs.Load()) / elapsed.Seconds(),
		LatencyP50Micros: p(0.50),
		LatencyP90Micros: p(0.90),
		LatencyP99Micros: p(0.99),
		LatencyMaxMicros: max,
		GoroutinesStart:  goStart,
		GoroutinesEnd:    goEnd,
	}

	return out
}
