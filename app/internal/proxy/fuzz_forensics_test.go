package proxy

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// Forensics sampler for long-running fuzz targets.
//
// FuzzHijackHeadersAndBody has been killing the monthly hosted-runner job at
// ~80 minutes in with "runner lost communication" — the kernel OOM-kills the
// worker process before Go's fuzz coordinator can flush any diagnostics, so
// the workflow log stops at "Resolve fuzz budget" and we get no insight into
// what was actually growing.
//
// To convert the next failure into actionable forensics, the affected fuzz
// target opts in via startFuzzForensicsSampler. The sampler runs once per
// worker process (Go fuzz forks worker subprocesses, so a sync.Once inside
// the fuzz callback gives us exactly one sampler per worker), and every
// minute it writes a single line capturing heap, goroutine, FD, and Sys
// totals to both stderr (with a SOCKGUARD-FUZZ-FORENSICS sentinel for
// grep) and an append-only file under ./forensics/. The monthly workflow's
// upload-artifact step picks up the latter on failure or cancel, so even
// if the runner dies mid-write the file lands on disk and survives the
// kernel SIGKILL.

const fuzzForensicsSampleEvery = 60 * time.Second

var fuzzForensicsOnce sync.Once

// startFuzzForensicsSampler arms the per-process sampler the first time it is
// called inside a fuzz worker. Subsequent calls in the same process are
// no-ops, so it is safe to invoke from inside the f.Fuzz callback on every
// iteration. The sampler is best-effort: a setup error never fails the fuzz
// target.
func startFuzzForensicsSampler(tb testing.TB, fuzzer string) {
	tb.Helper()
	fuzzForensicsOnce.Do(func() {
		path, file := openFuzzForensicsFile(fuzzer)
		emitFuzzForensicsLine(fuzzer, path, file, 0, true)
		go func() {
			start := time.Now()
			ticker := time.NewTicker(fuzzForensicsSampleEvery)
			defer ticker.Stop()
			for {
				<-ticker.C
				emitFuzzForensicsLine(fuzzer, path, file, time.Since(start), false)
			}
		}()
	})
}

func openFuzzForensicsFile(fuzzer string) (string, *os.File) {
	dir := fuzzForensicsDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "SOCKGUARD-FUZZ-FORENSICS: mkdir %s: %v\n", dir, err)
		return "", nil
	}
	name := fmt.Sprintf("%s-%d.log", fuzzer, os.Getpid())
	path := filepath.Join(dir, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SOCKGUARD-FUZZ-FORENSICS: open %s: %v\n", path, err)
		return path, nil
	}
	return path, file
}

// fuzzForensicsDir is overridable via the SOCKGUARD_FUZZ_FORENSICS_DIR env var
// so CI workflows can plant the dump in a path the upload-artifact step will
// pick up. The default ./forensics resolves under the test's CWD, which the
// monthly workflow sets to app/.
func fuzzForensicsDir() string {
	if override := os.Getenv("SOCKGUARD_FUZZ_FORENSICS_DIR"); override != "" {
		return override
	}
	return "forensics"
}

func emitFuzzForensicsLine(fuzzer, path string, file *os.File, elapsed time.Duration, baseline bool) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	tag := "sample"
	if baseline {
		tag = "baseline"
	}
	line := fmt.Sprintf(
		"SOCKGUARD-FUZZ-FORENSICS: ts=%s tag=%s fuzzer=%s pid=%d elapsed=%s goroutines=%d heap_alloc=%d heap_inuse=%d heap_objects=%d stack_inuse=%d sys=%d open_fds=%d gc_cycles=%d\n",
		time.Now().UTC().Format(time.RFC3339),
		tag,
		fuzzer,
		os.Getpid(),
		elapsed.Truncate(time.Second),
		runtime.NumGoroutine(),
		ms.HeapAlloc,
		ms.HeapInuse,
		ms.HeapObjects,
		ms.StackInuse,
		ms.Sys,
		countOpenFDs(),
		ms.NumGC,
	)
	_, _ = fmt.Fprint(os.Stderr, line)
	if file != nil {
		if _, err := file.WriteString(line); err == nil {
			_ = file.Sync()
		}
	}
	_ = path // retained for future diagnostic log lines
}

// countOpenFDs returns the number of file descriptors held by the current
// process on Linux. Other platforms return -1 (the sampler still runs but
// without FD data — useful when triaging locally on macOS).
func countOpenFDs() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}
