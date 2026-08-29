package buildkitproxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// lengthDelimited builds one length-delimited protobuf field (tag + varint
// length + value) — the only wire type every field in controlinfo.go's tables
// uses. Fixtures are assembled from this rather than from generated types
// because InfoResponse/ListWorkersResponse/WorkerRecord are exactly the
// messages buildkitproto never vendored (PROVENANCE.md), which is why the
// filter under test works on wire bytes in the first place.
func lengthDelimited(number protowire.Number, value []byte) []byte {
	out := protowire.AppendTag(nil, number, protowire.BytesType)
	return protowire.AppendBytes(out, value)
}

// The fixture worker below mirrors what a real buildkitd returns: an ID, the
// host-describing label set (hostname included), a platform, a GC policy, a
// version, and a CDI device.
var (
	testWorkerLabelHostname = concatBytes(
		lengthDelimited(1, []byte("org.mobyproject.buildkit.worker.hostname")),
		lengthDelimited(2, []byte("build-host-01.internal")),
	)
	testWorkerLabelExecutor = concatBytes(
		lengthDelimited(1, []byte("org.mobyproject.buildkit.worker.executor")),
		lengthDelimited(2, []byte("oci")),
	)
	testWorkerPlatform = concatBytes(
		lengthDelimited(1, []byte("amd64")),
		lengthDelimited(2, []byte("linux")),
	)
	testWorkerGCPolicy = concatBytes(
		lengthDelimited(3, []byte("unused-filter")),
	)
	testBuildkitVersion = concatBytes(
		lengthDelimited(1, []byte("github.com/moby/buildkit")),
		lengthDelimited(2, []byte("v0.32.0")),
		lengthDelimited(3, []byte("0123456789abcdef")),
		lengthDelimited(4, []byte("1.7")),
	)
	testWorkerCDIDevice = concatBytes(
		lengthDelimited(1, []byte("nvidia.com/gpu=all")),
	)

	testWorkerRecord = concatBytes(
		lengthDelimited(1, []byte("worker-abcdef")),
		lengthDelimited(2, testWorkerLabelHostname),
		lengthDelimited(2, testWorkerLabelExecutor),
		lengthDelimited(3, testWorkerPlatform),
		lengthDelimited(4, testWorkerGCPolicy),
		lengthDelimited(5, testBuildkitVersion),
		lengthDelimited(6, testWorkerCDIDevice),
	)

	testWorkerRecordFiltered = concatBytes(
		lengthDelimited(1, []byte("worker-abcdef")),
		lengthDelimited(3, testWorkerPlatform),
		lengthDelimited(5, testBuildkitVersion),
	)
)

// TestFilterControlResponseMessage is the field-level table: for each of the
// two response shapes, what survives the allowlist and what must not.
func TestFilterControlResponseMessage(t *testing.T) {
	cases := []struct {
		name    string
		table   *responseFieldTable
		payload []byte
		want    []byte
	}{
		{
			name:    "InfoResponse keeps the buildkit version whole",
			table:   controlInfoResponseFields,
			payload: lengthDelimited(1, testBuildkitVersion),
			want:    lengthDelimited(1, testBuildkitVersion),
		},
		{
			name:    "InfoResponse with no version set stays empty",
			table:   controlInfoResponseFields,
			payload: nil,
			want:    []byte{},
		},
		{
			name:    "ListWorkersResponse drops labels, GC policy and CDI devices",
			table:   controlListWorkersResponseFields,
			payload: lengthDelimited(1, testWorkerRecord),
			want:    lengthDelimited(1, testWorkerRecordFiltered),
		},
		{
			name:  "every worker in a multi-worker response is filtered",
			table: controlListWorkersResponseFields,
			payload: concatBytes(
				lengthDelimited(1, testWorkerRecord),
				lengthDelimited(1, testWorkerRecord),
			),
			want: concatBytes(
				lengthDelimited(1, testWorkerRecordFiltered),
				lengthDelimited(1, testWorkerRecordFiltered),
			),
		},
		{
			name:    "a worker with nothing but dropped fields becomes an empty record",
			table:   controlListWorkersResponseFields,
			payload: lengthDelimited(1, lengthDelimited(2, testWorkerLabelHostname)),
			want:    lengthDelimited(1, nil),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, denial := filterControlResponseMessage(tc.payload, tc.table)
			if denial != nil {
				t.Fatalf("filterControlResponseMessage denied a well-formed message: %s/%s", denial.reasonCode, denial.message)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("filtered bytes = %x, want %x", got, tc.want)
			}
		})
	}
}

// TestFilterControlResponseWithholdsHostMetadata is the security assertion
// stated as the thing an attacker wants rather than as a byte comparison: no
// label value, GC-policy value or CDI device name a caller is not permitted
// may survive anywhere in the bytes the client receives.
func TestFilterControlResponseWithholdsHostMetadata(t *testing.T) {
	got, _, denial := filterControlResponseMessage(lengthDelimited(1, testWorkerRecord), controlListWorkersResponseFields)
	if denial != nil {
		t.Fatalf("unexpected denial: %s", denial.reasonCode)
	}

	withheld := []string{
		"org.mobyproject.buildkit.worker.hostname",
		"build-host-01.internal",
		"org.mobyproject.buildkit.worker.executor",
		"unused-filter",
		"nvidia.com/gpu=all",
	}
	for _, s := range withheld {
		if bytes.Contains(got, []byte(s)) {
			t.Errorf("filtered ListWorkersResponse still carries %q", s)
		}
	}

	kept := []string{"worker-abcdef", "amd64", "linux", "v0.32.0"}
	for _, s := range kept {
		if !bytes.Contains(got, []byte(s)) {
			t.Errorf("filtered ListWorkersResponse lost %q, which a client needs to target a build", s)
		}
	}
}

// TestFilterControlResponseMessageFailsClosed covers every way a response can
// fail to parse or filter. None may relay anything: each case must return a
// denial and no bytes at all.
func TestFilterControlResponseMessageFailsClosed(t *testing.T) {
	cases := []struct {
		name           string
		table          *responseFieldTable
		payload        []byte
		wantReasonCode string
		wantCode       int
	}{
		{
			name:           "truncated length prefix",
			table:          controlListWorkersResponseFields,
			payload:        []byte{0x0a, 0x7f},
			wantReasonCode: "buildkit_response_filter_failed",
			wantCode:       grpcCodeInternal,
		},
		{
			name:           "trailing tag with no value",
			table:          controlInfoResponseFields,
			payload:        []byte{0x0a},
			wantReasonCode: "buildkit_response_filter_failed",
			wantCode:       grpcCodeInternal,
		},
		{
			name:           "known field arriving with a varint wire type",
			table:          controlInfoResponseFields,
			payload:        protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 7),
			wantReasonCode: "buildkit_response_filter_failed",
			wantCode:       grpcCodeInternal,
		},
		{
			name:           "dropped field arriving with a varint wire type is still refused, not skipped",
			table:          controlListWorkersResponseFields,
			payload:        lengthDelimited(1, protowire.AppendVarint(protowire.AppendTag(nil, 2, protowire.VarintType), 7)),
			wantReasonCode: "buildkit_response_filter_failed",
			wantCode:       grpcCodeInternal,
		},
		{
			name:           "garbage bytes",
			table:          controlListWorkersResponseFields,
			payload:        []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			wantReasonCode: "buildkit_response_filter_failed",
			wantCode:       grpcCodeInternal,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, denial := filterControlResponseMessage(tc.payload, tc.table)
			if denial == nil {
				t.Fatalf("filterControlResponseMessage admitted %x, want a denial", tc.payload)
			}
			if got != nil {
				t.Fatalf("a denied response still produced %x bytes; nothing may be relayed", got)
			}
			if denial.reasonCode != tc.wantReasonCode {
				t.Errorf("reasonCode = %q, want %q", denial.reasonCode, tc.wantReasonCode)
			}
			if denial.code != tc.wantCode {
				t.Errorf("gRPC code = %d, want %d", denial.code, tc.wantCode)
			}
		})
	}
}

// TestFilterControlUnaryResponseFraming pins the stream shape. Info and
// ListWorkers are unary/unary upstream, but the wire format cannot enforce
// that, so zero messages (a gRPC error status) is accepted and two is not.
func TestFilterControlUnaryResponseFraming(t *testing.T) {
	filteredFrame := grpcFrame(lengthDelimited(1, testWorkerRecordFiltered))

	cases := []struct {
		name           string
		body           []byte
		maxLen         int64
		wantFrame      []byte
		wantReasonCode string
	}{
		{
			name:      "one message is filtered and re-framed",
			body:      grpcFrame(lengthDelimited(1, testWorkerRecord)),
			maxLen:    1 << 20,
			wantFrame: filteredFrame,
		},
		{
			name:      "no message at all is a legal error-status response",
			body:      nil,
			maxLen:    1 << 20,
			wantFrame: nil,
		},
		{
			name:           "a second message on a unary response fails closed",
			body:           append(grpcFrame(lengthDelimited(1, testWorkerRecord)), grpcFrame(lengthDelimited(1, testWorkerRecord))...),
			maxLen:         1 << 20,
			wantReasonCode: "buildkit_response_filter_failed",
		},
		{
			name:           "trailing bytes after the single message fail closed",
			body:           append(grpcFrame(lengthDelimited(1, testWorkerRecord)), 0x00),
			maxLen:         1 << 20,
			wantReasonCode: "buildkit_response_filter_failed",
		},
		{
			name:           "a truncated frame fails closed",
			body:           grpcFrame(lengthDelimited(1, testWorkerRecord))[:8],
			maxLen:         1 << 20,
			wantReasonCode: "buildkit_response_filter_failed",
		},
		{
			name:           "a compressed frame fails closed",
			body:           append([]byte{0x01}, grpcFrame(lengthDelimited(1, testWorkerRecord))[1:]...),
			maxLen:         1 << 20,
			wantReasonCode: "buildkit_response_filter_failed",
		},
		{
			name:           "a frame declaring more than the cap fails closed before allocating",
			body:           grpcFrame(lengthDelimited(1, testWorkerRecord)),
			maxLen:         4,
			wantReasonCode: "buildkit_message_too_large",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frame, _, denial := filterControlUnaryResponse(bytes.NewReader(tc.body), tc.maxLen, controlListWorkersResponseFields)
			if tc.wantReasonCode != "" {
				if denial == nil {
					t.Fatalf("filterControlUnaryResponse admitted %x, want a %s denial", tc.body, tc.wantReasonCode)
				}
				if denial.reasonCode != tc.wantReasonCode {
					t.Errorf("reasonCode = %q, want %q", denial.reasonCode, tc.wantReasonCode)
				}
				if frame != nil {
					t.Errorf("a denied response still produced %x bytes; nothing may be relayed", frame)
				}
				return
			}
			if denial != nil {
				t.Fatalf("unexpected denial %s: %s", denial.reasonCode, denial.message)
			}
			if !bytes.Equal(frame, tc.wantFrame) {
				t.Fatalf("frame = %x, want %x", frame, tc.wantFrame)
			}
		})
	}
}

// TestBridgeControlListWorkersFiltersDaemonResponse drives the whole bridge:
// a daemon that returns a full WorkerRecord, and a client that must receive
// the same message with the host metadata gone.
func TestBridgeControlListWorkersFiltersDaemonResponse(t *testing.T) {
	daemon := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(grpcFrame(lengthDelimited(1, testWorkerRecord)))
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	})

	tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, DefaultLimits(), daemon)

	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/ListWorkers", string(grpcFrame(nil))))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	_ = resp.Body.Close()

	if bytes.Contains(body, []byte("build-host-01.internal")) {
		t.Fatalf("the client received the daemon host's own hostname:\n%x", body)
	}
	if bytes.Contains(body, []byte("nvidia.com/gpu=all")) {
		t.Fatalf("the client received the host's CDI device inventory:\n%x", body)
	}
	want := grpcFrame(lengthDelimited(1, testWorkerRecordFiltered))
	if !bytes.Equal(body, want) {
		t.Fatalf("relayed body = %x, want %x", body, want)
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("Grpc-Status trailer = %q, want %q (the daemon's own trailer must still pass through)", got, "0")
	}
}

// TestBridgeControlInfoFailsClosedOnUnfilterableResponse is the falsification
// case: a daemon response sockguard cannot filter must reach the client as an
// error with no body, never as the daemon's original bytes.
func TestBridgeControlInfoFailsClosedOnUnfilterableResponse(t *testing.T) {
	const secret = "org.mobyproject.buildkit.worker.hostname=build-host-01.internal"

	cases := []struct {
		name           string
		responseBody   []byte
		wantCode       int
		wantReasonCode string
	}{
		{
			name:           "a response that is not gRPC-framed at all",
			responseBody:   []byte(secret),
			wantCode:       grpcCodeInternal,
			wantReasonCode: "buildkit_response_filter_failed",
		},
		{
			name:           "a framed message whose protobuf bytes are malformed",
			responseBody:   grpcFrame([]byte{0x0a, 0x7f, 0x01}),
			wantCode:       grpcCodeInternal,
			wantReasonCode: "buildkit_response_filter_failed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			daemon := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/grpc")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(tc.responseBody)
			})

			logs := &syncLogBuffer{}
			logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			tb := newTestBridgeWithLogger(t, EndpointGRPC, allowAllPolicy, DefaultLimits(), daemon, logger)

			resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/Info", string(grpcFrame(nil))))
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("reading response body: %v", err)
			}
			_ = resp.Body.Close()

			if len(body) != 0 {
				t.Fatalf("an unfilterable response relayed %d body bytes: %q", len(body), body)
			}
			if bytes.Contains(body, []byte(secret)) {
				t.Fatalf("the daemon's unfiltered bytes reached the client: %q", body)
			}
			if got := resp.Header.Get("Grpc-Status"); got != strconv.Itoa(tc.wantCode) {
				t.Fatalf("Grpc-Status header = %q, want %d", got, tc.wantCode)
			}
			if out := logs.String(); !strings.Contains(out, "reason_code="+tc.wantReasonCode) {
				t.Fatalf("audit log missing reason_code=%s:\n%s", tc.wantReasonCode, out)
			}
		})
	}
}

// TestBridgeControlInfoRelaysDaemonErrorStatus confirms the zero-message case
// end to end: a daemon that answers with a gRPC error and no body must have
// that status reach the client untouched, not be turned into a filter denial.
func TestBridgeControlInfoRelaysDaemonErrorStatus(t *testing.T) {
	daemon := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeGRPCStatus(w, grpcCodeUnimplemented, "no such worker backend")
	})

	tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, DefaultLimits(), daemon)

	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/Info", string(grpcFrame(nil))))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, msg := grpcStatusOf(t, resp)
	if code != grpcCodeUnimplemented {
		t.Fatalf("Grpc-Status = %d, want %d (the daemon's own status must pass through); message = %q", code, grpcCodeUnimplemented, msg)
	}
}

// TestBridgeControlInfoForwardsRequestVerbatim pins the other half of the
// registry's Mediate note: only the RESPONSE is mediated for these two, so
// the client's request bytes must still reach the daemon unchanged.
func TestBridgeControlInfoForwardsRequestVerbatim(t *testing.T) {
	requestFilter := lengthDelimited(1, []byte("label=org.mobyproject.buildkit.worker.executor"))
	gotRequest := make(chan []byte, 1)

	daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotRequest <- body
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(grpcFrame(lengthDelimited(1, testWorkerRecord)))
	})

	tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, DefaultLimits(), daemon)

	sent := grpcFrame(requestFilter)
	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/ListWorkers", string(sent)))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	select {
	case got := <-gotRequest:
		if !bytes.Equal(got, sent) {
			t.Fatalf("daemon saw request %x, want the client's exact bytes %x", got, sent)
		}
	default:
		t.Fatal("the daemon never received the request")
	}
}

// TestBridgeControlListWorkersResponseSizeCapStillEnforced proves the cap
// wiring, not the cap logic: forwardControlInfoMediated must hand the
// bridge's own Limits.MaxMessageBytes to the response filter, so an
// oversized daemon reply is refused rather than buffered whole.
func TestBridgeControlListWorkersResponseSizeCapStillEnforced(t *testing.T) {
	oversized := grpcFrame(lengthDelimited(1, bytes.Repeat([]byte("x"), 4096)))
	daemon := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(oversized)
	})

	limits := DefaultLimits()
	limits.MaxMessageBytes = 64

	tb := newTestBridge(t, EndpointGRPC, allowAllPolicy, limits, daemon)

	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/ListWorkers", string(grpcFrame(nil))))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	_ = resp.Body.Close()

	if len(body) != 0 {
		t.Fatalf("an oversized response relayed %d body bytes", len(body))
	}
	if got := resp.Header.Get("Grpc-Status"); got != strconv.Itoa(grpcCodeResourceExhausted) {
		t.Fatalf("Grpc-Status header = %q, want %d (RESOURCE_EXHAUSTED)", got, grpcCodeResourceExhausted)
	}
}

// FuzzFilterControlResponseMessage fuzzes the wire-level rewriter against
// arbitrary bytes, since a Control/Info or Control/ListWorkers response is
// data sockguard parses on behalf of a client that never sees the original.
// The invariants are:
//
//  1. Never panics, for any input against either response table.
//  2. Exactly one of (bytes, nil) or (nil, denial) is returned — a denial
//     never carries bytes, so a caller can never partially trust a failed
//     filter. This is the property the fail-closed posture rests on.
//  3. A denial's reason code is always one of the two the filter defines.
//  4. Output is never longer than input: rewriting only removes fields and
//     re-encodes tags and lengths minimally. This is what makes the uint32
//     length prefix filterControlUnaryResponse writes safe by construction.
//  5. Filtering an already-filtered message is a no-op, so the allowlist
//     reaches a fixed point rather than depending on how many times it ran.
func FuzzFilterControlResponseMessage(f *testing.F) {
	f.Add(lengthDelimited(1, testWorkerRecord), true)
	f.Add(lengthDelimited(1, testBuildkitVersion), false)
	f.Add(testWorkerRecordFiltered, true)
	f.Add([]byte{}, true)
	f.Add([]byte{0x0a}, true)
	f.Add([]byte{0x0a, 0x7f}, false)
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, true)
	f.Add(lengthDelimited(1, lengthDelimited(7, []byte("unreviewed"))), true)

	f.Fuzz(func(t *testing.T, payload []byte, listWorkers bool) {
		table := controlInfoResponseFields
		if listWorkers {
			table = controlListWorkersResponseFields
		}

		got, _, denial := filterControlResponseMessage(payload, table)
		if denial != nil {
			if got != nil {
				t.Fatalf("denial %s still returned %x bytes", denial.reasonCode, got)
			}
			// An unknown field number is dropped and reported now, not
			// denied, so the only denial this function can still produce is
			// "these bytes could not be parsed at all".
			if denial.reasonCode != "buildkit_response_filter_failed" {
				t.Fatalf("unexpected reason code %q", denial.reasonCode)
			}
			return
		}
		if len(got) > len(payload) {
			t.Fatalf("filtered %d bytes into %d; rewriting must never grow a message", len(payload), len(got))
		}

		again, _, denial := filterControlResponseMessage(got, table)
		if denial != nil {
			t.Fatalf("re-filtering an already-filtered message denied it: %s", denial.reasonCode)
		}
		if !bytes.Equal(again, got) {
			t.Fatalf("filtering is not idempotent: %x then %x", got, again)
		}
	})
}

// TestFilterControlResponseMessageDropsUnknownFields is the other half of the
// fails-closed story. An unknown field number is NOT a denial: it is dropped,
// and reported so an operator learns the tables are behind upstream. What
// matters is that dropping withholds exactly what denying would have, which
// is why every case here asserts the payload bytes are gone from the output
// as well as asserting the drift report.
//
// The four shapes are the four depths a future upstream field can appear at,
// and all four have real precedent: upstream added WorkerRecord.5 in v0.11.0,
// WorkerRecord.6 in v0.20.0 and BuildkitVersion.4 in v0.30.0.
func TestFilterControlResponseMessageDropsUnknownFields(t *testing.T) {
	const secret = "org.mobyproject.buildkit.worker.hostname=build-host-01.internal"

	cases := []struct {
		name      string
		table     *responseFieldTable
		payload   []byte
		wantDrift []schemaDriftField
	}{
		{
			name:      "unknown top-level field on InfoResponse",
			table:     controlInfoResponseFields,
			payload:   lengthDelimited(2, []byte(secret)),
			wantDrift: []schemaDriftField{{table: "InfoResponse", number: 2}},
		},
		{
			name:      "unknown field added to WorkerRecord",
			table:     controlListWorkersResponseFields,
			payload:   lengthDelimited(1, lengthDelimited(7, []byte(secret))),
			wantDrift: []schemaDriftField{{table: "WorkerRecord", number: 7}},
		},
		{
			name:      "unknown field added to BuildkitVersion",
			table:     controlInfoResponseFields,
			payload:   lengthDelimited(1, lengthDelimited(5, []byte(secret))),
			wantDrift: []schemaDriftField{{table: "BuildkitVersion", number: 5}},
		},
		{
			name:      "unknown field added to Platform",
			table:     controlListWorkersResponseFields,
			payload:   lengthDelimited(1, lengthDelimited(3, lengthDelimited(6, []byte(secret)))),
			wantDrift: []schemaDriftField{{table: "Platform", number: 6}},
		},
		{
			name:  "a non-length-delimited unknown field is skipped by its own wire type",
			table: controlInfoResponseFields,
			// Field 3, varint. ConsumeFieldValue measures it without the
			// BytesType check known fields get, so this must not be an error.
			payload:   append(protowire.AppendTag(nil, 3, protowire.VarintType), protowire.AppendVarint(nil, 42)...),
			wantDrift: []schemaDriftField{{table: "InfoResponse", number: 3}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, drift, denial := filterControlResponseMessage(tc.payload, tc.table)
			if denial != nil {
				t.Fatalf("an unknown field denied the response (%s); it must be dropped and reported instead", denial.reasonCode)
			}
			if bytes.Contains(got, []byte(secret)) {
				t.Fatalf("dropping let the unknown field's bytes through:\n%x", got)
			}
			if !reflect.DeepEqual(drift, tc.wantDrift) {
				t.Fatalf("drift = %+v, want %+v", drift, tc.wantDrift)
			}
		})
	}
}

// TestFilterControlResponseMessageDedupesRepeatedUnknownFields pins the
// dedup this file's drift collection does at gather time: the same unknown
// field number, repeated any number of times across a response, must yield
// exactly one drift entry, while a genuinely different unknown number still
// gets its own entry, in the order each was first seen. Without this, a
// response carrying one unknown field on every repeated WorkerRecord could
// grow the drift slice far larger than the input it was measuring, for
// entries the downstream schemaDriftLimiter was going to collapse anyway.
func TestFilterControlResponseMessageDedupesRepeatedUnknownFields(t *testing.T) {
	// Field 5 appears three times, field 6 once, interleaved so encounter
	// order isn't just numeric order.
	payload := concatBytes(
		lengthDelimited(5, []byte("a")),
		lengthDelimited(6, []byte("b")),
		lengthDelimited(5, []byte("c")),
		lengthDelimited(5, []byte("d")),
	)
	want := []schemaDriftField{
		{table: "InfoResponse", number: 5},
		{table: "InfoResponse", number: 6},
	}

	_, drift, denial := filterControlResponseMessage(payload, controlInfoResponseFields)
	if denial != nil {
		t.Fatalf("repeated unknown fields denied the response (%s); they must be dropped and reported instead", denial.reasonCode)
	}
	if !reflect.DeepEqual(drift, want) {
		t.Fatalf("drift = %+v, want %+v (field 5 must collapse to one entry, field 6 keeps its own, in first-encounter order)", drift, want)
	}
}

// TestBridgeControlListWorkersDropsAndReportsSchemaDrift is the end-to-end
// version: the call must SUCCEED, the unknown field's bytes must not reach
// the client, and the operator must get both a warning naming the message and
// field and an audit record, so drift is visible without being fatal.
func TestBridgeControlListWorkersDropsAndReportsSchemaDrift(t *testing.T) {
	const secret = "org.mobyproject.buildkit.worker.hostname=build-host-01.internal"

	// A WorkerRecord carrying only a field 7 nobody has reviewed.
	body := grpcFrame(lengthDelimited(1, lengthDelimited(7, []byte(secret))))
	daemon := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	logs := &syncLogBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	// A limiter of its own, not the package-level controlSchemaDrift: that
	// var is shared for the life of the process, so under -count>1 a second
	// run of this test would find field 7 already marked seen by the first
	// and the assertion below would never see the warning it expects.
	limiter := &schemaDriftLimiter{}
	tb := newTestBridgeWithLogger(t, EndpointGRPC, allowAllPolicy, DefaultLimits(), daemon, logger, limiter)

	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.buildkit.v1.Control/ListWorkers", string(grpcFrame(nil))))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	relayed, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	_ = resp.Body.Close()

	if got := resp.Header.Get("Grpc-Status"); got != "" && got != "0" {
		t.Fatalf("Grpc-Status header = %q; schema drift must not fail the call", got)
	}
	if bytes.Contains(relayed, []byte(secret)) {
		t.Fatalf("the unknown field's bytes reached the client: %q", relayed)
	}

	out := logs.String()
	if !strings.Contains(out, "reason_code=buildkit_schema_drift") {
		t.Fatalf("audit log missing reason_code=buildkit_schema_drift:\n%s", out)
	}
	if !strings.Contains(out, "message=WorkerRecord") || !strings.Contains(out, "field=7") {
		t.Fatalf("drift report does not name the message and field an operator has to look up:\n%s", out)
	}
}

// TestSchemaDriftLimiterReportsEachFieldOnce pins the rate limit. ListWorkers
// runs at least once per build, so an unrated warning on a drifted daemon is
// a line per build forever.
func TestSchemaDriftLimiterReportsEachFieldOnce(t *testing.T) {
	var limiter schemaDriftLimiter
	worker7 := schemaDriftField{table: "WorkerRecord", number: 7}

	if !limiter.allow(worker7) {
		t.Fatal("the first sighting of a drifted field must be reported")
	}
	if limiter.allow(worker7) {
		t.Fatal("the same field was reported twice; the limiter is not deduplicating")
	}
	if !limiter.allow(schemaDriftField{table: "Platform", number: 7}) {
		t.Fatal("field 7 in a different message is a different fact and must be reported on its own")
	}
	if !limiter.allow(schemaDriftField{table: "WorkerRecord", number: 8}) {
		t.Fatal("a different field in the same message must be reported on its own")
	}
}
