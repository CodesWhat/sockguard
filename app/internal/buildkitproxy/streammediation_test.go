package buildkitproxy

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/codeswhat/sockguard/app/internal/buildkitproto/upload"
)

func TestIsStreamMediatedMethod(t *testing.T) {
	cases := []struct {
		name     string
		endpoint Endpoint
		service  string
		method   string
		want     bool
	}{
		{"FileSync DiffCopy on session is mediated", EndpointSession, "moby.filesync.v1.FileSync", "DiffCopy", true},
		{"FileSend DiffCopy on session is mediated", EndpointSession, "moby.filesync.v1.FileSend", "DiffCopy", true},
		{"Upload Pull on session is mediated", EndpointSession, "moby.upload.v1.Upload", "Pull", true},
		{"FileSync TarStream is not stream-mediated (stays hard-denied)", EndpointSession, "moby.filesync.v1.FileSync", "TarStream", false},
		{"wrong method name on FileSync", EndpointSession, "moby.filesync.v1.FileSync", "Frobnicate", false},
		{"wrong service entirely", EndpointSession, "moby.buildkit.v1.Control", "Solve", false},
		{"same service/method but on EndpointGRPC is not stream-mediated", EndpointGRPC, "moby.filesync.v1.FileSync", "DiffCopy", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isStreamMediatedMethod(tc.endpoint, tc.service, tc.method); got != tc.want {
				t.Fatalf("isStreamMediatedMethod(%v, %q, %q) = %v, want %v", tc.endpoint, tc.service, tc.method, got, tc.want)
			}
		})
	}
}

// TestForwardStreamMediatedUnknownServiceFailsClosed exercises
// forwardStreamMediated's defensive switch default directly, mirroring
// TestForwardControlMediatedUnknownMethodFailsClosed: isStreamMediatedMethod's
// table above lists exactly the three services this dispatches, so the
// default arm is unreachable in production, but if the two ever drift it
// must fail CLOSED rather than forward with zero policy evaluation.
func TestForwardStreamMediatedUnknownServiceFailsClosed(t *testing.T) {
	b := newUnitTestBridge(t, &fakeClientLeg{})

	req := httptest.NewRequest(http.MethodPost, "/moby.filesync.v1.NotAService/DiffCopy", strings.NewReader(""))
	rec := httptest.NewRecorder()

	b.forwardStreamMediated(rec, req, "moby.filesync.v1.NotAService", "DiffCopy")

	code, msg := grpcStatusOf(t, rec.Result())
	if code != grpcCodeInternal {
		t.Fatalf("Grpc-Status = %d, want %d (Internal)", code, grpcCodeInternal)
	}
	if msg == "" {
		t.Fatal("Grpc-Message is empty, want a fixed denial message")
	}
}

// --- streamRelayReader -------------------------------------------------

func TestStreamRelayReaderForwardsAdmittedFramesVerbatim(t *testing.T) {
	src := io.NopCloser(bytes.NewReader(append(grpcFrame([]byte("one")), grpcFrame([]byte("two"))...)))
	r := &streamRelayReader{src: src, validate: func([]byte) *mediationDenial { return nil }}

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	want := append(grpcFrame([]byte("one")), grpcFrame([]byte("two"))...)
	if !bytes.Equal(got, want) {
		t.Fatalf("relayed bytes = %v, want the original frames verbatim %v", got, want)
	}
}

func TestStreamRelayReaderCleanEOFHasNoDenial(t *testing.T) {
	src := io.NopCloser(bytes.NewReader(nil))
	r := &streamRelayReader{src: src, validate: func([]byte) *mediationDenial { return nil }}

	buf := make([]byte, 4)
	_, err := r.Read(buf)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
	if r.Denial() != nil {
		t.Fatalf("denial = %+v, want nil after a clean EOF", r.Denial())
	}
}

func TestStreamRelayReaderValidateDenialIsSticky(t *testing.T) {
	src := io.NopCloser(bytes.NewReader(append(grpcFrame([]byte("bad")), grpcFrame([]byte("more"))...)))
	calls := 0
	r := &streamRelayReader{src: src, validate: func([]byte) *mediationDenial {
		calls++
		return deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
	}}

	buf := make([]byte, 4)
	_, err1 := r.Read(buf)
	if err1 == nil {
		t.Fatal("first Read() = nil error, want the validate denial's sentinel error")
	}
	if r.Denial() == nil || r.Denial().reasonCode != "buildkit_schema_unsupported" {
		t.Fatalf("denial = %+v, want buildkit_schema_unsupported", r.Denial())
	}

	_, err2 := r.Read(buf)
	if !errors.Is(err2, err1) {
		t.Fatalf("second Read() err = %v, want the same sticky error %v", err2, err1)
	}
	if calls != 1 {
		t.Fatalf("validate called %d times, want exactly 1 — a denied frame must not be re-validated on the next Read", calls)
	}
}

func TestStreamRelayReaderMalformedFramingDeniesProtocolError(t *testing.T) {
	src := io.NopCloser(bytes.NewReader([]byte{0, 0, 0, 0, 5, 'h', 'i'})) // declares 5 bytes, only 2 present
	r := &streamRelayReader{src: src, validate: func([]byte) *mediationDenial { return nil }}

	_, err := io.ReadAll(r)
	if err == nil {
		t.Fatal("ReadAll() = nil error, want a protocol error")
	}
	if r.Denial() == nil {
		t.Fatal("denial = nil, want a denial for malformed framing")
	}
	if r.Denial().reasonCode != "buildkit_protocol_error" {
		t.Fatalf("reasonCode = %q, want buildkit_protocol_error", r.Denial().reasonCode)
	}
}

func TestStreamRelayReaderOversizedFrameDeniesMessageTooLarge(t *testing.T) {
	src := io.NopCloser(bytes.NewReader(grpcFrame(bytes.Repeat([]byte("x"), 100))))
	r := &streamRelayReader{src: src, maxLen: 10, validate: func([]byte) *mediationDenial { return nil }}

	_, err := io.ReadAll(r)
	if err == nil {
		t.Fatal("ReadAll() = nil error, want a size-cap error")
	}
	if r.Denial() == nil || r.Denial().reasonCode != "buildkit_message_too_large" {
		t.Fatalf("denial = %+v, want buildkit_message_too_large", r.Denial())
	}
	if r.Denial().code != grpcCodeResourceExhausted {
		t.Fatalf("denial.code = %d, want %d (ResourceExhausted)", r.Denial().code, grpcCodeResourceExhausted)
	}
}

func TestStreamRelayReaderDenialAccessorIsRaceFree(t *testing.T) {
	// Read runs on one goroutine (as golang.org/x/net/http2.Transport pumps
	// the outgoing body) while Denial() is polled from another (as
	// forwardStreamRelay reads the sticky denial after RoundTrip returns for a
	// reason unrelated to this reader). Under `go test -race` this asserts the
	// atomic accessor is memory-safe; the plain-pointer field it replaced
	// would flag a data race on this exact interleaving.
	pr, pw := io.Pipe()
	r := &streamRelayReader{src: pr, validate: func([]byte) *mediationDenial {
		return deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
	}}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.ReadAll(r) // drives Read -> validate -> denial.Store, then errors out
	}()
	go func() {
		_, _ = pw.Write(grpcFrame([]byte("payload")))
		_ = pw.Close()
	}()

	var got *mediationDenial
	for {
		if got = r.Denial(); got != nil {
			break
		}
		select {
		case <-done:
			if got = r.Denial(); got == nil {
				t.Fatal("Read completed without recording a denial")
			}
		default:
		}
	}
	<-done
	if got.reasonCode != "buildkit_schema_unsupported" {
		t.Fatalf("Denial() reasonCode = %q, want buildkit_schema_unsupported", got.reasonCode)
	}
}

func TestStreamRelayReaderClose(t *testing.T) {
	closed := false
	src := fakeCloser{Reader: bytes.NewReader(nil), onClose: func() { closed = true }}
	r := &streamRelayReader{src: src}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !closed {
		t.Fatal("Close() did not close the underlying src")
	}
}

type fakeCloser struct {
	io.Reader
	onClose func()
}

func (f fakeCloser) Close() error {
	f.onClose()
	return nil
}

// --- relayValidatedFrames ------------------------------------------------

func TestRelayValidatedFramesForwardsAdmittedFramesAndReturnsCleanly(t *testing.T) {
	src := bytes.NewReader(append(grpcFrame([]byte("one")), grpcFrame([]byte("two"))...))
	rec := httptest.NewRecorder()

	denial, err := relayValidatedFrames(rec, src, 0, func([]byte) *mediationDenial { return nil })
	if denial != nil || err != nil {
		t.Fatalf("relayValidatedFrames() = (%v, %v), want (nil, nil)", denial, err)
	}
	want := append(grpcFrame([]byte("one")), grpcFrame([]byte("two"))...)
	if got := rec.Body.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("written bytes = %v, want the original frames verbatim %v", got, want)
	}
}

func TestRelayValidatedFramesValidateDenial(t *testing.T) {
	src := bytes.NewReader(grpcFrame([]byte("bad")))
	rec := httptest.NewRecorder()

	denial, err := relayValidatedFrames(rec, src, 0, func([]byte) *mediationDenial {
		return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "denied by policy")
	})
	if err != nil {
		t.Fatalf("err = %v, want nil (a validate denial is not an I/O error)", err)
	}
	if denial == nil || denial.reasonCode != "buildkit_policy_denied" {
		t.Fatalf("denial = %+v, want buildkit_policy_denied", denial)
	}
}

func TestRelayValidatedFramesMalformedFraming(t *testing.T) {
	src := bytes.NewReader([]byte{0, 0, 0, 0, 5, 'h', 'i'})
	rec := httptest.NewRecorder()

	denial, err := relayValidatedFrames(rec, src, 0, func([]byte) *mediationDenial { return nil })
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if denial == nil || denial.reasonCode != "buildkit_protocol_error" {
		t.Fatalf("denial = %+v, want buildkit_protocol_error", denial)
	}
}

func TestRelayValidatedFramesOversizedFrame(t *testing.T) {
	src := bytes.NewReader(grpcFrame(bytes.Repeat([]byte("x"), 100)))
	rec := httptest.NewRecorder()

	denial, err := relayValidatedFrames(rec, src, 10, func([]byte) *mediationDenial { return nil })
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if denial == nil || denial.reasonCode != "buildkit_message_too_large" {
		t.Fatalf("denial = %+v, want buildkit_message_too_large", denial)
	}
}

func TestRelayValidatedFramesWriteError(t *testing.T) {
	src := bytes.NewReader(grpcFrame([]byte("one")))
	w := &failingResponseWriter{httptest.NewRecorder(), errors.New("write failed")}

	denial, err := relayValidatedFrames(w, src, 0, func([]byte) *mediationDenial { return nil })
	if denial != nil {
		t.Fatalf("denial = %+v, want nil (this is a transport failure, not a policy denial)", denial)
	}
	if err == nil {
		t.Fatal("err = nil, want the write failure")
	}
}

// failingResponseWriter wraps a *httptest.ResponseRecorder so Write always
// fails, exercising relayValidatedFrames' io-error return path — the
// ResponseRecorder itself never fails a Write, so this is the only way to
// reach that branch deterministically.
type failingResponseWriter struct {
	*httptest.ResponseRecorder
	err error
}

func (f *failingResponseWriter) Write([]byte) (int, error) {
	return 0, f.err
}

// --- bytesMessageCapValidator / rawByteCapValidator -----------------------

func TestBytesMessageCapValidatorAdmitsUnderCap(t *testing.T) {
	v := &bytesMessageCapValidator{newMsg: func() proto.Message { return &upload.BytesMessage{} }, maxTotalBytes: 100}
	payload := mustMarshal(t, &upload.BytesMessage{Data: []byte("hello")})
	if d := v.validate(payload); d != nil {
		t.Fatalf("validate() = %+v, want nil (admitted)", d)
	}
}

func TestBytesMessageCapValidatorRejectsMalformed(t *testing.T) {
	v := &bytesMessageCapValidator{newMsg: func() proto.Message { return &upload.BytesMessage{} }, maxTotalBytes: 100}
	d := v.validate([]byte{0xff, 0xff, 0xff})
	if d == nil || d.reasonCode != "buildkit_protocol_error" {
		t.Fatalf("validate() = %+v, want buildkit_protocol_error", d)
	}
}

func TestBytesMessageCapValidatorRejectsUnknownFields(t *testing.T) {
	v := &bytesMessageCapValidator{newMsg: func() proto.Message { return &upload.BytesMessage{} }, maxTotalBytes: 100}
	d := v.validate(unknownFieldBytes())
	if d == nil || d.reasonCode != "buildkit_schema_unsupported" {
		t.Fatalf("validate() = %+v, want buildkit_schema_unsupported", d)
	}
}

func TestBytesMessageCapValidatorTripsCumulativeCap(t *testing.T) {
	v := &bytesMessageCapValidator{newMsg: func() proto.Message { return &upload.BytesMessage{} }, maxTotalBytes: 5}
	first := mustMarshal(t, &upload.BytesMessage{Data: []byte("abc")})
	if d := v.validate(first); d != nil {
		t.Fatalf("first validate() = %+v, want nil", d)
	}
	second := mustMarshal(t, &upload.BytesMessage{Data: []byte("abc")})
	d := v.validate(second)
	if d == nil || d.reasonCode != "buildkit_byte_limit_exceeded" {
		t.Fatalf("second validate() = %+v, want buildkit_byte_limit_exceeded", d)
	}
}

func TestBytesMessageCapValidatorZeroCapDisablesLimit(t *testing.T) {
	v := &bytesMessageCapValidator{newMsg: func() proto.Message { return &upload.BytesMessage{} }}
	for range 3 {
		payload := mustMarshal(t, &upload.BytesMessage{Data: bytes.Repeat([]byte("x"), 1000)})
		if d := v.validate(payload); d != nil {
			t.Fatalf("validate() = %+v, want nil (cap disabled)", d)
		}
	}
}

func TestRawByteCapValidatorAdmitsUnderCap(t *testing.T) {
	v := &rawByteCapValidator{maxTotalBytes: 100}
	// Deliberately not protobuf-shaped bytes at all — rawByteCapValidator
	// must never attempt to decode, only count.
	if d := v.validate([]byte{0xff, 0xff, 0xff}); d != nil {
		t.Fatalf("validate() = %+v, want nil (admitted, no decode attempted)", d)
	}
}

func TestRawByteCapValidatorTripsCumulativeCap(t *testing.T) {
	v := &rawByteCapValidator{maxTotalBytes: 5}
	if d := v.validate([]byte("abc")); d != nil {
		t.Fatalf("first validate() = %+v, want nil", d)
	}
	d := v.validate([]byte("abc"))
	if d == nil || d.reasonCode != "buildkit_byte_limit_exceeded" {
		t.Fatalf("second validate() = %+v, want buildkit_byte_limit_exceeded", d)
	}
}

// TestRawByteCapValidatorAdmitsExactlyAtCap pins the cap's own boundary:
// total landing exactly ON maxTotalBytes must admit, only strictly
// exceeding it (TestRawByteCapValidatorTripsCumulativeCap above) denies.
func TestRawByteCapValidatorAdmitsExactlyAtCap(t *testing.T) {
	v := &rawByteCapValidator{maxTotalBytes: 5}
	if d := v.validate([]byte("abcde")); d != nil {
		t.Fatalf("validate() with total exactly at maxTotalBytes = %+v, want nil", d)
	}
}

func TestRawByteCapValidatorZeroCapDisablesLimit(t *testing.T) {
	v := &rawByteCapValidator{}
	if d := v.validate(bytes.Repeat([]byte("x"), 10000)); d != nil {
		t.Fatalf("validate() = %+v, want nil (cap disabled)", d)
	}
}

// --- forwardStreamRelay ----------------------------------------------------

// drainingFakeClientLeg reads r.Body to completion before returning resp/err
// (as golang.org/x/net/http2.Transport genuinely does when pumping an
// outgoing streaming request body), so tests can drive
// streamRelayReader-originated denials/errors deterministically through
// forwardStreamRelay without a live transport — mirroring bridge_test.go's
// own fakeClientLeg rationale, extended to actually consume the body since
// forwardStreamRelay's request-side behavior (unlike forward()'s) depends on
// the body actually being read.
type drainingFakeClientLeg struct {
	resp   *http.Response
	err    error
	gotReq *http.Request
}

func (f *drainingFakeClientLeg) RoundTrip(r *http.Request) (*http.Response, error) {
	f.gotReq = r
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		return nil, err
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func (f *drainingFakeClientLeg) Close() error { return nil }

func TestForwardStreamRelayRequestDenialEndsStreamWithoutClosingTunnel(t *testing.T) {
	fake := &drainingFakeClientLeg{}
	b := newUnitTestBridge(t, fake)

	req := httptest.NewRequest(http.MethodPost, "/moby.upload.v1.Upload/Pull", bytes.NewReader(grpcFrame([]byte("x"))))
	rec := httptest.NewRecorder()

	reqValidate := func([]byte) *mediationDenial {
		return deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
	}
	relayResponse := func(http.ResponseWriter, io.Reader) (*mediationDenial, error) {
		t.Fatal("relayResponse must not be called when the request direction is denied")
		return nil, nil
	}

	b.forwardStreamRelay(rec, req, "moby.upload.v1.Upload", "Pull", reqValidate, relayResponse)

	code, _ := grpcStatusOf(t, rec.Result())
	if code != grpcCodeFailedPrecondition {
		t.Fatalf("Grpc-Status = %d, want %d (FailedPrecondition)", code, grpcCodeFailedPrecondition)
	}
	if b.closeErr != nil {
		t.Fatalf("closeErr = %v, want nil — a request-side denial is stream-local, not tunnel-ending", b.closeErr)
	}
}

func TestForwardStreamRelayGenericRoundTripErrorTerminatesTunnel(t *testing.T) {
	fake := &drainingFakeClientLeg{err: errors.New("connection reset by peer")}
	b := newUnitTestBridge(t, fake)

	req := httptest.NewRequest(http.MethodPost, "/moby.upload.v1.Upload/Pull", bytes.NewReader(grpcFrame([]byte("x"))))
	rec := httptest.NewRecorder()

	reqValidate := func([]byte) *mediationDenial { return nil }
	relayResponse := func(http.ResponseWriter, io.Reader) (*mediationDenial, error) {
		t.Fatal("relayResponse must not be called when RoundTrip itself fails")
		return nil, nil
	}

	b.forwardStreamRelay(rec, req, "moby.upload.v1.Upload", "Pull", reqValidate, relayResponse)

	if b.closeErr == nil {
		t.Fatal("closeErr = nil, want a non-nil error — a genuine transport failure must terminate the tunnel")
	}
	if !strings.Contains(b.closeErr.Error(), "connection reset by peer") {
		t.Fatalf("closeErr = %v, want it to wrap the RoundTrip error", b.closeErr)
	}
}

func TestForwardStreamRelayResponseDenialWritesTrailerStatus(t *testing.T) {
	fake := &drainingFakeClientLeg{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("")),
	}}
	b := newUnitTestBridge(t, fake)

	req := httptest.NewRequest(http.MethodPost, "/moby.upload.v1.Upload/Pull", bytes.NewReader(grpcFrame([]byte("x"))))
	rec := httptest.NewRecorder()

	reqValidate := func([]byte) *mediationDenial { return nil }
	relayResponse := func(http.ResponseWriter, io.Reader) (*mediationDenial, error) {
		return deny(grpcCodeResourceExhausted, "buildkit_byte_limit_exceeded", "cumulative bytes exceeded"), nil
	}

	b.forwardStreamRelay(rec, req, "moby.upload.v1.Upload", "Pull", reqValidate, relayResponse)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (response headers are already committed by the time a response-side denial fires)", rec.Code)
	}
	code, _ := grpcStatusOf(t, rec.Result())
	if code != grpcCodeResourceExhausted {
		t.Fatalf("Grpc-Status = %d, want %d (ResourceExhausted, from the trailer)", code, grpcCodeResourceExhausted)
	}
	if b.closeErr != nil {
		t.Fatalf("closeErr = %v, want nil — one response-side denial is under the abuse budget, so the tunnel stays open", b.closeErr)
	}
}

func TestForwardStreamRelayResponseDenialCountsAgainstAbuseBudget(t *testing.T) {
	// A response-side denial is as client-driven as a request-side one on
	// EndpointSession (see forwardStreamRelay's response-arm comment), so it
	// must count against DeniedStreamBudget. With a budget of 1, the SECOND
	// response-side denial exceeds it and tears the tunnel down.
	newFake := func() *drainingFakeClientLeg {
		return &drainingFakeClientLeg{resp: &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader("")),
		}}
	}
	b := newUnitTestBridge(t, newFake())
	b.guard = newStreamAbuseGuard(Limits{DeniedStreamBudget: 1, DeniedStreamWindow: time.Minute})

	reqValidate := func([]byte) *mediationDenial { return nil }
	relayResponse := func(http.ResponseWriter, io.Reader) (*mediationDenial, error) {
		return deny(grpcCodeResourceExhausted, "buildkit_byte_limit_exceeded", "cumulative bytes exceeded"), nil
	}

	call := func() {
		b.clientLeg = newFake()
		req := httptest.NewRequest(http.MethodPost, "/moby.upload.v1.Upload/Pull", bytes.NewReader(grpcFrame([]byte("x"))))
		b.forwardStreamRelay(httptest.NewRecorder(), req, "moby.upload.v1.Upload", "Pull", reqValidate, relayResponse)
	}

	call()
	if b.closeErr != nil {
		t.Fatalf("closeErr = %v after one denial, want nil (budget=1 not yet exceeded)", b.closeErr)
	}
	call()
	if b.closeErr == nil {
		t.Fatal("closeErr = nil after a second response-side denial, want the tunnel torn down — response denials must count against the abuse budget")
	}
}

func TestForwardStreamRelayResponseCopyErrorTerminatesTunnel(t *testing.T) {
	fake := &drainingFakeClientLeg{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("")),
	}}
	b := newUnitTestBridge(t, fake)

	req := httptest.NewRequest(http.MethodPost, "/moby.upload.v1.Upload/Pull", bytes.NewReader(grpcFrame([]byte("x"))))
	rec := httptest.NewRecorder()

	reqValidate := func([]byte) *mediationDenial { return nil }
	wantErr := errors.New("stream reset")
	relayResponse := func(http.ResponseWriter, io.Reader) (*mediationDenial, error) {
		return nil, wantErr
	}

	b.forwardStreamRelay(rec, req, "moby.upload.v1.Upload", "Pull", reqValidate, relayResponse)

	if b.closeErr == nil {
		t.Fatal("closeErr = nil, want a non-nil error")
	}
	if !strings.Contains(b.closeErr.Error(), "stream reset") {
		t.Fatalf("closeErr = %v, want it to wrap the relayResponse error", b.closeErr)
	}
}

func TestForwardStreamRelaySuccessCopiesTrailersAndDefaultsHost(t *testing.T) {
	fake := &drainingFakeClientLeg{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"X-Foo": []string{"bar"}},
		Trailer:    http.Header{"Grpc-Status": []string{"0"}},
		Body:       io.NopCloser(strings.NewReader("")),
	}}
	b := newUnitTestBridge(t, fake)

	req := httptest.NewRequest(http.MethodPost, "/moby.upload.v1.Upload/Pull", bytes.NewReader(grpcFrame([]byte("x"))))
	req.Host = ""
	rec := httptest.NewRecorder()

	reqValidate := func([]byte) *mediationDenial { return nil }
	relayResponse := func(http.ResponseWriter, io.Reader) (*mediationDenial, error) { return nil, nil }

	b.forwardStreamRelay(rec, req, "moby.upload.v1.Upload", "Pull", reqValidate, relayResponse)

	if got := rec.Header().Get("X-Foo"); got != "bar" {
		t.Fatalf("response header X-Foo = %q, want %q (copied from resp)", got, "bar")
	}
	if got := rec.Result().Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("trailer Grpc-Status = %q, want %q", got, "0")
	}
	if b.closeErr != nil {
		t.Fatalf("closeErr = %v, want nil on a clean success", b.closeErr)
	}
	if fake.gotReq == nil {
		t.Fatal("RoundTrip was never called")
	}
	if fake.gotReq.Host != "buildkitd" {
		t.Fatalf("outgoing request Host = %q, want forwardStreamRelay's default %q", fake.gotReq.Host, "buildkitd")
	}
}
