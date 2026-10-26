package buildkitrunner

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/gateway"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/pb"
	"google.golang.org/protobuf/proto"
)

func TestOperationReportPreservesOriginalBytes(t *testing.T) {
	op := &pb.Op{Op: &pb.Op_Exec{Exec: &pb.ExecOp{Meta: &pb.Meta{Args: []string{"/bin/sh", "-c", "echo reviewed"}}}}}
	raw, err := proto.Marshal(op)
	if err != nil {
		t.Fatal(err)
	}
	// Unknown fields are included in the digest and report, even if the server will reject them.
	raw = append(raw, 0xf8, 0x07, 0x01)
	var output bytes.Buffer
	report := newOperationReporter(&output)
	def := &pb.Definition{Def: [][]byte{raw, raw}}
	if err := report.write(def); err != nil {
		t.Fatal(err)
	}
	var got operationRecord
	decoder := json.NewDecoder(&output)
	if err := decoder.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Digest != fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) || !bytes.Equal(got.Encoded, raw) {
		t.Fatal("report changed the operation identity")
	}
	if decoder.More() {
		t.Fatal("duplicate operation was reported twice")
	}
	if err := report.write(def); err != nil || output.Len() != 0 {
		t.Fatal("repeated solve duplicated operation records")
	}
}

func TestRelayRejectsNonGatewayBeforeUpstream(t *testing.T) {
	relay := &gatewayRelay{report: newOperationReporter(nil)}
	for _, path := range []string{"/moby.buildkit.v1.Control/Solve", "/" + gatewayService + "/ExecProcess", "/" + gatewayService + "/NewContainer", "/other/Ping"} {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(frameMessage(nil)))
		rec := httptest.NewRecorder()
		relay.ServeHTTP(rec, req)
		if rec.Header().Get("Grpc-Status") != "7" {
			t.Fatalf("non-gateway request accepted: %s", path)
		}
	}
}

func TestRelayRejectsMalformedSolveBeforeUpstream(t *testing.T) {
	relay := &gatewayRelay{report: newOperationReporter(nil)}
	payload, err := proto.Marshal(&gateway.SolveRequest{Definition: &pb.Definition{Def: [][]byte{{0xff}}}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/"+gatewayService+"/Solve", bytes.NewReader(frameMessage(payload)))
	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, req)
	if rec.Header().Get("Grpc-Status") != "3" {
		t.Fatal("malformed graph reached upstream")
	}
}
