package buildkitrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/gateway"
	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/pb"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type operationRecord struct {
	Digest    string          `json:"digest"`
	Encoded   []byte          `json:"encoded"`
	Operation json.RawMessage `json:"operation"`
}

type operationReporter struct {
	mu    sync.Mutex
	out   io.Writer
	seen  map[string]bool
	bytes int
	err   error
}

func newOperationReporter(out io.Writer) *operationReporter {
	if out == nil {
		out = io.Discard
	}
	return &operationReporter{out: out, seen: make(map[string]bool)}
}

func (r *operationReporter) write(def *pb.Definition) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	for _, raw := range def.GetDef() {
		digest := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
		if r.seen[digest] {
			continue
		}
		if len(r.seen) >= 4096 || r.bytes+len(raw) > 32<<20 {
			return errors.New("operation report limit exceeded")
		}
		var op pb.Op
		if err := proto.Unmarshal(raw, &op); err != nil {
			return fmt.Errorf("decode reported operation: %w", err)
		}
		description, err := protojson.Marshal(&op)
		if err != nil {
			return err
		}
		if err := json.NewEncoder(r.out).Encode(operationRecord{Digest: digest, Encoded: raw, Operation: description}); err != nil {
			r.err = err
			return err
		}
		r.seen[digest] = true
		r.bytes += len(raw)
	}
	return nil
}

type gatewayRelay struct {
	client *http2.ClientConn
	build  string
	report *operationReporter
}

func (g *gatewayRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	method := strings.TrimPrefix(r.URL.Path, "/"+gatewayService+"/")
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || !strings.HasPrefix(r.URL.Path, "/"+gatewayService+"/") || !gatewayMethod(method) {
		rpcError(w, "7", "frontend may call only the mediated gateway")
		return
	}
	if encoding := r.Header.Get("Grpc-Encoding"); encoding != "" && encoding != "identity" {
		rpcError(w, "3", "compressed gateway messages are not supported")
		return
	}
	payload, err := readMessage(r.Body)
	if err != nil {
		rpcError(w, "3", "invalid gateway request framing")
		return
	}
	if method == "Solve" {
		var solve gateway.SolveRequest
		if err := proto.Unmarshal(payload, &solve); err != nil {
			rpcError(w, "3", "invalid gateway Solve")
			return
		}
		if err := g.report.write(solve.Definition); err != nil {
			rpcError(w, "3", err.Error())
			return
		}
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	out, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://sockguard/"+gatewayService+"/"+method, bytes.NewReader(frameMessage(payload))) // #nosec G704 -- fixed authority on an existing proxy connection; method is restricted to the gateway allowlist above.
	if err != nil {
		rpcError(w, "13", "cannot construct gateway request")
		return
	}
	out.Header.Set("Content-Type", "application/grpc")
	out.Header.Set("Te", "trailers")
	out.Header.Set(buildHeader, g.build)
	response, err := g.client.RoundTrip(out)
	if err != nil {
		rpcError(w, "14", "proxy gateway connection failed")
		return
	}
	defer response.Body.Close()
	body, readErr := readMessage(response.Body)
	if response.StatusCode != http.StatusOK {
		rpcError(w, "14", "proxy returned an HTTP error")
		return
	}
	status := response.Trailer.Get("Grpc-Status")
	if status == "" {
		status = response.Header.Get("Grpc-Status")
	}
	if status == "" || (readErr != nil && (!errors.Is(readErr, io.EOF) || status == "0")) {
		rpcError(w, "13", "invalid gateway response")
		return
	}
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Trailer", "Grpc-Status, Grpc-Message, Grpc-Status-Details-Bin")
	w.WriteHeader(http.StatusOK)
	if readErr == nil {
		if _, err := w.Write(frameMessage(body)); err != nil {
			return
		}
	}
	for _, name := range []string{"Grpc-Status", "Grpc-Message", "Grpc-Status-Details-Bin"} {
		value := response.Trailer.Get(name)
		if value == "" {
			value = response.Header.Get(name)
		}
		if value != "" {
			w.Header().Set(name, value)
		}
	}
}

func gatewayMethod(method string) bool {
	switch method {
	case "Ping", "Solve", "ResolveImageConfig", "ResolveSourceMeta", "ReadFile", "ReadDir", "StatFile", "Evaluate", "Return", "Inputs", "Warn":
		return true
	default:
		return false
	}
}

func rpcError(w http.ResponseWriter, code, message string) {
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Grpc-Status", code)
	// Percent-encode bytes outside the gRPC message header's safe ASCII range.
	var encoded strings.Builder
	for i := 0; i < len(message); i++ {
		c := message[i]
		if c < 0x20 || c >= 0x7f || c == '%' {
			fmt.Fprintf(&encoded, "%%%02X", c)
		} else {
			encoded.WriteByte(c)
		}
	}
	w.Header().Set("Grpc-Message", encoded.String())
	w.WriteHeader(http.StatusOK)
}
