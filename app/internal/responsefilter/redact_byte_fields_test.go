package responsefilter

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Docker clients (moby/api, docker/docker) decode these fields as []byte, which
// is base64 on the wire. A "<redacted>" sentinel is not valid base64, so the
// typed decode of the whole response fails. These local structs mirror only the
// []byte fields so the test needs no Docker module.
type byteTLSInfo struct {
	TrustRoot           string
	CertIssuerSubject   []byte
	CertIssuerPublicKey []byte
}

type byteSpecData struct {
	Name string
	Data []byte
}

func TestByteFieldsDecodeIntoTypedStructsAfterRedaction(t *testing.T) {
	t.Parallel()

	// base64 of "issuer-subject-leak", "issuer-pubkey-leak", "payload-leak".
	const (
		subjectB64 = "aXNzdWVyLXN1YmplY3QtbGVhaw=="
		pubB64     = "aXNzdWVyLXB1YmtleS1sZWFr"
		dataB64    = "cGF5bG9hZC1sZWFr"
	)
	tls := `{"TrustRoot":"pem-leak","CertIssuerSubject":"` + subjectB64 + `","CertIssuerPublicKey":"` + pubB64 + `"}`

	tests := []struct {
		name   string
		path   string
		body   string
		decode func(t *testing.T, body []byte)
	}{
		{
			name: "node inspect",
			path: "/v1.53/nodes/node-1",
			body: `{"ID":"node-1","Description":{"TLSInfo":` + tls + `}}`,
			decode: func(t *testing.T, body []byte) {
				var v struct{ Description struct{ TLSInfo byteTLSInfo } }
				mustUnmarshal(t, body, &v)
				assertEmptyBytes(t, v.Description.TLSInfo.CertIssuerSubject, v.Description.TLSInfo.CertIssuerPublicKey)
			},
		},
		{
			name: "node list",
			path: "/v1.53/nodes",
			body: `[{"ID":"node-1","Description":{"TLSInfo":` + tls + `}}]`,
			decode: func(t *testing.T, body []byte) {
				var v []struct{ Description struct{ TLSInfo byteTLSInfo } }
				mustUnmarshal(t, body, &v)
				assertEmptyBytes(t, v[0].Description.TLSInfo.CertIssuerSubject, v[0].Description.TLSInfo.CertIssuerPublicKey)
			},
		},
		{
			name: "swarm inspect",
			path: "/v1.53/swarm",
			body: `{"ID":"swarm-1","TLSInfo":` + tls + `}`,
			decode: func(t *testing.T, body []byte) {
				var v struct{ TLSInfo byteTLSInfo }
				mustUnmarshal(t, body, &v)
				assertEmptyBytes(t, v.TLSInfo.CertIssuerSubject, v.TLSInfo.CertIssuerPublicKey)
			},
		},
		{
			name: "info on a swarm manager",
			path: "/v1.53/info",
			body: `{"Swarm":{"NodeID":"node-1","Cluster":{"TLSInfo":` + tls + `}}}`,
			decode: func(t *testing.T, body []byte) {
				var v struct {
					Swarm struct{ Cluster struct{ TLSInfo byteTLSInfo } }
				}
				mustUnmarshal(t, body, &v)
				assertEmptyBytes(t, v.Swarm.Cluster.TLSInfo.CertIssuerSubject, v.Swarm.Cluster.TLSInfo.CertIssuerPublicKey)
			},
		},
		{
			name: "config inspect",
			path: "/v1.53/configs/cfg-1",
			body: `{"ID":"cfg-1","Spec":{"Name":"cfg","Data":"` + dataB64 + `"}}`,
			decode: func(t *testing.T, body []byte) {
				var v struct{ Spec byteSpecData }
				mustUnmarshal(t, body, &v)
				assertEmptyBytes(t, v.Spec.Data)
			},
		},
		{
			name: "secret inspect",
			path: "/v1.53/secrets/sec-1",
			body: `{"ID":"sec-1","Spec":{"Name":"sec","Data":"` + dataB64 + `"}}`,
			decode: func(t *testing.T, body []byte) {
				var v struct{ Spec byteSpecData }
				mustUnmarshal(t, body, &v)
				assertEmptyBytes(t, v.Spec.Data)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := New(Options{
				RedactContainerEnv:    true,
				RedactMountPaths:      true,
				RedactNetworkTopology: true,
				RedactSensitiveData:   true,
			})
			resp := newResponseForTest(t, http.MethodGet, tt.path, tt.body)
			if err := f.ModifyResponse(resp); err != nil {
				t.Fatalf("ModifyResponse: %v", err)
			}
			out, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			for _, leak := range []string{subjectB64, pubB64, dataB64, "pem-leak"} {
				if strings.Contains(string(out), leak) {
					t.Fatalf("response leaks %q: %s", leak, out)
				}
			}
			tt.decode(t, out)
		})
	}
}

func mustUnmarshal(t *testing.T, body []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("typed decode failed: %v\nbody: %s", err, body)
	}
}

func assertEmptyBytes(t *testing.T, fields ...[]byte) {
	t.Helper()
	for i, b := range fields {
		if len(b) != 0 {
			t.Fatalf("byte field %d = %q, want empty", i, b)
		}
	}
}
