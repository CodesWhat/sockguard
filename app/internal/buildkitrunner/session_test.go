package buildkitrunner

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSessionProvidesHealthAndOnlyAnonymousCredentials(t *testing.T) {
	for _, tc := range []struct {
		path   string
		status string
		reply  []byte
	}{
		{"/grpc.health.v1.Health/Check", "0", []byte{8, 1}},
		{"/moby.filesync.v1.Auth/Credentials", "0", nil},
		{"/moby.filesync.v1.Auth/GetTokenAuthority", "12", nil},
		{"/moby.filesync.v1.Auth/FetchToken", "12", nil},
		{"/moby.buildkit.secrets.v1.Secrets/GetSecret", "7", nil},
		{"/moby.filesync.v1.FileSync/DiffCopy", "7", nil},
	} {
		t.Run(tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			serveSession(rec, httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(frameMessage(nil))))
			if got := rec.Header().Get("Grpc-Status"); got != tc.status {
				t.Fatalf("status=%s want=%s", got, tc.status)
			}
			if tc.status == "0" {
				reply, err := readMessage(rec.Body)
				if err != nil || !bytes.Equal(reply, tc.reply) {
					t.Fatalf("unexpected callback data: %x %v", reply, err)
				}
			}
		})
	}
}
