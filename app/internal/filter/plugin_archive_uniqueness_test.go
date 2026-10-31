package filter

import (
	"archive/tar"
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPluginCreateRejectsMultipleConfigurations(t *testing.T) {
	t.Parallel()
	allow, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/plugins/create", Action: ActionAllow})
	if err != nil {
		t.Fatal(err)
	}
	for _, gzipEncoded := range []bool{false, true} {
		for _, secondName := range []string{"config.json", "./config.json", "/config.json", "nested/../config.json"} {
			for _, secondConfig := range []string{`{}`, `{"Network":{"Type":"host"}}`} {
				payload := mustPluginCreateContextTarBytes(t, []pluginTarEntry{
					{name: "rootfs/", typ: tar.TypeDir},
					{name: "config.json", body: []byte(`{}`)},
					{name: secondName, body: []byte(secondConfig)},
				}, gzipEncoded)
				reached := false
				handler := MiddlewareWithOptions([]*CompiledRule{allow}, testLogger(), Options{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					reached = true
					w.WriteHeader(http.StatusNoContent)
				}))
				req := httptest.NewRequest(http.MethodPost, "/v1.44/plugins/create?name=acme/plugin", bytes.NewReader(payload))
				t.Cleanup(func() { _ = req.Body.Close() })
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if reached || rec.Code != http.StatusForbidden {
					t.Errorf("gzip=%v name=%q config=%s: reached=%v status=%d", gzipEncoded, secondName, secondConfig, reached, rec.Code)
				}
			}
		}
	}
}
