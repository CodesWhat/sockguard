package httpjson

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWrite(t *testing.T) {
	rec := httptest.NewRecorder()

	err := Write(rec, http.StatusBadGateway, map[string]string{"message": "upstream unreachable"})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["message"] != "upstream unreachable" {
		t.Fatalf("message = %q, want upstream unreachable", body["message"])
	}
}
