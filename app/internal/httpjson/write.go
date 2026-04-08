package httpjson

import (
	"encoding/json"
	"net/http"
)

// Write serializes payload as JSON with the given status code.
func Write(w http.ResponseWriter, status int, payload any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(payload)
}
