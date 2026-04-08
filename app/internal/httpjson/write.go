package httpjson

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// Write serializes payload as JSON with the given status code.
func Write(w http.ResponseWriter, status int, payload any) error {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(payload); err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err := w.Write(body.Bytes())
	return err
}
