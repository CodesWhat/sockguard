package httpjson

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
)

var jsonBufferPool = sync.Pool{
	New: func() any {
		return &bytes.Buffer{}
	},
}

func getJSONBuffer() *bytes.Buffer {
	buf, _ := jsonBufferPool.Get().(*bytes.Buffer)
	if buf == nil {
		return &bytes.Buffer{}
	}
	buf.Reset()
	return buf
}

func putJSONBuffer(buf *bytes.Buffer) {
	if buf == nil {
		return
	}
	buf.Reset()
	jsonBufferPool.Put(buf)
}

// Write serializes payload as JSON with the given status code.
func Write(w http.ResponseWriter, status int, payload any) error {
	body := getJSONBuffer()
	defer putJSONBuffer(body)

	if err := json.NewEncoder(body).Encode(payload); err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err := w.Write(body.Bytes())
	return err
}
