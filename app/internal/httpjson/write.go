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

	header := w.Header()
	header.Set("Content-Type", "application/json")
	header.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, err := w.Write(body.Bytes())
	return err
}
