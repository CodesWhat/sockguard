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

const (
	contentTypeHeader       = "Content-Type"
	contentTypeJSONValue    = "application/json"
	contentTypeOptionsKey   = "X-Content-Type-Options"
	contentTypeOptionsValue = "nosniff"
)

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

func setJSONHeaders(header http.Header) {
	if header == nil {
		return
	}
	header.Set(contentTypeHeader, contentTypeJSONValue)
	header.Set(contentTypeOptionsKey, contentTypeOptionsValue)
}

// Write serializes payload as JSON with the given status code.
func Write(w http.ResponseWriter, status int, payload any) error {
	body := getJSONBuffer()
	defer putJSONBuffer(body)

	if err := json.NewEncoder(body).Encode(payload); err != nil {
		return err
	}

	setJSONHeaders(w.Header())
	w.WriteHeader(status)
	_, err := w.Write(body.Bytes())
	return err
}
