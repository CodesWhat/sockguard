package proxy

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httputil"
)

// New creates a reverse proxy that forwards requests to the upstream Docker socket.
func New(upstreamSocket string) *httputil.ReverseProxy {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", upstreamSocket)
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
	}

	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "docker"
		},
		Transport:     transport,
		FlushInterval: -1, // immediate flush for streaming endpoints
		ErrorHandler:  handleError,
	}
}

func handleError(w http.ResponseWriter, _ *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	json.NewEncoder(w).Encode(map[string]string{"message": "upstream Docker socket unreachable", "error": err.Error()})
}
