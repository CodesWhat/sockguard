package proxy

import (
	"context"
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

func handleError(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	w.Write([]byte(`{"message":"upstream Docker socket unreachable","error":"` + err.Error() + `"}`))
}
