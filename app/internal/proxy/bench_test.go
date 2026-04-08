package proxy

import "testing"

func BenchmarkIsHijackEndpoint(b *testing.B) {
	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"attach", "POST", "/containers/abc123/attach"},
		{"exec_versioned", "POST", "/v1.45/exec/abc123/start"},
		{"not_hijack", "GET", "/containers/json"},
		{"wrong_method", "GET", "/containers/abc123/attach"},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			for b.Loop() {
				IsHijackEndpoint(c.method, c.path)
			}
		})
	}
}
