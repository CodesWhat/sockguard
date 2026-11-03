package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsStreamingRequest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		method string
		target string
		want   bool
	}{
		{"events", http.MethodGet, "/events", true},
		{"events versioned", http.MethodGet, "/v1.45/events", true},
		{"libpod events", http.MethodGet, "/libpod/events", true},
		{"logs follow", http.MethodGet, "/containers/abc/logs?follow=1", true},
		{"logs follow versioned", http.MethodGet, "/v1.45/containers/abc/logs?follow=true", true},
		{"libpod logs follow", http.MethodGet, "/libpod/containers/abc/logs?follow=true", true},
		{"logs without follow", http.MethodGet, "/containers/abc/logs", false},
		{"logs follow false", http.MethodGet, "/containers/abc/logs?follow=0", false},
		{"stats default streams", http.MethodGet, "/containers/abc/stats", true},
		{"stats stream true", http.MethodGet, "/containers/abc/stats?stream=1", true},
		{"stats one-shot", http.MethodGet, "/containers/abc/stats?stream=0", false},
		{"wait", http.MethodPost, "/containers/abc/wait", true},
		{"libpod wait", http.MethodPost, "/libpod/containers/abc/wait", true},
		{"attach", http.MethodPost, "/containers/abc/attach", true},
		{"libpod attach", http.MethodPost, "/libpod/containers/abc/attach", true},
		{"attach ws", http.MethodGet, "/containers/abc/attach/ws", true},
		{"exec start", http.MethodPost, "/exec/abc/start", true},
		{"libpod exec start", http.MethodPost, "/libpod/exec/abc/start", true},
		{"exec create", http.MethodPost, "/containers/abc/exec", false},
		{"build", http.MethodPost, "/build", false},
		{"prune", http.MethodPost, "/containers/prune", false},
		{"system prune", http.MethodPost, "/system/prune", false},
		{"image pull", http.MethodPost, "/images/create?fromImage=alpine", false},
		{"image push", http.MethodPost, "/images/alpine/push", false},
		{"image load", http.MethodPost, "/images/load", false},
		{"image export", http.MethodGet, "/images/alpine/get", false},
		{"container export", http.MethodGet, "/containers/abc/export", false},
		{"container archive", http.MethodGet, "/containers/abc/archive?path=/x", false},
		{"plugin pull", http.MethodPost, "/plugins/pull", false},
		{"stop is not a stream", http.MethodPost, "/containers/abc/stop", false},
		{"system df", http.MethodGet, "/system/df", false},
		{"container list", http.MethodGet, "/containers/json", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(tc.method, tc.target, nil)
			if got := IsStreamingRequest(httptest.NewRecorder(), req); got != tc.want {
				t.Fatalf("IsStreamingRequest(%s %s) = %v, want %v", tc.method, tc.target, got, tc.want)
			}
		})
	}
	if IsStreamingRequest(httptest.NewRecorder(), nil) {
		t.Fatal("nil request must not be a stream")
	}
}
