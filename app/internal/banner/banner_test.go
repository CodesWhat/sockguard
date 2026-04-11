package banner

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderContainsRuntimeInfo(t *testing.T) {
	var buf bytes.Buffer
	Render(&buf, Info{
		Listen:    "unix:/var/run/sockguard.sock",
		Upstream:  "/var/run/docker.sock",
		Rules:     12,
		LogFormat: "json",
		LogLevel:  "info",
		AccessLog: true,
	})

	out := buf.String()
	wants := []string{
		"unix:/var/run/sockguard.sock",
		"/var/run/docker.sock",
		"rules     12",
		"log json/info",
		"access=on",
		"sockguard ",
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("Render() output missing %q\n---\n%s", w, out)
		}
	}
}

func TestRenderAccessLogOff(t *testing.T) {
	var buf bytes.Buffer
	Render(&buf, Info{AccessLog: false})
	if !strings.Contains(buf.String(), "access=off") {
		t.Errorf("Render() with AccessLog=false should contain access=off, got:\n%s", buf.String())
	}
}

func TestShortCommit(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"abc", "abc"},
		{"abcdef0", "abcdef0"},
		{"abcdef01234567", "abcdef0"},
		{"5fe1940abcdef", "5fe1940"},
	}
	for _, tt := range tests {
		if got := shortCommit(tt.in); got != tt.want {
			t.Errorf("shortCommit(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
