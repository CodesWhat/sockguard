package dockerclient_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/dockerclient"
)

func TestNew_TransportValues(t *testing.T) {
	client := dockerclient.New("/var/run/docker.sock")

	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", client.Transport)
	}

	if got, want := tr.MaxIdleConnsPerHost, 10; got != want {
		t.Errorf("MaxIdleConnsPerHost = %d, want %d", got, want)
	}

	if got, want := tr.IdleConnTimeout, 90*time.Second; got != want {
		t.Errorf("IdleConnTimeout = %v, want %v", got, want)
	}
}

func TestNew_DialContextSet(t *testing.T) {
	client := dockerclient.New("/var/run/docker.sock")

	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", client.Transport)
	}

	if tr.DialContext == nil {
		t.Error("DialContext is nil, want a unix-socket dialer")
	}
}
