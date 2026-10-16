package buildkitproxy

import (
	"context"
	"testing"
	"time"
)

func TestRefAdmissionWaitKeepsClientAndProfileIsolation(t *testing.T) {
	for _, other := range []SessionKey{{ClientIdentity: "other", Profile: "restricted"}, {ClientIdentity: "caller", Profile: "other"}} {
		registry := NewSessionRegistry()
		key := SessionKey{ClientIdentity: "caller", Profile: "restricted"}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		result := make(chan bool, 1)
		go func() { result <- registry.waitForRef(ctx, key, "build") }()
		foreign := registry.Open(other, EndpointGRPC, "")
		if !registry.PutRef(foreign, "build", 10) {
			t.Fatal("foreign ref not registered")
		}
		select {
		case <-result:
			t.Fatal("other client/profile satisfied wait")
		case <-time.After(25 * time.Millisecond):
		}
		own := registry.Open(key, EndpointGRPC, "")
		if !registry.PutRef(own, "build", 10) {
			t.Fatal("own ref not registered")
		}
		select {
		case ok := <-result:
			if !ok {
				t.Fatal("own admission didn't satisfy wait")
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if !registry.waitForRef(ctx, key, "build") {
			t.Fatal("already-admitted ref not visible")
		}
	}
}

func TestRefAdmissionWaitStopsAtCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if NewSessionRegistry().waitForRef(ctx, SessionKey{ClientIdentity: "caller"}, "missing") {
		t.Fatal("unadmitted ref granted on cancellation")
	}
}
