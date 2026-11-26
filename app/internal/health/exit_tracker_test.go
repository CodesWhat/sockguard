package health

import (
	"testing"
	"time"
)

func TestDownTracker(t *testing.T) {
	base := time.Unix(1000, 0)
	at := func(s int) time.Time { return base.Add(time.Duration(s) * time.Second) }
	down := func(s int) WatchdogState { return WatchdogState{Up: false, CheckedAt: at(s)} }
	up := func(s int) WatchdogState { return WatchdogState{Up: true, CheckedAt: at(s)} }

	t.Run("healthy never trips", func(t *testing.T) {
		tr := NewDownTracker(10 * time.Second)
		for s := 0; s < 100; s += 5 {
			if _, tripped := tr.Observe(up(s)); tripped {
				t.Fatalf("tripped while healthy at %ds", s)
			}
		}
	})

	t.Run("trips once after continuous outage", func(t *testing.T) {
		tr := NewDownTracker(10 * time.Second)
		for _, s := range []int{0, 5, 9} {
			if _, tripped := tr.Observe(down(s)); tripped {
				t.Fatalf("tripped early at %ds", s)
			}
		}
		d, tripped := tr.Observe(down(10))
		if !tripped || d != 10*time.Second {
			t.Fatalf("Observe(10s) = %v, %v; want 10s, true", d, tripped)
		}
		if _, tripped := tr.Observe(down(15)); tripped {
			t.Fatal("tripped a second time")
		}
	})

	t.Run("recovery resets the clock", func(t *testing.T) {
		tr := NewDownTracker(10 * time.Second)
		tr.Observe(down(0))
		tr.Observe(down(8))
		tr.Observe(up(9))
		if _, tripped := tr.Observe(down(12)); tripped {
			t.Fatal("outage clock was not reset by recovery")
		}
		if _, tripped := tr.Observe(down(21)); tripped {
			t.Fatal("tripped 9s into the second outage")
		}
		if _, tripped := tr.Observe(down(22)); !tripped {
			t.Fatal("did not trip 10s into the second outage")
		}
	})

	t.Run("non-positive threshold and nil never trip", func(t *testing.T) {
		if _, tripped := NewDownTracker(0).Observe(down(1000)); tripped {
			t.Fatal("zero threshold tripped")
		}
		var tr *DownTracker
		if _, tripped := tr.Observe(down(1000)); tripped {
			t.Fatal("nil tracker tripped")
		}
	})
}
