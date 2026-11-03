package logging

import "testing"

func TestDroppedEventsNilReceiver(t *testing.T) {
	t.Parallel()
	var l *AuditLogger
	if got := l.DroppedEvents(); got != 0 {
		t.Fatalf("DroppedEvents() on nil = %d, want 0", got)
	}
}
