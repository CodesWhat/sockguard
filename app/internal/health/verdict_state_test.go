package health

import (
	"errors"
	"testing"
	"time"
)

// TestStateFromVerdictSetsUpFromErrNilness pins stateFromVerdict's Up field to
// v.err's nilness specifically (v.err == nil), not merely to some correlated
// field like status or present. A verdict with a nil error must report Up:
// true, and a verdict carrying any error must report Up: false, regardless of
// what status string accompanies it.
func TestStateFromVerdictSetsUpFromErrNilness(t *testing.T) {
	checkedAt := time.Unix(1_700_000_000, 0)
	checkErr := errors.New("upstream unreachable")

	tests := []struct {
		name string
		v    verdict
		want bool
	}{
		{
			name: "nil error reports up",
			v:    verdict{status: "connected", err: nil, checkedAt: checkedAt},
			want: true,
		},
		{
			name: "non-nil error reports down",
			v:    verdict{status: "unreachable", err: checkErr, checkedAt: checkedAt},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := stateFromVerdict(tc.v)
			if got.Up != tc.want {
				t.Fatalf("stateFromVerdict(%#v).Up = %v, want %v", tc.v, got.Up, tc.want)
			}
			if got.Status != tc.v.status {
				t.Fatalf("stateFromVerdict(%#v).Status = %q, want %q", tc.v, got.Status, tc.v.status)
			}
			if !errors.Is(got.Err, tc.v.err) {
				t.Fatalf("stateFromVerdict(%#v).Err = %v, want %v", tc.v, got.Err, tc.v.err)
			}
			if !got.CheckedAt.Equal(tc.v.checkedAt) {
				t.Fatalf("stateFromVerdict(%#v).CheckedAt = %v, want %v", tc.v, got.CheckedAt, tc.v.checkedAt)
			}
		})
	}
}
