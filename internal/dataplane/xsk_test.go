package dataplane

import (
	"errors"
	"strings"
	"testing"
)

func TestRegisterXSKSocketValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		runtime *Runtime
		queueID int
		want    string
		target  error
	}{
		{
			name:    "nil runtime",
			runtime: nil,
			queueID: 0,
			want:    "nil runtime",
		},
		{
			name:    "negative queue",
			runtime: &Runtime{},
			queueID: -1,
			want:    "queue -1 out of range",
		},
		{
			name:    "queue upper bound",
			runtime: &Runtime{},
			queueID: maxXSKQueues,
			want:    "queue 64 out of range",
		},
		{
			name:    "missing map",
			runtime: &Runtime{},
			queueID: 0,
			target:  errXSKMapUnavailable,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.runtime.RegisterXSKSocket(tc.queueID, 1)
			if err == nil {
				t.Fatal("RegisterXSKSocket() error = nil, want error")
			}
			if tc.target != nil {
				if !errors.Is(err, tc.target) {
					t.Fatalf("RegisterXSKSocket() error = %v, want target %v", err, tc.target)
				}
				return
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("RegisterXSKSocket() error = %q, want %q", err, tc.want)
			}
		})
	}
}
