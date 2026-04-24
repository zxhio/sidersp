package dataplane

import "testing"

func TestIngressFailureVerdict(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want uint32
	}{
		{name: "default", raw: "", want: ingressVerdictPass},
		{name: "pass", raw: "pass", want: ingressVerdictPass},
		{name: "drop", raw: "drop", want: ingressVerdictDrop},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := ingressFailureVerdict(tc.raw); got != tc.want {
				t.Fatalf("ingressFailureVerdict(%q) = %d, want %d", tc.raw, got, tc.want)
			}
		})
	}
}
