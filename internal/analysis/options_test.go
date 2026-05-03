package analysis

import (
	"testing"

	"sidersp/internal/config"
)

func TestNewOptionsDisabledWithoutInterface(t *testing.T) {
	t.Parallel()

	opts, err := NewOptions(config.AnalysisConfig{}, config.XSKConfig{Enabled: true})
	if err != nil {
		t.Fatalf("NewOptions() error = %v", err)
	}
	if opts.Enabled {
		t.Fatalf("NewOptions() = %+v, want disabled options", opts)
	}
	if opts.QueueSize != defaultQueueSize {
		t.Fatalf("NewOptions() queue size = %d, want %d", opts.QueueSize, defaultQueueSize)
	}
}

func TestNewOptionsEnabledWithInterface(t *testing.T) {
	t.Parallel()

	opts, err := NewOptions(
		config.AnalysisConfig{
			Interface: " eth2 ",
			WorkerCPUs: map[int]int{
				0: 4,
			},
		},
		config.XSKConfig{Enabled: true},
	)
	if err != nil {
		t.Fatalf("NewOptions() error = %v", err)
	}
	if !opts.Enabled {
		t.Fatalf("NewOptions() = %+v, want enabled options", opts)
	}
	if opts.Interface != "eth2" {
		t.Fatalf("NewOptions() interface = %q, want %q", opts.Interface, "eth2")
	}
	if got := opts.WorkerCPUs[0]; got != 4 {
		t.Fatalf("NewOptions() worker cpu = %d, want 4", got)
	}
	if opts.QueueSize != defaultQueueSize {
		t.Fatalf("NewOptions() queue size = %d, want %d", opts.QueueSize, defaultQueueSize)
	}
}

func TestNewOptionsDisabledWithoutXSK(t *testing.T) {
	t.Parallel()

	opts, err := NewOptions(
		config.AnalysisConfig{Interface: "eth2"},
		config.XSKConfig{},
	)
	if err != nil {
		t.Fatalf("NewOptions() error = %v", err)
	}
	if opts.Enabled {
		t.Fatalf("NewOptions() = %+v, want disabled options", opts)
	}
}
