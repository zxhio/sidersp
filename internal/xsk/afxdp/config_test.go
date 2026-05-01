package afxdp

import (
	"strings"
	"testing"
)

func TestSocketConfigValidateRequiresTXFrameReserve(t *testing.T) {
	t.Parallel()

	cfg := DefaultSocketConfig()
	cfg.IfIndex = 1
	cfg.TXFrameReserve = 0

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want reserve error")
	}
	if !strings.Contains(err.Error(), "tx frame reserve") {
		t.Fatalf("Validate() error = %q, want tx frame reserve", err)
	}
}

func TestSocketConfigValidateRejectsFillRingSizeWithoutTXBudget(t *testing.T) {
	t.Parallel()

	cfg := DefaultSocketConfig()
	cfg.IfIndex = 1
	cfg.FrameCount = 4096
	cfg.FillRingSize = 4096
	cfg.TXFrameReserve = 1

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want frame budget error")
	}
	if !strings.Contains(err.Error(), "exceeds frame count") {
		t.Fatalf("Validate() error = %q, want frame budget error", err)
	}
}
