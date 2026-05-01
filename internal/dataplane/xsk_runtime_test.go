package dataplane

import (
	"context"
	"errors"
	"testing"
)

type stubXSKRuntime struct {
	runErr     error
	closeErr   error
	runCalls   int
	closeCalls int
}

func (s *stubXSKRuntime) Run(context.Context) error {
	s.runCalls++
	return s.runErr
}

func (s *stubXSKRuntime) Close() error {
	s.closeCalls++
	return s.closeErr
}

func TestRuntimeRunXSKWithoutRuntimeIsNoop(t *testing.T) {
	t.Parallel()

	runtime := &Runtime{}
	if err := runtime.RunXSK(context.Background()); err != nil {
		t.Fatalf("RunXSK() error = %v, want nil", err)
	}
}

func TestRuntimeRunXSKDelegatesToXSKRuntime(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("run failed")
	xskRuntime := &stubXSKRuntime{runErr: wantErr}
	runtime := &Runtime{xskRuntime: xskRuntime}

	err := runtime.RunXSK(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("RunXSK() error = %v, want %v", err, wantErr)
	}
	if xskRuntime.runCalls != 1 {
		t.Fatalf("run calls = %d, want 1", xskRuntime.runCalls)
	}
}

func TestRuntimeCloseClosesXSKRuntime(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("close failed")
	xskRuntime := &stubXSKRuntime{closeErr: wantErr}
	runtime := &Runtime{xskRuntime: xskRuntime}

	err := runtime.Close()
	if !errors.Is(err, wantErr) {
		t.Fatalf("Close() error = %v, want %v", err, wantErr)
	}
	if xskRuntime.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", xskRuntime.closeCalls)
	}
	if runtime.xskRuntime != nil {
		t.Fatal("xskRuntime = non-nil after Close()")
	}
}
