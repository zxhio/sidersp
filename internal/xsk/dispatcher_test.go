package xsk

import (
	"context"
	"errors"
	"testing"
)

type stubResponseConsumer struct {
	envelopes []Envelope
	sockets   []Socket
	err       error
	hook      func()
}

func (s *stubResponseConsumer) HandleXSK(_ context.Context, envelope Envelope, socket Socket) error {
	s.envelopes = append(s.envelopes, envelope)
	s.sockets = append(s.sockets, socket)
	if s.hook != nil {
		s.hook()
	}
	return s.err
}

type stubAnalysisSubmitter struct {
	envelopes []Envelope
	err       error
	hook      func()
}

func (s *stubAnalysisSubmitter) SubmitXSK(_ context.Context, envelope Envelope) error {
	s.envelopes = append(s.envelopes, envelope)
	if s.hook != nil {
		s.hook()
	}
	return s.err
}

func TestDispatcherDispatchesToResponseAndAnalysis(t *testing.T) {
	t.Parallel()

	response := &stubResponseConsumer{}
	analysis := &stubAnalysisSubmitter{}
	dispatcher, err := NewDispatcher(Consumers{
		Response: response,
		Analysis: analysis,
	})
	if err != nil {
		t.Fatalf("NewDispatcher() error = %v", err)
	}

	socket := &stubSocket{fd: 42}
	frame := []byte{0xe9, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xaa, 0xbb}
	if err := dispatcher.Dispatch(context.Background(), 5, socket, frame); err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}

	if len(response.envelopes) != 1 {
		t.Fatalf("response envelopes = %d, want 1", len(response.envelopes))
	}
	if response.envelopes[0].QueueID != 5 || response.envelopes[0].Metadata.RuleID != 1001 {
		t.Fatalf("response envelope = %+v, want queue=5 rule=1001", response.envelopes[0])
	}
	if len(analysis.envelopes) != 1 || analysis.envelopes[0].Metadata.Action != 3 {
		t.Fatalf("analysis envelopes = %+v, want icmp_echo_reply envelope", analysis.envelopes)
	}
	if len(response.sockets) != 1 || response.sockets[0] != socket {
		t.Fatalf("response sockets = %+v, want socket passthrough", response.sockets)
	}
}

func TestDispatcherIgnoresAnalysisError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("response failed")
	analysis := &stubAnalysisSubmitter{err: errors.New("queue full")}
	response := &stubResponseConsumer{err: wantErr}
	dispatcher, err := NewDispatcher(Consumers{
		Response: response,
		Analysis: analysis,
	})
	if err != nil {
		t.Fatalf("NewDispatcher() error = %v", err)
	}

	socket := &stubSocket{fd: 42}
	frame := []byte{0xe9, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xaa}
	err = dispatcher.Dispatch(context.Background(), 0, socket, frame)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Dispatch() error = %v, want %v", err, wantErr)
	}
	if len(response.envelopes) != 1 {
		t.Fatalf("response envelopes = %d, want 1", len(response.envelopes))
	}
	if len(analysis.envelopes) != 1 {
		t.Fatalf("analysis envelopes = %d, want 1", len(analysis.envelopes))
	}
}

func TestDispatcherRunsResponseBeforeAnalysis(t *testing.T) {
	t.Parallel()

	var calls []string
	response := &stubResponseConsumer{
		hook: func() {
			calls = append(calls, "response")
		},
	}
	analysis := &stubAnalysisSubmitter{
		hook: func() {
			calls = append(calls, "analysis")
		},
	}
	dispatcher, err := NewDispatcher(Consumers{
		Response: response,
		Analysis: analysis,
	})
	if err != nil {
		t.Fatalf("NewDispatcher() error = %v", err)
	}

	socket := &stubSocket{fd: 42}
	frame := []byte{0xe9, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xaa}
	if err := dispatcher.Dispatch(context.Background(), 0, socket, frame); err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}

	if len(calls) != 2 {
		t.Fatalf("call count = %d, want 2", len(calls))
	}
	if calls[0] != "response" || calls[1] != "analysis" {
		t.Fatalf("call order = %+v, want [response analysis]", calls)
	}
}

func TestNewDispatcherRequiresResponseConsumer(t *testing.T) {
	t.Parallel()

	_, err := NewDispatcher(Consumers{})
	if err == nil {
		t.Fatal("NewDispatcher() error = nil, want validation error")
	}
}
