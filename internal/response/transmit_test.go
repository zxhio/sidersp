package response

import (
	"context"
	"errors"
	"testing"
)

type stubIPv4Transmitter struct {
	err     error
	packets [][]byte
	closed  bool
}

type stubFrameTransmitter struct {
	err    error
	frames [][]byte
	closed bool
}

func (s *stubIPv4Transmitter) TransmitIPv4(_ context.Context, packet []byte) error {
	s.packets = append(s.packets, append([]byte(nil), packet...))
	return s.err
}

func (s *stubIPv4Transmitter) TransmitIPv4Borrowed(_ context.Context, packet []byte) error {
	s.packets = append(s.packets, append([]byte(nil), packet...))
	return s.err
}

func (s *stubIPv4Transmitter) Close() error {
	s.closed = true
	return nil
}

func (s *stubFrameTransmitter) Transmit(_ context.Context, frame []byte) error {
	s.frames = append(s.frames, append([]byte(nil), frame...))
	return s.err
}

func (s *stubFrameTransmitter) TransmitBorrowed(_ context.Context, frame []byte) error {
	s.frames = append(s.frames, append([]byte(nil), frame...))
	return s.err
}

type retainingFrameTransmitter struct {
	frames [][]byte
}

func (t *retainingFrameTransmitter) Transmit(_ context.Context, frame []byte) error {
	t.frames = append(t.frames, frame)
	return nil
}

func (s *stubFrameTransmitter) Close() error {
	s.closed = true
	return nil
}

func TestActionTXMuxUsesICMPEgressForEchoReply(t *testing.T) {
	t.Parallel()

	defaultTX := &stubTransmitter{}
	sameInterfaceTX := &sameInterfaceTX{tx: defaultTX}
	egressTX := &stubIPv4Transmitter{}
	tx := &actionTXMux{
		defaultTX: sameInterfaceTX,
		overrides: map[uint16]actionTransmitter{
			ActionICMPEchoReply: &icmpEgressTX{tx: egressTX},
		},
	}

	err := tx.Transmit(context.Background(), XSKMetadata{Action: ActionICMPEchoReply}, buildTestICMPEchoRequest(t), BuildOptions{})
	if err != nil {
		t.Fatalf("Transmit() error = %v", err)
	}
	if len(defaultTX.frames) != 0 {
		t.Fatalf("same-interface frames = %d, want 0", len(defaultTX.frames))
	}
	if len(egressTX.packets) != 1 {
		t.Fatalf("egress packets = %d, want 1", len(egressTX.packets))
	}
}

func TestActionTXMuxKeepsNonICMPActionsOnSameInterface(t *testing.T) {
	t.Parallel()

	defaultTX := &stubTransmitter{}
	tx := &actionTXMux{
		defaultTX: &sameInterfaceTX{tx: defaultTX},
		overrides: map[uint16]actionTransmitter{
			ActionICMPEchoReply: &icmpEgressTX{tx: &stubIPv4Transmitter{}},
		},
	}

	err := tx.Transmit(context.Background(), XSKMetadata{Action: ActionARPReply}, buildTestARPRequest(t), BuildOptions{HardwareAddr: testHWAddr})
	if err != nil {
		t.Fatalf("Transmit() error = %v", err)
	}
	if len(defaultTX.frames) != 1 {
		t.Fatalf("same-interface frames = %d, want 1", len(defaultTX.frames))
	}
}

func TestICMPEgressTXReturnsSendError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("send failed")
	tx := &icmpEgressTX{tx: &stubIPv4Transmitter{err: wantErr}}

	err := tx.Transmit(context.Background(), XSKMetadata{Action: ActionICMPEchoReply}, buildTestICMPEchoRequest(t), BuildOptions{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Transmit() error = %v, want %v", err, wantErr)
	}
}

func TestActionTXMuxUsesARPEgressForARPReply(t *testing.T) {
	t.Parallel()

	defaultTX := &stubTransmitter{}
	tx := &actionTXMux{
		defaultTX: &sameInterfaceTX{tx: defaultTX},
		overrides: map[uint16]actionTransmitter{
			ActionARPReply: &arpEgressTX{tx: &stubFrameTransmitter{}},
		},
	}

	if err := tx.Transmit(context.Background(), XSKMetadata{Action: ActionARPReply}, buildTestARPRequest(t), BuildOptions{HardwareAddr: testHWAddr}); err != nil {
		t.Fatalf("Transmit() error = %v", err)
	}
	if len(defaultTX.frames) != 0 {
		t.Fatalf("same-interface frames = %d, want 0", len(defaultTX.frames))
	}
}

func TestSameInterfaceTXDoesNotReuseBufferForNonBorrowedTransmitter(t *testing.T) {
	t.Parallel()

	tx := &retainingFrameTransmitter{}
	same := &sameInterfaceTX{tx: tx}
	request := buildTestICMPEchoRequest(t)

	if err := same.Transmit(context.Background(), XSKMetadata{Action: ActionICMPEchoReply}, request, BuildOptions{}); err != nil {
		t.Fatalf("first Transmit() error = %v", err)
	}
	if err := same.Transmit(context.Background(), XSKMetadata{Action: ActionICMPEchoReply}, request, BuildOptions{}); err != nil {
		t.Fatalf("second Transmit() error = %v", err)
	}
	if len(tx.frames) != 2 {
		t.Fatalf("frames = %d, want 2", len(tx.frames))
	}
	if &tx.frames[0][0] == &tx.frames[1][0] {
		t.Fatal("Transmit() reused the same backing buffer for a non-borrowed transmitter")
	}
}
