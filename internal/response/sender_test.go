package response

import (
	"context"
	"errors"
	"testing"
)

type stubFrameSender struct {
	err    error
	frames [][]byte
	closed bool
}

func (s *stubFrameSender) SendFrame(_ context.Context, frame []byte) error {
	s.frames = append(s.frames, append([]byte(nil), frame...))
	return s.err
}

func (s *stubFrameSender) SendBorrowedFrame(_ context.Context, frame []byte) error {
	s.frames = append(s.frames, append([]byte(nil), frame...))
	return s.err
}

func (s *stubFrameSender) Close() error {
	s.closed = true
	return nil
}

type retainingFrameSender struct {
	frames [][]byte
}

func (s *retainingFrameSender) SendFrame(_ context.Context, frame []byte) error {
	s.frames = append(s.frames, frame)
	return nil
}

type stubMixedSender struct {
	frames      [][]byte
	ipv4Packets [][]byte
}

func (s *stubMixedSender) SendFrame(_ context.Context, frame []byte) error {
	s.frames = append(s.frames, append([]byte(nil), frame...))
	return nil
}

func (s *stubMixedSender) SendBorrowedFrame(_ context.Context, frame []byte) error {
	s.frames = append(s.frames, append([]byte(nil), frame...))
	return nil
}

func (s *stubMixedSender) SendBorrowedIPv4Packet(_ context.Context, packet []byte) error {
	s.ipv4Packets = append(s.ipv4Packets, append([]byte(nil), packet...))
	return nil
}

func TestAFXDPSenderBuildsAndSendsFrame(t *testing.T) {
	t.Parallel()

	out := &stubFrameSender{}
	sender := &afxdpSender{
		out:       out,
		buildOpts: BuildOptions{},
	}

	if err := sender.Send(context.Background(), XSKMetadata{Action: ActionICMPEchoReply}, nil, buildTestICMPEchoRequest(t), nil); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if len(out.frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(out.frames))
	}
}

func TestAFPacketSenderBuildsAndSendsFrame(t *testing.T) {
	t.Parallel()

	out := &stubFrameSender{}
	sender := &afpacketSender{
		out: out,
		buildOpts: BuildOptions{
			HardwareAddr: testHWAddr,
		},
	}

	if err := sender.Send(context.Background(), XSKMetadata{Action: ActionARPReply}, nil, buildTestARPRequest(t), nil); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if len(out.frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(out.frames))
	}
}

func TestAFXDPSenderReturnsFrameSendError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("send failed")
	sender := &afxdpSender{
		out:       &stubFrameSender{err: wantErr},
		buildOpts: BuildOptions{},
	}

	err := sender.Send(context.Background(), XSKMetadata{Action: ActionICMPEchoReply}, nil, buildTestICMPEchoRequest(t), nil)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Send() error = %v, want %v", err, wantErr)
	}
}

func TestAFPacketSenderUsesARPBuildOptions(t *testing.T) {
	t.Parallel()

	out := &stubFrameSender{}
	sender := &afpacketSender{
		out: out,
		buildOpts: BuildOptions{
			HardwareAddr: testHWAddr,
		},
	}

	if err := sender.Send(context.Background(), XSKMetadata{Action: ActionARPReply}, nil, buildTestARPRequest(t), nil); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if len(out.frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(out.frames))
	}
}

func TestAFPacketSenderUsesIPv4PacketPathForICMPEchoReply(t *testing.T) {
	t.Parallel()

	out := &stubMixedSender{}
	sender := &afpacketSender{
		out:       out,
		buildOpts: BuildOptions{},
	}

	if err := sender.Send(context.Background(), XSKMetadata{Action: ActionICMPEchoReply}, nil, buildTestICMPEchoRequest(t), nil); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if len(out.ipv4Packets) != 1 {
		t.Fatalf("ipv4 packets = %d, want 1", len(out.ipv4Packets))
	}
	if len(out.frames) != 0 {
		t.Fatalf("frames = %d, want 0", len(out.frames))
	}
}

func TestAFPacketSenderFallsBackToFramePathForARPReply(t *testing.T) {
	t.Parallel()

	out := &stubMixedSender{}
	sender := &afpacketSender{
		out: out,
		buildOpts: BuildOptions{
			HardwareAddr: testHWAddr,
		},
	}

	if err := sender.Send(context.Background(), XSKMetadata{Action: ActionARPReply}, nil, buildTestARPRequest(t), nil); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if len(out.frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(out.frames))
	}
	if len(out.ipv4Packets) != 0 {
		t.Fatalf("ipv4 packets = %d, want 0", len(out.ipv4Packets))
	}
}

func TestAFXDPSenderDoesNotReuseBufferForNonBorrowedSender(t *testing.T) {
	t.Parallel()

	out := &retainingFrameSender{}
	sender := &afxdpSender{
		out:       out,
		buildOpts: BuildOptions{},
	}
	request := buildTestICMPEchoRequest(t)

	if err := sender.Send(context.Background(), XSKMetadata{Action: ActionICMPEchoReply}, nil, request, nil); err != nil {
		t.Fatalf("first Send() error = %v", err)
	}
	if err := sender.Send(context.Background(), XSKMetadata{Action: ActionICMPEchoReply}, nil, request, nil); err != nil {
		t.Fatalf("second Send() error = %v", err)
	}
	if len(out.frames) != 2 {
		t.Fatalf("frames = %d, want 2", len(out.frames))
	}
	if &out.frames[0][0] == &out.frames[1][0] {
		t.Fatal("Send() reused the same backing buffer for a non-borrowed sender")
	}
}
