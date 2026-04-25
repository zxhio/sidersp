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

func TestAFXDPSenderBuildsAndSendsFrame(t *testing.T) {
	t.Parallel()

	out := &stubFrameSender{}
	sender := &afxdpSender{
		out:       out,
		buildOpts: BuildOptions{},
	}

	if err := sender.Send(context.Background(), XSKMetadata{Action: ActionICMPEchoReply}, buildTestICMPEchoRequest(t)); err != nil {
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

	if err := sender.Send(context.Background(), XSKMetadata{Action: ActionARPReply}, buildTestARPRequest(t)); err != nil {
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

	err := sender.Send(context.Background(), XSKMetadata{Action: ActionICMPEchoReply}, buildTestICMPEchoRequest(t))
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

	if err := sender.Send(context.Background(), XSKMetadata{Action: ActionARPReply}, buildTestARPRequest(t)); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if len(out.frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(out.frames))
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

	if err := sender.Send(context.Background(), XSKMetadata{Action: ActionICMPEchoReply}, request); err != nil {
		t.Fatalf("first Send() error = %v", err)
	}
	if err := sender.Send(context.Background(), XSKMetadata{Action: ActionICMPEchoReply}, request); err != nil {
		t.Fatalf("second Send() error = %v", err)
	}
	if len(out.frames) != 2 {
		t.Fatalf("frames = %d, want 2", len(out.frames))
	}
	if &out.frames[0][0] == &out.frames[1][0] {
		t.Fatal("Send() reused the same backing buffer for a non-borrowed sender")
	}
}
