package response

import (
	"context"
	"fmt"
)

type sameInterfaceTX struct {
	tx frameTransmitter
}

func (t *sameInterfaceTX) Transmit(ctx context.Context, meta XSKMetadata, frame []byte, opts BuildOptions) error {
	responseFrame, err := BuildResponseFrame(meta, frame, opts)
	if err != nil {
		return err
	}
	return t.tx.Transmit(ctx, responseFrame)
}

type icmpPacketSender interface {
	TransmitIPv4(context.Context, []byte) error
}

type icmpEgressTX struct {
	tx icmpPacketSender
}

func (t *icmpEgressTX) Transmit(ctx context.Context, meta XSKMetadata, frame []byte, _ BuildOptions) error {
	if meta.Action != ActionICMPEchoReply {
		return fmt.Errorf("icmp egress transmitter: unsupported action %d", meta.Action)
	}
	packet, err := BuildICMPEchoReplyIPv4(frame)
	if err != nil {
		return err
	}
	return t.tx.TransmitIPv4(ctx, packet)
}

type arpEgressTX struct {
	tx frameTransmitter
}

func (t *arpEgressTX) Transmit(ctx context.Context, meta XSKMetadata, frame []byte, opts BuildOptions) error {
	if meta.Action != ActionARPReply {
		return fmt.Errorf("arp egress transmitter: unsupported action %d", meta.Action)
	}
	responseFrame, err := BuildResponseFrame(meta, frame, opts)
	if err != nil {
		return err
	}
	return t.tx.Transmit(ctx, responseFrame)
}

type actionTXMux struct {
	defaultTX actionTransmitter
	overrides map[uint16]actionTransmitter
}

func (t *actionTXMux) Transmit(ctx context.Context, meta XSKMetadata, frame []byte, opts BuildOptions) error {
	if override, ok := t.overrides[meta.Action]; ok {
		return override.Transmit(ctx, meta, frame, opts)
	}
	return t.defaultTX.Transmit(ctx, meta, frame, opts)
}
