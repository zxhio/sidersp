package response

import (
	"context"
	"encoding/binary"
	"fmt"
)

type frameTransmitter interface {
	Transmit(context.Context, []byte) error
}

type actionTransmitter interface {
	Transmit(context.Context, XSKMetadata, []byte, BuildOptions) error
}

type ResponseExecutor struct {
	ifindex int
	queueID int
	opts    BuildOptions
	tx      actionTransmitter
	results *ResultBuffer
}

type ResponseExecutorConfig struct {
	IfIndex int
	QueueID int
	Options BuildOptions
	TX      actionTransmitter
	Results *ResultBuffer
}

func NewResponseExecutor(config ResponseExecutorConfig) (*ResponseExecutor, error) {
	if config.QueueID < 0 {
		return nil, fmt.Errorf("create response executor: queue %d out of range", config.QueueID)
	}
	if config.TX == nil {
		return nil, fmt.Errorf("create response executor: transmitter is required")
	}
	if config.Results == nil {
		return nil, fmt.Errorf("create response executor: result buffer is required")
	}
	return &ResponseExecutor{
		ifindex: config.IfIndex,
		queueID: config.QueueID,
		opts:    config.Options,
		tx:      config.TX,
		results: config.Results,
	}, nil
}

func (e *ResponseExecutor) Execute(ctx context.Context, meta XSKMetadata, frame []byte) error {
	if e == nil {
		return fmt.Errorf("execute response: nil executor")
	}

	action, ok := ResponseActionName(meta.Action)
	if !ok {
		return fmt.Errorf("execute response: unsupported action %d", meta.Action)
	}

	result := e.newResult(meta, action, frame)
	if err := e.tx.Transmit(ctx, meta, frame, e.opts); err != nil {
		err = fmt.Errorf("transmit response frame: %w", err)
		e.recordFailure(result, err)
		return err
	}

	result.Result = ResultSent
	return e.results.Record(result)
}

func (e *ResponseExecutor) ExecuteXSKFrame(ctx context.Context, frame []byte) error {
	if e == nil {
		return fmt.Errorf("execute xsk frame: nil executor")
	}

	meta, payload, err := DecodeXSKMetadata(frame)
	if err != nil {
		return err
	}
	return e.Execute(ctx, meta, payload)
}

func (e *ResponseExecutor) newResult(meta XSKMetadata, action string, frame []byte) ResponseResult {
	result := ResponseResult{
		RuleID:  meta.RuleID,
		Action:  action,
		IfIndex: e.ifindex,
		RXQueue: e.queueID,
	}
	fillTupleFields(&result, frame)
	return result
}

func (e *ResponseExecutor) recordFailure(result ResponseResult, err error) {
	result.Result = ResultFailed
	result.Error = err.Error()
	_ = e.results.Record(result)
}

func fillTupleFields(result *ResponseResult, frame []byte) {
	eth, err := parseTupleEthernetFrame(frame)
	if err != nil {
		return
	}

	switch eth.etherType {
	case fastpktEtherTypeIPv4:
		ip4, err := parseIPv4Packet(eth.payload, "fill tuple fields")
		if err != nil {
			return
		}
		result.SIP = binary.BigEndian.Uint32(ip4.src[:])
		result.DIP = binary.BigEndian.Uint32(ip4.dst[:])
		result.IPProto = ip4.protocol

		switch ip4.protocol {
		case fastpktIPProtoTCP:
			tcp, err := parseTCPPacket(ip4.payload, "fill tuple fields")
			if err != nil {
				return
			}
			result.SPort = tcp.srcPort
			result.DPort = tcp.dstPort
		case fastpktIPProtoUDP:
			udp, err := parseUDPPacket(ip4.payload)
			if err != nil {
				return
			}
			result.SPort = udp.srcPort
			result.DPort = udp.dstPort
		}
	case fastpktEtherTypeARP:
		arp, err := parseARPPacket(eth.payload)
		if err != nil {
			return
		}
		result.SIP = binary.BigEndian.Uint32(arp.srcProt[:])
		result.DIP = binary.BigEndian.Uint32(arp.dstProt[:])
	}
}
