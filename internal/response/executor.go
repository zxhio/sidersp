package response

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"
)

type frameSender interface {
	SendFrame(context.Context, []byte) error
}

type ResponseExecutor struct {
	ifindex int
	queueID int
	sender  responseSender
	results *ResultBuffer
	stats   *responseStatsCounters
	pf      parsedFrame
}

type ResponseExecutorConfig struct {
	IfIndex int
	QueueID int
	Sender  responseSender
	Results *ResultBuffer
	Stats   *responseStatsCounters
}

func NewResponseExecutor(config ResponseExecutorConfig) (*ResponseExecutor, error) {
	if config.QueueID < 0 {
		return nil, fmt.Errorf("create response executor: queue %d out of range", config.QueueID)
	}
	if config.Sender == nil {
		return nil, fmt.Errorf("create response executor: sender is required")
	}
	if config.Results == nil {
		return nil, fmt.Errorf("create response executor: result buffer is required")
	}
	if config.Stats == nil {
		return nil, fmt.Errorf("create response executor: stats counters are required")
	}
	return &ResponseExecutor{
		ifindex: config.IfIndex,
		queueID: config.QueueID,
		sender:  config.Sender,
		results: config.Results,
		stats:   config.Stats,
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

	parseErr := parseFrameForAction(&e.pf, frame, meta.Action, "execute response")
	if parseErr != nil {
		result := e.newResult(meta, action, frame)
		e.recordFailure(&result, fmt.Errorf("parse response frame: %w", parseErr))
		return parseErr
	}

	result := e.newResultFromParsed(meta, action, &e.pf)
	if err := e.sender.Send(ctx, meta, frame, &e.pf); err != nil {
		err = fmt.Errorf("transmit response frame: %w", err)
		e.recordFailure(&result, err)
		return err
	}

	result.Result = ResultSent
	e.stats.recordSent(result.TXBackend)
	return e.results.recordTrusted(&result)
}

func (e *ResponseExecutor) ExecuteXSK(ctx context.Context, frame []byte) error {
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
		TimestampNS: uint64(time.Now().UnixNano()),
		RuleID:      meta.RuleID,
		Action:      action,
		TXBackend:   e.sender.Backend(),
		IfIndex:     e.ifindex,
		RXQueue:     e.queueID,
	}
	fillTupleFields(&result, frame)
	return result
}

func (e *ResponseExecutor) newResultFromParsed(meta XSKMetadata, action string, pf *parsedFrame) ResponseResult {
	result := ResponseResult{
		TimestampNS: uint64(time.Now().UnixNano()),
		RuleID:      meta.RuleID,
		Action:      action,
		TXBackend:   e.sender.Backend(),
		IfIndex:     e.ifindex,
		RXQueue:     e.queueID,
	}
	fillTupleFromParsed(&result, pf)
	return result
}

func (e *ResponseExecutor) recordFailure(result *ResponseResult, err error) {
	result.Result = ResultFailed
	result.Error = err.Error()
	e.stats.recordFailed(result.TXBackend)
	_ = e.results.recordTrusted(result)
}

func fillTupleFields(result *ResponseResult, frame []byte) {
	etherType, payload, ok := parseTupleEthernetPayload(frame)
	if !ok {
		return
	}

	switch etherType {
	case fastpktEtherTypeIPv4:
		ip4, ok := parseTupleIPv4Packet(payload)
		if !ok {
			return
		}
		result.SIP = binary.BigEndian.Uint32(ip4.src[:])
		result.DIP = binary.BigEndian.Uint32(ip4.dst[:])
		result.IPProto = ip4.protocol

		switch ip4.protocol {
		case fastpktIPProtoTCP:
			tcp, ok := parseTupleTCPPacket(ip4.payload)
			if !ok {
				return
			}
			result.SPort = tcp.srcPort
			result.DPort = tcp.dstPort
		case fastpktIPProtoUDP:
			udp, ok := parseTupleUDPPacket(ip4.payload)
			if !ok {
				return
			}
			result.SPort = udp.srcPort
			result.DPort = udp.dstPort
		}
	case fastpktEtherTypeARP:
		arp, ok := parseTupleARPPacket(payload)
		if !ok {
			return
		}
		result.SIP = binary.BigEndian.Uint32(arp.srcProt[:])
		result.DIP = binary.BigEndian.Uint32(arp.dstProt[:])
	}
}

func fillTupleFromParsed(result *ResponseResult, pf *parsedFrame) {
	switch pf.kind {
	case parsedFrameICMP, parsedFrameTCP, parsedFrameUDP:
		result.SIP = binary.BigEndian.Uint32(pf.ip4.src[:])
		result.DIP = binary.BigEndian.Uint32(pf.ip4.dst[:])
		result.IPProto = pf.ip4.protocol
		if pf.kind == parsedFrameTCP {
			result.SPort = pf.tcp.srcPort
			result.DPort = pf.tcp.dstPort
		} else if pf.kind == parsedFrameUDP {
			result.SPort = pf.udp.srcPort
			result.DPort = pf.udp.dstPort
		}
	case parsedFrameARP:
		result.SIP = binary.BigEndian.Uint32(pf.arp.srcProt[:])
		result.DIP = binary.BigEndian.Uint32(pf.arp.dstProt[:])
	}
}
