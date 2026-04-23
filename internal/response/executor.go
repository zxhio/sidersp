package response

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		if ip4, ok := ipLayer.(*layers.IPv4); ok {
			result.SIP = ipv4ToUint32(ip4.SrcIP)
			result.DIP = ipv4ToUint32(ip4.DstIP)
			result.IPProto = uint8(ip4.Protocol)
		}
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			result.SPort = uint16(tcp.SrcPort)
			result.DPort = uint16(tcp.DstPort)
		}
		return
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if udp, ok := udpLayer.(*layers.UDP); ok {
			result.SPort = uint16(udp.SrcPort)
			result.DPort = uint16(udp.DstPort)
		}
		return
	}
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		if arp, ok := arpLayer.(*layers.ARP); ok {
			result.SIP = ipv4ToUint32(net.IP(arp.SourceProtAddress))
			result.DIP = ipv4ToUint32(net.IP(arp.DstProtAddress))
		}
	}
}

func ipv4ToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}
