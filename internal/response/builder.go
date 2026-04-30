package response

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"sidersp/internal/rule"
)

const (
	ActionICMPEchoReply = rule.ActionICMPEchoReply
	ActionARPReply      = rule.ActionARPReply
	ActionTCPSynAck     = rule.ActionTCPSynAck
	ActionUDPEchoReply  = rule.ActionUDPEchoReply
	ActionDNSRefused    = rule.ActionDNSRefused
	ActionDNSSinkhole   = rule.ActionDNSSinkhole
)

type BuildOptions struct {
	HardwareAddr net.HardwareAddr
	RuleConfigs  *RuleConfigStore
}

var errResponseRequiresEthernetFraming = errors.New("response requires ethernet framing")

func BuildResponseFrame(meta XSKMetadata, frame []byte, opts BuildOptions) ([]byte, error) {
	return BuildResponseFrameToBuffer(meta, frame, opts, nil)
}

func BuildResponseIPv4Packet(meta XSKMetadata, frame []byte, opts BuildOptions) ([]byte, error) {
	return BuildResponseIPv4PacketToBuffer(meta, frame, opts, nil)
}

func BuildResponseFrameToBuffer(meta XSKMetadata, frame []byte, opts BuildOptions, dst []byte) ([]byte, error) {
	engine := getResponseEngine()
	defer putResponseEngine(engine)

	context := buildContext(meta.Action)
	pkt, builder, err := engine.ResolveBuilder(meta, frame, context)
	if err != nil {
		return nil, err
	}
	return buildResponseFrame(builder, meta, pkt, opts, dst)
}

func BuildResponseIPv4PacketToBuffer(meta XSKMetadata, frame []byte, opts BuildOptions, dst []byte) ([]byte, error) {
	engine := getResponseEngine()
	defer putResponseEngine(engine)

	context := buildContext(meta.Action)
	pkt, builder, err := engine.ResolveBuilder(meta, frame, context)
	if err != nil {
		return nil, err
	}
	return buildResponseIPv4Packet(builder, meta, pkt, opts, dst)
}

const (
	dnsHeaderLen     = 12
	dnsRCodeServFail = 2
	dnsRCodeNXDomain = 3
	dnsRCodeRefused  = 5
	dnsTypeA         = 1
	dnsTypeAAAA      = 28
	dnsClassIN       = 1
)

func lookupDNSResponseConfig(ruleID uint32, configs *RuleConfigStore, context string) (DNSResponseConfig, error) {
	config, ok := configs.DNSResponseConfig(ruleID)
	if !ok {
		return DNSResponseConfig{}, fmt.Errorf("%s: rule %d dns response config is not configured", context, ruleID)
	}
	return config, nil
}

func selectDNSResponseAnswers(qtype, qclass uint16, config DNSResponseConfig, context string) (uint16, []netip.Addr, error) {
	if len(config.AnswersV4) == 0 && len(config.AnswersV6) == 0 {
		return 0, nil, nil
	}
	if qclass != dnsClassIN {
		return 0, nil, fmt.Errorf("%s: only dns class IN queries are supported", context)
	}

	switch qtype {
	case dnsTypeA:
		if len(config.AnswersV4) == 0 {
			return 0, nil, fmt.Errorf("%s: dns A query has no configured answers", context)
		}
		return dnsTypeA, config.AnswersV4, nil
	case dnsTypeAAAA:
		if len(config.AnswersV6) == 0 {
			return 0, nil, fmt.Errorf("%s: dns AAAA query has no configured answers", context)
		}
		return dnsTypeAAAA, config.AnswersV6, nil
	default:
		return 0, nil, fmt.Errorf("%s: only dns A and AAAA queries are supported", context)
	}
}

func lookupARPReplyConfig(ruleID uint32, defaultHardwareAddr net.HardwareAddr, configs *RuleConfigStore) (ARPReplyConfig, error) {
	config := ARPReplyConfig{}
	if configs != nil {
		if override, ok := configs.ARPReplyConfig(ruleID); ok {
			config = override
		}
	}

	if !config.HasHardwareAddr() {
		if len(defaultHardwareAddr) != 6 {
			return ARPReplyConfig{}, fmt.Errorf("build arp reply: hardware address is required")
		}
		config.HardwareAddr = defaultHardwareAddr
	}

	return config, nil
}

func lookupTCPSynAckSeq(ruleID uint32, configs *RuleConfigStore) uint32 {
	if configs != nil {
		if config, ok := configs.TCPSynAckConfig(ruleID); ok && config.TCPSeq != 0 {
			return config.TCPSeq
		}
	}
	return 1
}

var (
	outputLayerEthernet = layers.LayerTypeEthernet
	outputLayerIPv4     = layers.LayerTypeIPv4
)

type Builder interface {
	Build(gopacket.LayerType, uint32, *Packet, BuildOptions, []byte) ([]byte, error)
}

type builderEntry struct {
	layerType gopacket.LayerType
	builder   Builder
}

type builderRegistry struct {
	items map[uint16]builderEntry
}

func newBuilderRegistry() builderRegistry {
	items := map[uint16]builderEntry{
		ActionICMPEchoReply: {layerType: layers.LayerTypeICMPv4, builder: &ICMPEchoReply{replyBuilder: newReplyBuilder()}},
		ActionARPReply:      {layerType: layers.LayerTypeARP, builder: &ARPReply{replyBuilder: newReplyBuilder()}},
		ActionTCPSynAck:     {layerType: layers.LayerTypeTCP, builder: &TCPSynAck{replyBuilder: newReplyBuilder()}},
		ActionUDPEchoReply:  {layerType: layers.LayerTypeUDP, builder: &UDPEchoReply{replyBuilder: newReplyBuilder()}},
		ActionDNSRefused:    {layerType: layers.LayerTypeDNS, builder: &DNSReply{replyBuilder: newReplyBuilder()}},
		ActionDNSSinkhole:   {layerType: layers.LayerTypeDNS, builder: &DNSReply{replyBuilder: newReplyBuilder()}},
	}
	return builderRegistry{items: items}
}

func (r *builderRegistry) Builder(action uint16, layerType gopacket.LayerType, context string) (Builder, error) {
	entry, ok := r.items[action]
	if !ok {
		return nil, fmt.Errorf("%s: unsupported action %d", context, action)
	}
	if entry.layerType != layerType {
		if name, ok := ResponseActionName(action); ok {
			return nil, fmt.Errorf("%s: action %q does not apply to %s packets", context, name, layerType)
		}
		return nil, fmt.Errorf("%s: unsupported action %d", context, action)
	}
	return entry.builder, nil
}

func (r *builderRegistry) expectedLayer(action uint16) (gopacket.LayerType, bool) {
	entry, ok := r.items[action]
	if !ok {
		return 0, false
	}
	return entry.layerType, true
}

type serializer struct {
	small  gopacket.SerializeBuffer
	medium gopacket.SerializeBuffer
	large  gopacket.SerializeBuffer
	opts   gopacket.SerializeOptions
}

func newSerializer() serializer {
	return serializer{
		small:  gopacket.NewSerializeBufferExpectedSize(64, 64),
		medium: gopacket.NewSerializeBufferExpectedSize(128, 384),
		large:  gopacket.NewSerializeBufferExpectedSize(256, 1792),
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
	}
}

func (s *serializer) serializeFrame(dst []byte, headerLen, payloadLen int, app, transport, network, link gopacket.SerializableLayer) ([]byte, error) {
	totalLen := headerLen + payloadLen
	if totalLen < minEthernetFrameLen {
		totalLen = minEthernetFrameLen
	}
	return s.serialize(dst, totalLen, headerLen, app, transport, network, link)
}

func (s *serializer) serializeIPv4(dst []byte, headerLen, payloadLen int, app, transport, network gopacket.SerializableLayer) ([]byte, error) {
	return s.serialize(dst, headerLen+payloadLen, headerLen, app, transport, network, nil)
}

func (s *serializer) serialize(dst []byte, totalLen, headerLen int, app, transport, network, link gopacket.SerializableLayer) ([]byte, error) {
	buf := s.buffer(totalLen)
	if err := buf.Clear(); err != nil {
		return nil, err
	}

	if app != nil {
		if err := serializeLayer(buf, s.opts, app); err != nil {
			return nil, err
		}
	}
	if transport != nil {
		if err := serializeLayer(buf, s.opts, transport); err != nil {
			return nil, err
		}
	}
	if network != nil {
		if err := serializeLayer(buf, s.opts, network); err != nil {
			return nil, err
		}
	}
	if link != nil {
		if err := serializeLayer(buf, s.opts, link); err != nil {
			return nil, err
		}
	}
	return copySerializedBytes(dst, buf.Bytes()), nil
}

func serializeLayer(buf gopacket.SerializeBuffer, opts gopacket.SerializeOptions, layer gopacket.SerializableLayer) error {
	if err := layer.SerializeTo(buf, opts); err != nil {
		return err
	}
	buf.PushLayer(layer.LayerType())
	return nil
}

func (s *serializer) buffer(totalLen int) gopacket.SerializeBuffer {
	switch {
	case totalLen <= serializeSmallLimit:
		return s.small
	case totalLen <= serializeMediumLimit:
		return s.medium
	default:
		return s.large
	}
}

func copySerializedBytes(dst []byte, src []byte) []byte {
	if dst == nil {
		dst = make([]byte, len(src))
		copy(dst, src)
		return dst
	}
	if cap(dst) < len(src) {
		dst = make([]byte, len(src))
	} else {
		dst = dst[:len(src)]
	}
	copy(dst, src)
	return dst
}

type replyBuilder struct {
	serializer serializer
	eth        layers.Ethernet
	ip4        layers.IPv4
	arp        layers.ARP
	icmp       layers.ICMPv4
	tcp        layers.TCP
	udp        layers.UDP
	dns        layers.DNS
}

func newReplyBuilder() replyBuilder {
	return replyBuilder{serializer: newSerializer()}
}

func (b *replyBuilder) buildEthernet(srcMAC, dstMAC net.HardwareAddr, etherType layers.EthernetType) *layers.Ethernet {
	b.eth = layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: etherType,
	}
	return &b.eth
}

func (b *replyBuilder) buildEthernetReply(pkt *Packet, etherType layers.EthernetType) *layers.Ethernet {
	return b.buildEthernet(pkt.eth.DstMAC, pkt.eth.SrcMAC, etherType)
}

func (b *replyBuilder) buildIPv4Reply(pkt *Packet, protocol layers.IPProtocol) *layers.IPv4 {
	b.ip4 = layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      defaultIPv4TTL,
		Id:       pkt.ip4.Id,
		Protocol: protocol,
		SrcIP:    pkt.ip4.DstIP,
		DstIP:    pkt.ip4.SrcIP,
	}
	return &b.ip4
}

func (b *replyBuilder) serializeIPResponse(target gopacket.LayerType, dst []byte, frameHeaderLen, packetHeaderLen, payloadLen int, app, transport gopacket.SerializableLayer) ([]byte, error) {
	switch target {
	case outputLayerEthernet:
		return b.serializer.serializeFrame(dst, frameHeaderLen, payloadLen, app, transport, &b.ip4, &b.eth)
	case outputLayerIPv4:
		return b.serializer.serializeIPv4(dst, packetHeaderLen, payloadLen, app, transport, &b.ip4)
	default:
		return nil, fmt.Errorf("build response: unsupported output layer %s", target)
	}
}

func (b *replyBuilder) serializeARPResponse(dst []byte) ([]byte, error) {
	return b.serializer.serializeFrame(dst, ethernetARPFrameLen, 0, nil, &b.arp, nil, &b.eth)
}

type ICMPEchoReply struct {
	replyBuilder
}

func (b *ICMPEchoReply) Build(target gopacket.LayerType, _ uint32, pkt *Packet, _ BuildOptions, dst []byte) ([]byte, error) {
	if pkt.icmp.TypeCode.Type() != layers.ICMPv4TypeEchoRequest || pkt.icmp.TypeCode.Code() != icmpZeroCode {
		return nil, fmt.Errorf("build icmp echo reply: packet is not echo request")
	}
	b.buildEthernetReply(pkt, layers.EthernetTypeIPv4)
	b.buildIPv4Reply(pkt, layers.IPProtocolICMPv4)
	transport := b.buildICMP(pkt)
	payloadLen := len(pkt.icmp.Payload)
	return b.serializeIPResponse(
		target,
		dst,
		ethernetHeaderLen+minIPv4HeaderLen+minICMPv4HeaderLen,
		minIPv4HeaderLen+minICMPv4HeaderLen,
		payloadLen,
		gopacket.Payload(pkt.icmp.Payload),
		transport,
	)
}

func (b *ICMPEchoReply) buildICMP(pkt *Packet) *layers.ICMPv4 {
	b.icmp = layers.ICMPv4{
		TypeCode: icmpEchoReplyTypeCode,
		Id:       pkt.icmp.Id,
		Seq:      pkt.icmp.Seq,
	}
	return &b.icmp
}

type ARPReply struct {
	replyBuilder
	ipv4 [4]byte
}

func (b *ARPReply) Build(target gopacket.LayerType, ruleID uint32, pkt *Packet, opts BuildOptions, dst []byte) ([]byte, error) {
	if target != outputLayerEthernet {
		return nil, fmt.Errorf("build response ipv4 packet: %w for action %d", errResponseRequiresEthernetFraming, ActionARPReply)
	}
	if pkt.arp.Operation != layers.ARPRequest {
		return nil, fmt.Errorf("build arp reply: packet is not arp request")
	}
	config, err := lookupARPReplyConfig(ruleID, opts.HardwareAddr, opts.RuleConfigs)
	if err != nil {
		return nil, err
	}
	b.buildEthernet(config.HardwareAddr, pkt.eth.SrcMAC, layers.EthernetTypeARP)
	b.buildARP(pkt, config)
	return b.serializeARPResponse(dst)
}

func (b *ARPReply) buildARP(pkt *Packet, config ARPReplyConfig) *layers.ARP {
	sourceProt := pkt.arp.DstProtAddress
	if config.HasSenderIPv4() {
		b.ipv4 = config.SenderIPv4.As4()
		sourceProt = b.ipv4[:]
	}
	b.arp = layers.ARP{
		AddrType:          pkt.arp.AddrType,
		Protocol:          pkt.arp.Protocol,
		Operation:         layers.ARPReply,
		SourceHwAddress:   config.HardwareAddr,
		SourceProtAddress: sourceProt,
		DstHwAddress:      pkt.arp.SourceHwAddress,
		DstProtAddress:    pkt.arp.SourceProtAddress,
	}
	return &b.arp
}

type TCPSynAck struct {
	replyBuilder
}

func (b *TCPSynAck) Build(target gopacket.LayerType, ruleID uint32, pkt *Packet, opts BuildOptions, dst []byte) ([]byte, error) {
	if err := validateTCPSyn(pkt); err != nil {
		return nil, err
	}
	seq := lookupTCPSynAckSeq(ruleID, opts.RuleConfigs)
	b.buildEthernetReply(pkt, layers.EthernetTypeIPv4)
	b.buildIPv4Reply(pkt, layers.IPProtocolTCP)
	transport, err := b.buildTCP(pkt, seq)
	if err != nil {
		return nil, err
	}
	return b.serializeIPResponse(
		target,
		dst,
		ethernetHeaderLen+minIPv4HeaderLen+minTCPHeaderLen,
		minIPv4HeaderLen+minTCPHeaderLen,
		0,
		nil,
		transport,
	)
}

func (b *TCPSynAck) buildTCP(pkt *Packet, seq uint32) (*layers.TCP, error) {
	b.tcp = layers.TCP{
		SrcPort: pkt.tcp.DstPort,
		DstPort: pkt.tcp.SrcPort,
		Seq:     seq,
		Ack:     pkt.tcp.Seq + 1,
		SYN:     true,
		ACK:     true,
		Window:  defaultTCPWindow,
	}
	if err := b.tcp.SetNetworkLayerForChecksum(&b.ip4); err != nil {
		return nil, err
	}
	return &b.tcp, nil
}

func validateTCPSyn(pkt *Packet) error {
	if !pkt.tcp.SYN || pkt.tcp.ACK || pkt.tcp.RST || pkt.tcp.FIN {
		return fmt.Errorf("build tcp syn ack: packet is not initial syn")
	}
	if len(pkt.tcp.Payload) > 0 {
		return fmt.Errorf("build tcp syn ack: syn payload is not supported")
	}
	return nil
}

type UDPEchoReply struct {
	replyBuilder
}

func (b *UDPEchoReply) Build(target gopacket.LayerType, _ uint32, pkt *Packet, _ BuildOptions, dst []byte) ([]byte, error) {
	b.buildEthernetReply(pkt, layers.EthernetTypeIPv4)
	b.buildIPv4Reply(pkt, layers.IPProtocolUDP)
	transport, err := b.buildUDP(pkt)
	if err != nil {
		return nil, err
	}
	payloadLen := len(pkt.udp.Payload)
	return b.serializeIPResponse(
		target,
		dst,
		ethernetHeaderLen+minIPv4HeaderLen+minUDPHeaderLen,
		minIPv4HeaderLen+minUDPHeaderLen,
		payloadLen,
		gopacket.Payload(pkt.udp.Payload),
		transport,
	)
}

func (b *UDPEchoReply) buildUDP(pkt *Packet) (*layers.UDP, error) {
	b.udp = layers.UDP{
		SrcPort: pkt.udp.DstPort,
		DstPort: pkt.udp.SrcPort,
	}
	if err := b.udp.SetNetworkLayerForChecksum(&b.ip4); err != nil {
		return nil, err
	}
	return &b.udp, nil
}

type DNSReply struct {
	replyBuilder
}

func (b *DNSReply) Build(target gopacket.LayerType, ruleID uint32, pkt *Packet, opts BuildOptions, dst []byte) ([]byte, error) {
	if err := b.validateQuery(pkt); err != nil {
		return nil, err
	}

	config, err := lookupDNSResponseConfig(ruleID, opts.RuleConfigs, "build dns response")
	if err != nil {
		return nil, err
	}

	question := pkt.dns.Questions[0]
	answerType, answers, err := selectDNSResponseAnswers(uint16(question.Type), uint16(question.Class), config, "build dns response")
	if err != nil {
		return nil, err
	}

	b.buildEthernetReply(pkt, layers.EthernetTypeIPv4)
	b.buildIPv4Reply(pkt, layers.IPProtocolUDP)
	b.buildUDPReply(pkt)
	dnsPayloadLen := b.buildDNS(pkt, config, layers.DNSType(answerType), answers)

	return b.serializeIPResponse(
		target,
		dst,
		ethernetHeaderLen+minIPv4HeaderLen+minUDPHeaderLen,
		minIPv4HeaderLen+minUDPHeaderLen,
		dnsPayloadLen,
		&b.dns,
		&b.udp,
	)
}

func (b *DNSReply) validateQuery(pkt *Packet) error {
	if pkt.layerType != layers.LayerTypeDNS {
		return fmt.Errorf("build dns response: dns header missing")
	}
	dns := &pkt.dns
	if dns.QR {
		return fmt.Errorf("build dns response: packet is not dns query")
	}
	if dns.OpCode != layers.DNSOpCodeQuery {
		return fmt.Errorf("build dns response: only standard dns queries are supported")
	}
	if len(dns.Questions) != 1 {
		return fmt.Errorf("build dns response: exactly one dns question is required")
	}
	return nil
}

func (b *DNSReply) buildUDPReply(pkt *Packet) {
	b.udp = layers.UDP{
		SrcPort: pkt.udp.DstPort,
		DstPort: pkt.udp.SrcPort,
	}
	_ = b.udp.SetNetworkLayerForChecksum(&b.ip4)
}

func (b *DNSReply) buildDNS(pkt *Packet, config DNSResponseConfig, answerType layers.DNSType, answers []netip.Addr) int {
	question := pkt.dns.Questions[0]

	b.dns = layers.DNS{
		ID:           pkt.dns.ID,
		QR:           true,
		OpCode:       layers.DNSOpCodeQuery,
		RD:           pkt.dns.RD,
		ResponseCode: layers.DNSResponseCode(config.RCode),
		QDCount:      1,
		Questions:    []layers.DNSQuestion{question},
	}

	if len(answers) > 0 {
		records := make([]layers.DNSResourceRecord, 0, len(answers))
		for _, addr := range answers {
			records = append(records, layers.DNSResourceRecord{
				Name:  question.Name,
				Type:  answerType,
				Class: layers.DNSClassIN,
				TTL:   config.TTL,
				IP:    net.IP(addr.AsSlice()),
			})
		}
		b.dns.Answers = records
	}

	return 12 + len(question.Name) + 6 + len(answers)*(len(question.Name)+16)
}

type responseEngine struct {
	registry builderRegistry
	pkt      Packet
}

func newResponseEngine() *responseEngine {
	return &responseEngine{
		registry: newBuilderRegistry(),
	}
}

var responseEnginePool = sync.Pool{
	New: func() any {
		return newResponseEngine()
	},
}

func getResponseEngine() *responseEngine {
	return responseEnginePool.Get().(*responseEngine)
}

func putResponseEngine(item *responseEngine) {
	if item == nil {
		return
	}
	responseEnginePool.Put(item)
}

func (e *responseEngine) ResolveBuilder(meta XSKMetadata, frame []byte, context string) (*Packet, Builder, error) {
	if err := e.pkt.Decode(frame, nil, context); err != nil {
		return nil, nil, err
	}
	if expected, ok := e.registry.expectedLayer(meta.Action); ok && expected == layers.LayerTypeDNS && e.pkt.layerType != layers.LayerTypeDNS {
		return nil, nil, fmt.Errorf("%s: dns header missing", context)
	}
	builder, err := e.registry.Builder(meta.Action, e.pkt.layerType, context)
	if err != nil {
		return nil, nil, err
	}
	if builder == nil {
		return nil, nil, fmt.Errorf("%s: builder is not resolved", context)
	}
	return &e.pkt, builder, nil
}

func buildResponseFrame(builder Builder, meta XSKMetadata, pkt *Packet, opts BuildOptions, dst []byte) ([]byte, error) {
	if builder == nil {
		return nil, fmt.Errorf("build response: builder is required")
	}
	return builder.Build(outputLayerEthernet, meta.RuleID, pkt, opts, dst)
}

func buildResponseIPv4Packet(builder Builder, meta XSKMetadata, pkt *Packet, opts BuildOptions, dst []byte) ([]byte, error) {
	if builder == nil {
		return nil, fmt.Errorf("build response ipv4 packet: builder is required")
	}
	return builder.Build(outputLayerIPv4, meta.RuleID, pkt, opts, dst)
}

func buildContext(action uint16) string {
	switch action {
	case ActionICMPEchoReply:
		return "build icmp echo reply"
	case ActionARPReply:
		return "build arp reply"
	case ActionTCPSynAck:
		return "build tcp syn ack"
	case ActionUDPEchoReply:
		return "build udp echo reply"
	case ActionDNSRefused:
		return "build dns refused"
	case ActionDNSSinkhole:
		return "build dns sinkhole"
	default:
		return "build response"
	}
}
