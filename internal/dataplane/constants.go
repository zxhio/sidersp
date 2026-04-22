package dataplane

import "time"

const (
	maxRuleSlots     = 1024
	statsLogInterval = 10 * time.Second

	condProtoTCP        = 1 << 0
	condProtoUDP        = 1 << 1
	condProtoICMP       = 1 << 2
	condProtoARP        = 1 << 3
	condVLAN            = 1 << 4
	condSrcPrefix       = 1 << 5
	condDstPrefix       = 1 << 6
	condSrcPort         = 1 << 7
	condDstPort         = 1 << 8
	condTCPSYN          = 1 << 9
	condTCPACK          = 1 << 10
	condTCPRST          = 1 << 11
	condTCPFIN          = 1 << 12
	condTCPPSH          = 1 << 13
	condICMPEchoRequest = 1 << 14
	condICMPEchoReply   = 1 << 15
	condARPRequest      = 1 << 16
	condARPReply        = 1 << 17
	condL4Payload       = 1 << 18

	actionNone          uint16 = 0
	actionAlert         uint16 = 1
	actionTCPReset      uint16 = 2
	actionICMPEchoReply uint16 = 3
	actionARPReply      uint16 = 4
	actionTCPSynAck     uint16 = 5
)

const (
	statRXPackets uint32 = iota
	statParseFailed
	statRuleCandidates
	statMatchedRules
	statRingbufDropped
	statXDPTX
	statXskTX
	statTXFailed
	statXskFailed
)

var tcpFlagBits = map[string]uint32{
	"SYN": condTCPSYN,
	"ACK": condTCPACK,
	"RST": condTCPRST,
	"FIN": condTCPFIN,
	"PSH": condTCPPSH,
}
