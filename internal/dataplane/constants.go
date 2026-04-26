package dataplane

import (
	"time"

	"sidersp/internal/rule"
)

const (
	maxRuleSlots     = 512
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

	actionNone                = rule.ActionNone
	actionAlert               = rule.ActionAlert
	actionTCPReset            = rule.ActionTCPReset
	actionICMPEchoReply       = rule.ActionICMPEchoReply
	actionARPReply            = rule.ActionARPReply
	actionTCPSynAck           = rule.ActionTCPSynAck
	actionICMPPortUnreachable = rule.ActionICMPPortUnreachable
	actionUDPEchoReply        = rule.ActionUDPEchoReply
	actionDNSRefused          = rule.ActionDNSRefused
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
	statXskMetaFailed
	statXskRedirectFailed
	statRedirectTX
	statRedirectFailed
	statFibLookupFailed
)

const (
	tcpResetTXModeTX uint32 = iota
	tcpResetTXModeRedirect
)

const (
	tcpResetVLANPreserve uint32 = iota
	tcpResetVLANAccess
)

const (
	tcpResetFailurePass uint32 = iota
	tcpResetFailureDrop
)

const (
	verdictObserve uint8 = iota
	verdictTX
	verdictXSK
	verdictRedirectTX
)

var tcpFlagBits = map[string]uint32{
	"SYN": condTCPSYN,
	"ACK": condTCPACK,
	"RST": condTCPRST,
	"FIN": condTCPFIN,
	"PSH": condTCPPSH,
}
