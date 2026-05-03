package rule

import "strings"

type ActionSpec struct {
	Code              uint16
	Name              string
	UserSpaceResponse bool
}

var actionSpecs = []ActionSpec{
	{Code: ActionNone, Name: "none"},
	{Code: ActionAlert, Name: "alert"},
	{Code: ActionTCPReset, Name: "tcp_reset"},
	{Code: ActionICMPEchoReply, Name: "icmp_echo_reply", UserSpaceResponse: true},
	{Code: ActionARPReply, Name: "arp_reply", UserSpaceResponse: true},
	{Code: ActionTCPSynAck, Name: "tcp_syn_ack", UserSpaceResponse: true},
	{Code: ActionICMPPortUnreachable, Name: "icmp_port_unreachable"},
	{Code: ActionUDPEchoReply, Name: "udp_echo_reply", UserSpaceResponse: true},
	{Code: ActionDNSRefused, Name: "dns_refused", UserSpaceResponse: true},
	{Code: ActionICMPHostUnreachable, Name: "icmp_host_unreachable"},
	{Code: ActionICMPAdminProhibited, Name: "icmp_admin_prohibited"},
	{Code: ActionDNSSinkhole, Name: "dns_sinkhole", UserSpaceResponse: true},
}

var actionSpecByCode = buildActionSpecByCode()
var actionSpecByName = buildActionSpecByName()

func ActionName(code uint16) (string, bool) {
	spec, ok := actionSpecByCode[code]
	if !ok {
		return "", false
	}
	return spec.Name, true
}

func ActionCode(name string) (uint16, bool) {
	spec, ok := actionSpecByName[name]
	if !ok {
		return 0, false
	}
	return spec.Code, true
}

func NormalizeActionName(raw string) (string, bool) {
	name := strings.ToLower(strings.TrimSpace(raw))
	if _, ok := actionSpecByName[name]; !ok {
		return "", false
	}
	return name, true
}

func IsKnownActionName(name string) bool {
	_, ok := actionSpecByName[name]
	return ok
}

func UserSpaceResponseActionName(code uint16) (string, bool) {
	spec, ok := actionSpecByCode[code]
	if !ok || !spec.UserSpaceResponse {
		return "", false
	}
	return spec.Name, true
}

func IsUserSpaceResponseActionName(name string) bool {
	spec, ok := actionSpecByName[name]
	return ok && spec.UserSpaceResponse
}

func buildActionSpecByCode() map[uint16]ActionSpec {
	items := make(map[uint16]ActionSpec, len(actionSpecs))
	for _, spec := range actionSpecs {
		items[spec.Code] = spec
	}
	return items
}

func buildActionSpecByName() map[string]ActionSpec {
	items := make(map[string]ActionSpec, len(actionSpecs))
	for _, spec := range actionSpecs {
		items[spec.Name] = spec
	}
	return items
}
