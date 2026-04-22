package rule

const (
	ActionNone uint16 = iota
	ActionAlert
	ActionTCPReset
	ActionICMPEchoReply
	ActionARPReply
	ActionTCPSynAck
)

type RuleSet struct {
	Rules []Rule `json:"rules" yaml:"rules"`
}

type Rule struct {
	ID       int          `json:"id" yaml:"id"`
	Name     string       `json:"name" yaml:"name"`
	Enabled  bool         `json:"enabled" yaml:"enabled"`
	Priority int          `json:"priority" yaml:"priority"`
	Match    RuleMatch    `json:"match" yaml:"match"`
	Response RuleResponse `json:"response" yaml:"response"`
}

type RuleMatch struct {
	Protocol    string     `json:"protocol" yaml:"protocol"`
	VLANs       []int      `json:"vlans" yaml:"vlans"`
	SrcPrefixes []string   `json:"src_prefixes" yaml:"src_prefixes"`
	DstPrefixes []string   `json:"dst_prefixes" yaml:"dst_prefixes"`
	SrcPorts    []int      `json:"src_ports" yaml:"src_ports"`
	DstPorts    []int      `json:"dst_ports" yaml:"dst_ports"`
	TCPFlags    TCPFlags   `json:"tcp_flags" yaml:"tcp_flags"`
	ICMP        *ICMPMatch `json:"icmp,omitempty" yaml:"icmp,omitempty"`
	ARP         *ARPMatch  `json:"arp,omitempty" yaml:"arp,omitempty"`
}

type RuleResponse struct {
	Action string                 `json:"action" yaml:"action"`
	Params map[string]interface{} `json:"params,omitempty" yaml:"params,omitempty"`
}

type TCPFlags struct {
	SYN *bool `json:"syn,omitempty" yaml:"syn,omitempty"`
	ACK *bool `json:"ack,omitempty" yaml:"ack,omitempty"`
	RST *bool `json:"rst,omitempty" yaml:"rst,omitempty"`
	FIN *bool `json:"fin,omitempty" yaml:"fin,omitempty"`
	PSH *bool `json:"psh,omitempty" yaml:"psh,omitempty"`
}

type ICMPMatch struct {
	Type string `json:"type" yaml:"type"`
}

type ARPMatch struct {
	Operation string `json:"operation" yaml:"operation"`
}
