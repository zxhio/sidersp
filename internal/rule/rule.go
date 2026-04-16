package rule

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
	VLANs       []int    `json:"vlans" yaml:"vlans"`
	SrcPrefixes []string `json:"src_prefixes" yaml:"src_prefixes"`
	DstPrefixes []string `json:"dst_prefixes" yaml:"dst_prefixes"`
	SrcPorts    []int    `json:"src_ports" yaml:"src_ports"`
	DstPorts    []int    `json:"dst_ports" yaml:"dst_ports"`
	Features    []string `json:"features" yaml:"features"`
}

type RuleResponse struct {
	Action string `json:"action" yaml:"action"`
}
