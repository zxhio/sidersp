package types

import "fmt"

type ValidationError struct {
	Detail string
}

func (e ValidationError) Error() string {
	return e.Detail
}

func NewValidationError(format string, args ...any) ValidationError {
	return ValidationError{Detail: fmt.Sprintf(format, args...)}
}

type Ruleset struct {
	Version uint64
	Rules   []Rule
}

type Rule struct {
	RuleID   uint32
	Priority int
	Match    RuleMatch
	Response RuleResponse
}

type RuleMatch struct {
	Protocol    string
	VLANs       []int
	SrcPrefixes []string
	DstPrefixes []string
	SrcPorts    []int
	DstPorts    []int
	TCPFlags    TCPFlags
	ICMP        *ICMPMatch
	ARP         *ARPMatch
}

type TCPFlags struct {
	SYN *bool
	ACK *bool
	RST *bool
	FIN *bool
	PSH *bool
}

type ICMPMatch struct {
	Type string
}

type ARPMatch struct {
	Operation string
}

type RuleResponse struct {
	Action string
	Params map[string]any
}
