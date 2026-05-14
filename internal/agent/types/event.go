package types

type Event struct {
	Timestamp int64
	Type      string
	RuleID    uint32
	Action    string
	Path      string
	Verdict   string
	Result    string
	IfIndex   int
	SIP       uint32
	DIP       uint32
	SPort     uint16
	DPort     uint16
	IPProto   uint8
}
