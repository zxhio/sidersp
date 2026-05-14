package api

import "sidersp/internal/agent/types"

type HealthResponse struct {
	Status string `json:"status"`
}

type StatusResponse struct {
	Status             string `json:"status"`
	Attachments        int    `json:"attachments"`
	RulesetVersion     uint64 `json:"ruleset_version"`
	ResponseConfigured bool   `json:"response_configured"`
	DispatchEnabled    bool   `json:"dispatch_enabled"`
}

type RulesetRequest struct {
	Version *uint64        `json:"version"`
	Rules   *[]RuleRequest `json:"rules"`
}

type RulesetResponse struct {
	Version uint64         `json:"version"`
	Rules   []RuleResponse `json:"rules"`
}

type RuleRequest struct {
	RuleID   *uint32          `json:"rule_id,omitempty"`
	Priority int              `json:"priority,omitempty"`
	Match    RuleMatchBody    `json:"match,omitempty"`
	Response RuleResponseBody `json:"response"`
}

type RuleResponse struct {
	RuleID   uint32           `json:"rule_id"`
	Priority int              `json:"priority,omitempty"`
	Match    RuleMatchBody    `json:"match,omitempty"`
	Response RuleResponseBody `json:"response"`
}

type RuleMatchBody struct {
	Protocol    string       `json:"protocol,omitempty"`
	VLANs       []int        `json:"vlans,omitempty"`
	SrcPrefixes []string     `json:"src_prefixes,omitempty"`
	DstPrefixes []string     `json:"dst_prefixes,omitempty"`
	SrcPorts    []int        `json:"src_ports,omitempty"`
	DstPorts    []int        `json:"dst_ports,omitempty"`
	TCPFlags    TCPFlagsBody `json:"tcp_flags,omitempty"`
	ICMP        *ICMPBody    `json:"icmp,omitempty"`
	ARP         *ARPBody     `json:"arp,omitempty"`
}

type TCPFlagsBody struct {
	SYN *bool `json:"syn,omitempty"`
	ACK *bool `json:"ack,omitempty"`
	RST *bool `json:"rst,omitempty"`
	FIN *bool `json:"fin,omitempty"`
	PSH *bool `json:"psh,omitempty"`
}

type ICMPBody struct {
	Type string `json:"type"`
}

type ARPBody struct {
	Operation string `json:"operation"`
}

type RuleResponseBody struct {
	Action string         `json:"action"`
	Params map[string]any `json:"params,omitempty"`
}

type AttachmentRequest struct {
	IfIndex     *int                          `json:"ifindex"`
	IfName      string                        `json:"ifname,omitempty"`
	AttachMode  string                        `json:"attach_mode,omitempty"`
	MissVerdict string                        `json:"miss_verdict,omitempty"`
	Channels    AttachmentChannelsRequestBody `json:"channels,omitempty"`
	XSK         AttachmentXSKBody             `json:"xsk,omitempty"`
}

type AttachmentResponse struct {
	IfIndex     int                    `json:"ifindex"`
	IfName      string                 `json:"ifname,omitempty"`
	AttachMode  string                 `json:"attach_mode"`
	Enabled     bool                   `json:"enabled"`
	MissVerdict string                 `json:"miss_verdict"`
	Channels    AttachmentChannelsBody `json:"channels"`
	XSK         AttachmentXSKBody      `json:"xsk"`
	Runtime     AttachmentRuntimeBody  `json:"runtime"`
}

type AttachmentChannelsRequestBody struct {
	RXQueueCount int `json:"rx_queue_count"`
}

type AttachmentChannelsBody struct {
	RXQueueCount    int `json:"rx_queue_count"`
	MaxRXQueueCount int `json:"max_rx_queue_count"`
}

type AttachmentXSKBody struct {
	Enabled bool               `json:"enabled"`
	Queues  []int              `json:"queues,omitempty"`
	UMEM    AttachmentUMEMBody `json:"umem"`
}

type AttachmentUMEMBody struct {
	FrameSize          int `json:"frame_size"`
	FrameCount         int `json:"frame_count"`
	FillRingSize       int `json:"fill_ring_size"`
	CompletionRingSize int `json:"completion_ring_size"`
	RXRingSize         int `json:"rx_ring_size"`
	TXRingSize         int `json:"tx_ring_size"`
	TXFrameReserve     int `json:"tx_frame_reserve"`
}

type AttachmentRuntimeBody struct {
	ProgramID uint32 `json:"program_id"`
}

type PatchAttachmentRequest struct {
	Enabled *bool `json:"enabled"`
}

type ResponseConfigRequest struct {
	IfIndex  *int   `json:"ifindex"`
	IfName   string `json:"ifname,omitempty"`
	VLANMode string `json:"vlan_mode,omitempty"`
}

type ResponseConfigResponse struct {
	IfIndex  int    `json:"ifindex"`
	IfName   string `json:"ifname,omitempty"`
	VLANMode string `json:"vlan_mode"`
}

type DispatchConfigRequest struct {
	Enabled        bool   `json:"enabled,omitempty"`
	Backend        string `json:"backend,omitempty"`
	TargetIfIndex  int    `json:"target_ifindex,omitempty"`
	TargetIfName   string `json:"target_ifname,omitempty"`
	VLANMode       string `json:"vlan_mode,omitempty"`
	QueueSize      int    `json:"queue_size,omitempty"`
	MaxPacketBytes int    `json:"max_packet_bytes,omitempty"`
}

type DispatchConfigResponse struct {
	Enabled        bool   `json:"enabled"`
	Backend        string `json:"backend"`
	TargetIfIndex  int    `json:"target_ifindex,omitempty"`
	TargetIfName   string `json:"target_ifname,omitempty"`
	VLANMode       string `json:"vlan_mode"`
	QueueSize      int    `json:"queue_size"`
	MaxPacketBytes int    `json:"max_packet_bytes"`
}

func newHealthResponse(item types.Health) HealthResponse {
	return HealthResponse{Status: item.Status}
}

func newStatusResponse(item types.Status) StatusResponse {
	return StatusResponse{
		Status:             item.Status,
		Attachments:        item.Attachments,
		RulesetVersion:     item.RulesetVersion,
		ResponseConfigured: item.ResponseConfigured,
		DispatchEnabled:    item.DispatchEnabled,
	}
}

func newRuleset(req RulesetRequest) (types.Ruleset, error) {
	if req.Version == nil {
		return types.Ruleset{}, types.NewValidationError("version is required")
	}
	if req.Rules == nil {
		return types.Ruleset{}, types.NewValidationError("rules is required")
	}

	rules := make([]types.Rule, 0, len(*req.Rules))
	for i, item := range *req.Rules {
		rule, err := newRule(item, i)
		if err != nil {
			return types.Ruleset{}, err
		}
		rules = append(rules, rule)
	}

	return types.Ruleset{
		Version: *req.Version,
		Rules:   rules,
	}, nil
}

func newRule(item RuleRequest, index int) (types.Rule, error) {
	if item.RuleID == nil {
		return types.Rule{}, types.NewValidationError("rules[%d].rule_id is required", index)
	}
	return types.Rule{
		RuleID:   *item.RuleID,
		Priority: item.Priority,
		Match:    newRuleMatch(item.Match),
		Response: types.RuleResponse{
			Action: item.Response.Action,
			Params: cloneBodyParams(item.Response.Params),
		},
	}, nil
}

func newRuleMatch(item RuleMatchBody) types.RuleMatch {
	return types.RuleMatch{
		Protocol:    item.Protocol,
		VLANs:       append([]int(nil), item.VLANs...),
		SrcPrefixes: append([]string(nil), item.SrcPrefixes...),
		DstPrefixes: append([]string(nil), item.DstPrefixes...),
		SrcPorts:    append([]int(nil), item.SrcPorts...),
		DstPorts:    append([]int(nil), item.DstPorts...),
		TCPFlags: types.TCPFlags{
			SYN: cloneBool(item.TCPFlags.SYN),
			ACK: cloneBool(item.TCPFlags.ACK),
			RST: cloneBool(item.TCPFlags.RST),
			FIN: cloneBool(item.TCPFlags.FIN),
			PSH: cloneBool(item.TCPFlags.PSH),
		},
		ICMP: newICMPMatch(item.ICMP),
		ARP:  newARPMatch(item.ARP),
	}
}

func newICMPMatch(item *ICMPBody) *types.ICMPMatch {
	if item == nil {
		return nil
	}
	return &types.ICMPMatch{Type: item.Type}
}

func newARPMatch(item *ARPBody) *types.ARPMatch {
	if item == nil {
		return nil
	}
	return &types.ARPMatch{Operation: item.Operation}
}

func newRulesetResponse(item types.Ruleset) RulesetResponse {
	return RulesetResponse{
		Version: item.Version,
		Rules:   newRuleResponses(item.Rules),
	}
}

func newRuleResponses(items []types.Rule) []RuleResponse {
	if items == nil {
		return []RuleResponse{}
	}
	out := make([]RuleResponse, 0, len(items))
	for _, item := range items {
		out = append(out, newRuleResponse(item))
	}
	return out
}

func newRuleResponse(item types.Rule) RuleResponse {
	return RuleResponse{
		RuleID:   item.RuleID,
		Priority: item.Priority,
		Match:    newRuleMatchBody(item.Match),
		Response: RuleResponseBody{
			Action: item.Response.Action,
			Params: cloneBodyParams(item.Response.Params),
		},
	}
}

func newRuleMatchBody(item types.RuleMatch) RuleMatchBody {
	return RuleMatchBody{
		Protocol:    item.Protocol,
		VLANs:       append([]int(nil), item.VLANs...),
		SrcPrefixes: append([]string(nil), item.SrcPrefixes...),
		DstPrefixes: append([]string(nil), item.DstPrefixes...),
		SrcPorts:    append([]int(nil), item.SrcPorts...),
		DstPorts:    append([]int(nil), item.DstPorts...),
		TCPFlags: TCPFlagsBody{
			SYN: cloneBool(item.TCPFlags.SYN),
			ACK: cloneBool(item.TCPFlags.ACK),
			RST: cloneBool(item.TCPFlags.RST),
			FIN: cloneBool(item.TCPFlags.FIN),
			PSH: cloneBool(item.TCPFlags.PSH),
		},
		ICMP: newICMPBody(item.ICMP),
		ARP:  newARPBody(item.ARP),
	}
}

func newICMPBody(item *types.ICMPMatch) *ICMPBody {
	if item == nil {
		return nil
	}
	return &ICMPBody{Type: item.Type}
}

func newARPBody(item *types.ARPMatch) *ARPBody {
	if item == nil {
		return nil
	}
	return &ARPBody{Operation: item.Operation}
}

func cloneBool(item *bool) *bool {
	if item == nil {
		return nil
	}
	next := *item
	return &next
}

func cloneBodyParams(params map[string]any) map[string]any {
	if params == nil {
		return nil
	}
	out := make(map[string]any, len(params))
	for key, value := range params {
		out[key] = value
	}
	return out
}

func newAttachment(req AttachmentRequest) (types.Attachment, error) {
	if req.IfIndex == nil {
		return types.Attachment{}, types.NewValidationError("ifindex is required")
	}
	return types.Attachment{
		IfIndex:     *req.IfIndex,
		IfName:      req.IfName,
		AttachMode:  req.AttachMode,
		MissVerdict: req.MissVerdict,
		Channels: types.AttachmentChannels{
			RXQueueCount: req.Channels.RXQueueCount,
		},
		XSK: types.AttachmentXSK{
			Enabled: req.XSK.Enabled,
			Queues:  append([]int(nil), req.XSK.Queues...),
			UMEM: types.AttachmentUMEM{
				FrameSize:          req.XSK.UMEM.FrameSize,
				FrameCount:         req.XSK.UMEM.FrameCount,
				FillRingSize:       req.XSK.UMEM.FillRingSize,
				CompletionRingSize: req.XSK.UMEM.CompletionRingSize,
				RXRingSize:         req.XSK.UMEM.RXRingSize,
				TXRingSize:         req.XSK.UMEM.TXRingSize,
				TXFrameReserve:     req.XSK.UMEM.TXFrameReserve,
			},
		},
	}, nil
}

func newAttachmentResponse(item types.Attachment) AttachmentResponse {
	return AttachmentResponse{
		IfIndex:     item.IfIndex,
		IfName:      item.IfName,
		AttachMode:  item.AttachMode,
		Enabled:     item.Enabled,
		MissVerdict: item.MissVerdict,
		Channels: AttachmentChannelsBody{
			RXQueueCount:    item.Channels.RXQueueCount,
			MaxRXQueueCount: item.Channels.MaxRXQueueCount,
		},
		XSK: AttachmentXSKBody{
			Enabled: item.XSK.Enabled,
			Queues:  append([]int(nil), item.XSK.Queues...),
			UMEM: AttachmentUMEMBody{
				FrameSize:          item.XSK.UMEM.FrameSize,
				FrameCount:         item.XSK.UMEM.FrameCount,
				FillRingSize:       item.XSK.UMEM.FillRingSize,
				CompletionRingSize: item.XSK.UMEM.CompletionRingSize,
				RXRingSize:         item.XSK.UMEM.RXRingSize,
				TXRingSize:         item.XSK.UMEM.TXRingSize,
				TXFrameReserve:     item.XSK.UMEM.TXFrameReserve,
			},
		},
		Runtime: AttachmentRuntimeBody{
			ProgramID: item.Runtime.ProgramID,
		},
	}
}

func newAttachmentResponses(items []types.Attachment) []AttachmentResponse {
	if items == nil {
		return []AttachmentResponse{}
	}
	out := make([]AttachmentResponse, 0, len(items))
	for _, item := range items {
		out = append(out, newAttachmentResponse(item))
	}
	return out
}

func newResponseConfig(req ResponseConfigRequest) (types.ResponseConfig, error) {
	if req.IfIndex == nil {
		return types.ResponseConfig{}, types.NewValidationError("ifindex is required")
	}
	return types.ResponseConfig{
		IfIndex:  *req.IfIndex,
		IfName:   req.IfName,
		VLANMode: req.VLANMode,
	}, nil
}

func newResponseConfigResponse(item types.ResponseConfig) ResponseConfigResponse {
	return ResponseConfigResponse{
		IfIndex:  item.IfIndex,
		IfName:   item.IfName,
		VLANMode: item.VLANMode,
	}
}

func newDispatchConfig(req DispatchConfigRequest) types.DispatchConfig {
	return types.DispatchConfig{
		Enabled:        req.Enabled,
		Backend:        req.Backend,
		TargetIfIndex:  req.TargetIfIndex,
		TargetIfName:   req.TargetIfName,
		VLANMode:       req.VLANMode,
		QueueSize:      req.QueueSize,
		MaxPacketBytes: req.MaxPacketBytes,
	}
}

func newDispatchConfigResponse(item types.DispatchConfig) DispatchConfigResponse {
	return DispatchConfigResponse{
		Enabled:        item.Enabled,
		Backend:        item.Backend,
		TargetIfIndex:  item.TargetIfIndex,
		TargetIfName:   item.TargetIfName,
		VLANMode:       item.VLANMode,
		QueueSize:      item.QueueSize,
		MaxPacketBytes: item.MaxPacketBytes,
	}
}
